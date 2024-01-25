

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use bitcoin::{Amount, OutPoint, Transaction};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;

use ark::{musig, Destination, Vtxo, VtxoId};
use ark::connectors::ConnectorChain;
use ark::tree::signed::{SignedVtxoTree, VtxoTreeSpec};

use crate::App;
use crate::database::ForfeitVtxo;

#[derive(Debug, Clone)]
pub enum RoundEvent {
	Start {
		id: u64,
	},
	Proposal {
		id: u64,
		vtxos_spec: VtxoTreeSpec,
		round_tx: Transaction,
		vtxos_signers: Vec<PublicKey>,
		vtxos_agg_nonces: Vec<musig::MusigAggNonce>,
		forfeit_nonces: HashMap<VtxoId, Vec<musig::MusigPubNonce>>,
	},
	Finished {
		id: u64,
		vtxos: SignedVtxoTree,
		round_tx: Transaction,
	},
}

#[derive(Debug)]
pub enum RoundInput {
	RegisterPayment {
		inputs: Vec<Vtxo>,
		outputs: Vec<Destination>,
		cosign_pubkey: PublicKey,
		public_nonces: Vec<musig::MusigPubNonce>,
	},
	Signatures {
		vtxo_pubkey: PublicKey,
		vtxo_signatures: Vec<musig::MusigPartialSignature>,
		forfeit: HashMap<VtxoId, (Vec<musig::MusigPubNonce>, Vec<musig::MusigPartialSignature>)>,
	},
}

fn validate_payment(inputs: &[Vtxo], outputs: &[Destination]) -> bool {
	let mut in_set = HashSet::with_capacity(inputs.len());
	let mut in_sum = Amount::ZERO;
	for input in inputs {
		in_sum += input.amount();
		if in_sum > Amount::MAX_MONEY || !in_set.insert(input.id()) {
			return false;
		}
	}

	let mut out_sum = Amount::ZERO;
	for output in outputs {
		out_sum += output.amount;
		if out_sum > in_sum {
			return false;
		}
	}

	true
}

/// This method is called from a tokio thread so it can be long-lasting.
pub async fn run_round_scheduler(
	app: Arc<App>,
	mut round_input_rx: tokio::sync::mpsc::UnboundedReceiver<RoundInput>,
) -> anyhow::Result<()> {
	let cfg = &app.config;

	'round: loop {
		tokio::time::sleep(cfg.round_interval).await;
		let round_id = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() /
			cfg.round_interval.as_secs();
		info!("Starting round {}", round_id);

		// Start new round, announce.
		let _ = app.round_event_tx.send(RoundEvent::Start { id: round_id });

		// In this loop we will try to finish the round and make new attempts.
		let mut allowed_inputs = HashSet::new();
		'attempt: loop {
			let mut all_inputs = Vec::<Vtxo>::new();
			let mut all_outputs = Vec::<Destination>::new();
			let mut cosigners = HashSet::<PublicKey>::new();
			cosigners.insert(app.master_key.public_key());
			let mut nonces = Vec::<Vec<musig::MusigPubNonce>>::new();

			// Start receiving payments.
			trace!("Starting receiving payments...");
			let timeout = tokio::time::sleep(cfg.round_submit_time);
			tokio::pin!(timeout);
			'receive: loop {
				tokio::select! {
					() = &mut timeout => break 'receive,
					input = round_input_rx.recv() => match input.expect("broken channel") {
						RoundInput::RegisterPayment { inputs, outputs, cosign_pubkey, public_nonces } => {
							//TODO(stevenroose) verify ownership over inputs

							if !allowed_inputs.is_empty() {
								// This means we're not trying first time and we filter inputs.
								if let Some(bad) = inputs.iter().find(|i| allowed_inputs.contains(&i.id())) {
									warn!("User attempted to submit invalid input: {}", bad.id());
									//TODO(stevenroose) would be nice if user saw this
									continue 'receive;
								}
							}

							//TODO(stevenroose) check that vtxos exist!

							if !validate_payment(&inputs, &outputs) {
								warn!("User submitted bad payment: ins {:?}; outs {:?}",
									inputs, outputs);
								continue 'receive;
							}

							trace!("Received {} inputs and {} outputs from user",
								inputs.len(), outputs.len());
							all_inputs.extend(inputs);
							//TODO(stevenroose) somehow check if a tree using these outputs
							//will exceed the config.nb_round_nonces number of nodes
							all_outputs.extend(outputs);
							assert!(cosigners.insert(cosign_pubkey));
							nonces.push(public_nonces);
						},
						v => debug!("Received unexpected input: {:?}", v),
					}
				}
			}
			if all_inputs.is_empty() || all_outputs.is_empty() {
				info!("No payments this round, sitting it out...");
				continue 'round;
			}
			info!("Received {} inputs and {} outputs for round", all_inputs.len(), all_outputs.len());
			// Make sure we don't allow other inputs next attempt.
			allowed_inputs.clear();
			allowed_inputs.extend(all_inputs.iter().map(|v| v.id()));

			// Start vtxo tree and connector chain construction
			let tip = bdk_bitcoind_rpc::bitcoincore_rpc::RpcApi::get_block_count(&app.bitcoind)?;
			let vtxos_spec = VtxoTreeSpec::new(
				cosigners.iter().copied().collect(),
				all_outputs,
				app.master_key.public_key(),
				tip as u32 + cfg.vtxo_expiry_delta as u32,
				cfg.vtxo_exit_delta,
			);
			//TODO(stevenroose) this is super inefficient, improve this with direct getter
			let nb_nodes = vtxos_spec.build_unsigned_tree(OutPoint::null()).nb_nodes();
			//TODO(stevenroose) handle this better
			assert!(nb_nodes < cfg.nb_round_nonces);
			let connector_output = ConnectorChain::output(
				all_inputs.len(), app.master_key.public_key(),
			);

			// Build round tx.
			app.sync_onchain_wallet().await.context("error syncing onchain wallet")?;
			//TODO(stevenroose) think about if we can release lock sooner
			let mut wallet = app.wallet.lock().await;
			let mut round_tx_psbt = {
				let mut b = wallet.build_tx();
				b.ordering(bdk::wallet::tx_builder::TxOrdering::Untouched);
				b.add_recipient(vtxos_spec.cosign_spk(), vtxos_spec.total_required_value().to_sat());
				b.add_recipient(connector_output.script_pubkey, connector_output.value);
				b.fee_rate(bdk::FeeRate::from_sat_per_vb(100.0)); //TODO(stevenroose) fix
				b.finish().context("bdk failed to create round tx")?
			};
			let round_tx = round_tx_psbt.clone().extract_tx();
			let vtxos_utxo = OutPoint::new(round_tx.txid(), 0);
			let conns_utxo = OutPoint::new(round_tx.txid(), 1);

			// Generate nonces and combine with user's nonces.
			let (sec_vtxo_nonces, pub_vtxo_nonces) = {
				let mut secs = Vec::with_capacity(nb_nodes);
				let mut pubs = Vec::with_capacity(nb_nodes);
				for _ in 0..nb_nodes {
					let (s, p) = musig::nonce_pair(&app.master_key);
					secs.push(s);
					pubs.push(p);
				}
				(secs, pubs)
			};
			let agg_vtxo_nonces = {
				let mut ret = Vec::with_capacity(nb_nodes);
				let mut buf = Vec::with_capacity(cosigners.len());
				for i in 0..nb_nodes {
					buf.clear();
					buf.push(pub_vtxo_nonces[i]);
					buf.extend(nonces.iter().map(|nonces| nonces[i]));
					ret.push(musig::MusigAggNonce::new(&musig::SECP, &buf));
				}
				ret
			};

			// Prepare nonces for forfeit txs.
			// We need to prepare N nonces for each of N inputs.
			let mut forfeit_pub_nonces = HashMap::with_capacity(all_inputs.len());
			let mut forfeit_sec_nonces = HashMap::with_capacity(all_inputs.len());
			for input in &all_inputs {
				let mut secs = Vec::with_capacity(all_inputs.len());
				let mut pubs = Vec::with_capacity(all_inputs.len());
				for _ in 0..all_inputs.len() {
					let (s, p) = musig::nonce_pair(&app.master_key);
					secs.push(s);
					pubs.push(p);
				}
				forfeit_pub_nonces.insert(input.id(), pubs);
				forfeit_sec_nonces.insert(input.id(), secs);
			}

			// Send out proposal to signers.
			let _ = app.round_event_tx.send(RoundEvent::Proposal {
				id: round_id,
				vtxos_spec: vtxos_spec.clone(),
				round_tx: round_tx.clone(),
				vtxos_signers: cosigners.iter().copied().collect(),
				vtxos_agg_nonces: agg_vtxo_nonces.clone(),
				forfeit_nonces: forfeit_pub_nonces.clone(),
			});

			// Wait for signatures from users.
			let mut vtxo_part_sigs = HashMap::with_capacity(cosigners.len());
			let mut forfeit_part_sigs = HashMap::with_capacity(all_inputs.len());
			let timeout = tokio::time::sleep(cfg.round_sign_time);
			tokio::pin!(timeout);
			'receive: loop {
				tokio::select! {
					_ = &mut timeout => break 'receive,
					input = round_input_rx.recv() => match input.expect("broken channel") {
						RoundInput::Signatures { vtxo_pubkey, vtxo_signatures, forfeit } => {
							if !cosigners.contains(&vtxo_pubkey) {
								warn!("Received signatures from non-signer: {}", vtxo_pubkey);
								continue 'receive;
							}
							trace!("Received signatures from cosigner {}", vtxo_pubkey);

							//TODO(stevenroose) validate partial signatures
							vtxo_part_sigs.insert(vtxo_pubkey, vtxo_signatures);

							//TODO(stevenroose) validate forfeit txs
							let mut ok = true;
							for (id, (n, s)) in &forfeit {
								if n.len() != all_inputs.len() || s.len() != all_inputs.len() {
									warn!("User didn't provide enough forfeit sigs for {}", id);
									ok = false;
								}
							}
							if ok {
								forfeit_part_sigs.extend(forfeit.into_iter());
							}
						},
						v => debug!("Received unexpected input: {:?}", v),
					}
				}
			}

			//TODO(stevenroose) kick out signers that didn't sign and retry
			if cosigners.len() - 1 != vtxo_part_sigs.len() {
				error!("Not enough vtxo partial signatures! ({} != {})",
					cosigners.len() - 1, vtxo_part_sigs.len());
				continue 'round;
			}
			if forfeit_part_sigs.len() != all_inputs.len() {
				error!("Not enough forfeit partial signatures! ({} != {})",
					forfeit_part_sigs.len(), all_inputs.len());
				continue 'round;
			}

			// Finish the forfeit signatures.
			let mut forfeit_sigs = HashMap::with_capacity(all_inputs.len());
			let mut missing_forfeits = HashSet::new();
			let connectors = ConnectorChain::new(
				all_inputs.len(), conns_utxo, app.master_key.public_key(),
			);
			for vtxo in &all_inputs {
				if let Some((user_nonces, partial_sigs)) = forfeit_part_sigs.get(&vtxo.id()) {
					let vtxo = vtxo.clone();
					let sec_nonces = forfeit_sec_nonces.remove(&vtxo.id()).unwrap().into_iter();
					let pub_nonces = forfeit_pub_nonces.get(&vtxo.id()).unwrap();
					let connectors = connectors.connectors();
					let mut sigs = Vec::with_capacity(all_inputs.len());
					for (i, (conn, sec)) in connectors.zip(sec_nonces.into_iter()).enumerate() {
						let (sighash, _) = ark::forfeit::forfeit_sighash(&vtxo, conn);
						let agg_nonce = musig::nonce_agg([user_nonces[i], pub_nonces[i]]);
						let (_, sig) = musig::partial_sign(
							[app.master_key.public_key(), vtxo.spec().user_pubkey],
							agg_nonce,
							&app.master_key,
							sec,
							sighash.to_byte_array(),
							Some(vtxo.spec().exit_taptweak().to_byte_array()),
							Some(&[partial_sigs[i]]),
						);
						sigs.push(sig.expect("should be signed"));
					}
					forfeit_sigs.insert(vtxo.id(), sigs);
				} else {
					missing_forfeits.insert(vtxo.id());
				}
			}
			//TODO(stevenroose) if missing forfeits, ban inputs and restart round

			// Combine the vtxo signatures.
			let sighashes = vtxos_spec.sighashes(vtxos_utxo);
			assert_eq!(sighashes.len(), agg_vtxo_nonces.len());
			let mut signatures = Vec::with_capacity(nb_nodes);
			for (i, sec_nonce) in sec_vtxo_nonces.into_iter().enumerate() {
				let others = vtxo_part_sigs.values().map(|s| s[i].clone()).collect::<Vec<_>>();
				let sig = musig::partial_sign(
					cosigners.iter().copied(),
					agg_vtxo_nonces[i],
					&app.master_key,
					sec_nonce,
					sighashes[i].to_byte_array(),
					Some(vtxos_spec.cosign_taptweak().to_byte_array()),
					Some(&others),
				).1.expect("should be signed");
				signatures.push(sig);
			}
			
			// Then construct the final signed vtxo tree.
			let signed_vtxos = SignedVtxoTree::new(vtxos_spec, vtxos_utxo, signatures);

			// And sign the on-chain tx.
			let finalized = wallet.sign(&mut round_tx_psbt, bdk::SignOptions::default())?;
			assert!(finalized);
			let round_tx = round_tx_psbt.extract_tx();
			drop(wallet); // we no longer need the lock

			// Broadcast over bitcoind.
			debug!("Broadcasting round tx {}", round_tx.txid());
			let bc = bdk_bitcoind_rpc::bitcoincore_rpc::RpcApi::send_raw_transaction(&app.bitcoind, &round_tx);
			if let Err(e) = bc {
				warn!("Couldn't broadcast round tx: {}", e);
			}

			// Send out the finished round to users.
			trace!("Sending out finish event.");
			let _ = app.round_event_tx.send(RoundEvent::Finished {
				id: round_id,
				vtxos: signed_vtxos.clone(),
				round_tx: round_tx.clone(),
			});


			// Store forfeit txs and round info in database.
			let round_id = round_tx.txid();
			for vtxo in all_inputs {
				let forfeit_sigs = forfeit_sigs.remove(&vtxo.id()).unwrap();
				let point = vtxo.point();
				let ff = match vtxo {
					Vtxo::Onboard { utxo, spec, .. } => {
						ForfeitVtxo::Onboard { spec, utxo, forfeit_sigs }
					},
					Vtxo::Round { utxo, spec, leaf_idx, .. } => {
						ForfeitVtxo::Round { spec, round_id, point, leaf_idx, forfeit_sigs }
					},
				};
				trace!("Storing forfeit vtxo for vtxo {}", point);
				app.db.store_forfeit_vtxo(ff)?;
			}

			trace!("Storing round result");
			app.db.store_round(round_tx.clone(), signed_vtxos)?;

			info!("Finished round {} with tx {}", round_id, round_tx.txid());
			break 'attempt;
		}
	}
}
