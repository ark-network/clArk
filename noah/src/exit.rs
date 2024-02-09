
use std::io;
use std::collections::HashSet;

use anyhow::Context;
use bitcoin::{secp256k1, sighash, taproot, Amount, OutPoint, Witness};

use ark::{Vtxo, VtxoSpec};

use crate::{SECP, Wallet};
use crate::psbt::PsbtInputExt;



const VTXO_CLAIM_INPUT_WEIGHT: usize = 138;

#[derive(Debug, Serialize, Deserialize)]
pub struct ClaimInput {
	pub utxo: OutPoint,
	pub spec: VtxoSpec,
}

impl ClaimInput {
	pub fn encode(&self) -> Vec<u8> {
		let mut buf = Vec::new();
		ciborium::into_writer(self, &mut buf).unwrap();
		buf
	}

	pub fn decode(bytes: &[u8]) -> Result<Self, ciborium::de::Error<io::Error>> {
		ciborium::from_reader(bytes)
	}

	pub fn satisfaction_weight(&self) -> usize {
		// NB Better use a method for this because might be vtxo-dependent in the future.
		VTXO_CLAIM_INPUT_WEIGHT
	}
}

impl Wallet {
	/// Exit all vtxo onto the chain.
	pub async fn start_unilateral_exit(&mut self) -> anyhow::Result<()> {
		if let Err(e) = self.sync_ark().await {
			warn!("Failed to sync incoming Ark payments, still doing exit: {}", e);
		}

		let vtxos = self.db.get_all_vtxos()?;

		//TODO(stevenroose) idea, each vtxo will have a fee anchor for us.
		// We should here
		// - collect all fee anchor outputs of broadcasted txs in a list
		// - add up the vsize of all txs we broadcasted
		// - create a new tx using our on-chain wallet that spends all anchors and
		// has an absolute fee that pays our feerate (also todo) for the entire
		// "package" vsize.

		info!("Starting unilateral exit of {} vtxos...", vtxos.len());
		let mut total_size = 0;
		let mut started = Vec::with_capacity(vtxos.len());
		let mut new_claim_inputs = Vec::with_capacity(vtxos.len());
		let mut fee_anchors = Vec::with_capacity(vtxos.len());
		'vtxo: for vtxo in vtxos {
			let id = vtxo.id();
			match vtxo {
				Vtxo::Onboard { spec, utxo, reveal_tx_signature } => {
					let reveal_tx = ark::onboard::create_reveal_tx(
						&spec, utxo, Some(&reveal_tx_signature),
					);

					debug!("Broadcasting reveal tx for vtxo {}: {}", id, reveal_tx.txid());
					if let Err(e) = self.onchain.broadcast_tx(&reveal_tx) {
						error!("Error broadcasting reveal tx for onboard vtxo {}: {}", id, e);
						continue;
					}
					total_size += reveal_tx.vsize();

					started.push(id);
					let utxo = OutPoint::new(reveal_tx.txid(), 0);
					new_claim_inputs.push(ClaimInput { utxo, spec });
					fee_anchors.push(OutPoint::new(reveal_tx.txid(), 1));
				},
				Vtxo::Round { spec, utxo: _, leaf_idx: _, exit_branch } => {
					debug!("Broadcasting {} txs of exit branch for vtxo {}: {:?}",
						exit_branch.len(), id, exit_branch.iter().map(|t| t.txid()).collect::<Vec<_>>());
					let mut branch_size = 0;
					for tx in &exit_branch {
						if let Err(e) = self.onchain.broadcast_tx(&tx) {
							error!("Error broadcasting exit branch tx {} for vtxo {}: {}",
								tx.txid(), id, e,
							);
							continue 'vtxo;
						}
						branch_size += tx.vsize();
					}
					total_size += branch_size;
					let leaf = exit_branch.last().unwrap();
					started.push(id);
					let utxo = OutPoint::new(leaf.txid(), 0);
					new_claim_inputs.push(ClaimInput { utxo, spec });
					fee_anchors.push(OutPoint::new(leaf.txid(), 1));
				},
			}
		}

		if new_claim_inputs.len() == 0 {
			return Ok(());
		}

		info!("Got {} outputs to claim, {} fee anchors to spend and {} package vsize to cover",
			new_claim_inputs.len(), fee_anchors.len(), total_size);

		// First we will store the claim inputs so we for sure don't forget about them.
		// We might already have some pending claim inputs.
		let mut claim_inputs = self.db.get_claim_inputs().context("db error getting existing claims")?;
		let mut claim_utxos = claim_inputs.iter().map(|i| i.utxo).collect::<HashSet<_>>();
		for new in new_claim_inputs {
			if claim_utxos.insert(new.utxo) {
				claim_inputs.push(new);
			} else {
				warn!("A claim input for utxo {} already existed", new.utxo);
			}
		}
		self.db.store_claim_inputs(&claim_inputs).context("db error storing claim inputs")?;

		// Then we'll send a tx that will pay the fee for all the txs we made.
		let tx = self.onchain.spend_fee_anchors(&fee_anchors, total_size)?;
		info!("Sent anchor spend tx: {}", tx.txid());

		// After we succesfully stored the claim inputs, we can drop the vtxos.
		for id in started {
			if let Err(e) = self.db.remove_vtxo(id) {
				// Don't error here so we can try remove the others.
				warn!("Error removing vtxo {} from db: {}", id, e);
			}
		}
		Ok(())
	}

	/// Returns all the pending exit claims, first the claimable ones and then
	/// the unclaimable ones.
	pub async fn unclaimed_exits(&self) -> anyhow::Result<(Vec<ClaimInput>, Vec<ClaimInput>)> {
		let bitcoind = self.onchain.bitcoind();
		let all_inputs = self.db.get_claim_inputs()?;
		//TODO(stevenroose) we need to find a way of what to do with the inputs
		// that are already spent
		let mut claimable = Vec::with_capacity(all_inputs.len());
		let mut unclaimable = Vec::with_capacity(all_inputs.len());
		for input in all_inputs {
			if let Ok(Some(txout))=  bdk_bitcoind_rpc::bitcoincore_rpc::RpcApi::get_tx_out(
				bitcoind,
				&input.utxo.txid,
				input.utxo.vout,
				Some(true), // include mempool
			) {
				if txout.confirmations >= input.spec.exit_delta as u32 {
					claimable.push(input);
					continue;
				} else {
					trace!("Claim input {} has only {} confirmations (need {})",
						input.utxo, txout.confirmations, input.spec.exit_delta);
				}
			} else {
				warn!("Claim input {} not found in utxo set or mempool...", input.utxo);
			}
			unclaimable.push(input);
		}
		Ok((claimable, unclaimable))
	}

	pub async fn claim_unilateral_exit(&mut self) -> anyhow::Result<()> {
		let (inputs, remaining) = self.unclaimed_exits().await?;

		if inputs.is_empty() {
			info!("No inputs we can claim.");
			return Ok(());
		}
		let total_amount = inputs.iter().map(|i| i.spec.amount).sum::<Amount>();
		debug!("Claiming the following exits with total value of {}: {:?}",
			total_amount, inputs.iter().map(|i| i.utxo.to_string()).collect::<Vec<_>>(),
		);

		let mut psbt = self.onchain.create_exit_claim_tx(&inputs)?;

		// Sign all the claim inputs.
		let vtxo_key = self.vtxo_seed.to_keypair(&SECP);
		let lver = taproot::LeafVersion::TapScript;
		let prevouts = psbt.inputs.iter()
			.map(|i| i.witness_utxo.clone().unwrap())
			.collect::<Vec<_>>();
		let mut shc = sighash::SighashCache::new(&psbt.unsigned_tx);
		for (i, input) in psbt.inputs.iter_mut().enumerate() {
			let claim = if let Some(c) = input.get_claim_input() {
				c
			} else {
				continue;
			};

			// Now we need to sign for this.
			let exit_script = claim.spec.exit_clause();
			let leaf_hash = taproot::TapLeafHash::from_script(&exit_script, lver);
			let sighash = shc.taproot_script_spend_signature_hash(
				i, &sighash::Prevouts::All(&prevouts), leaf_hash, sighash::TapSighashType::Default,
			).expect("all prevouts provided");
			trace!("sighash: {}", sighash);

			assert_eq!(vtxo_key.public_key(), claim.spec.user_pubkey);
			let msg = secp256k1::Message::from_slice(&sighash[..]).unwrap();
			let sig = SECP.sign_schnorr(&msg, &vtxo_key);

			let cb = claim.spec.exit_taproot()
				.control_block(&(exit_script.clone(), lver))
				.expect("script is in taproot");

			let mut wit = Witness::new();
			wit.push(&sig[..]);
			wit.push(exit_script.as_bytes());
			wit.push(cb.serialize());
			debug_assert_eq!(wit.serialized_len(), claim.satisfaction_weight());
			input.final_script_witness = Some(wit);
		}

		// Then sign the wallet's funding inputs.
		let tx = self.onchain.finish_tx(psbt).context("finishing claim psbt")?;
		if let Err(e) = self.onchain.broadcast_tx(&tx) {
			bail!("Error broadcasting claim tx: {}", e);
		}

		// Then update the database and only set the remaining inputs as to do.
		self.db.store_claim_inputs(&remaining).context("failed db update")?;

		info!("Successfully claimed total value of {}", total_amount);

		Ok(())
	}
}
