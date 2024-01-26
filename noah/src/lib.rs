
#[macro_use] extern crate log;

mod database;
mod onchain;


use std::{env, fs, iter};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{bail, Context};
use bitcoin::{bip32, secp256k1};
use bitcoin::{Address, Amount, Network, OutPoint, Transaction};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{rand, KeyPair, PublicKey};
use tokio_stream::StreamExt;

use ark::{musig, Destination, Vtxo, VtxoId, VtxoSpec};
use ark::connectors::ConnectorChain;
use ark::tree::signed::{SignedVtxoTree, VtxoTreeSpec};
use arkd_rpc_client as rpc;


lazy_static::lazy_static! {
	/// Global secp context.
	static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

pub struct ArkInfo {
	pub asp_pubkey: PublicKey,
	pub nb_round_nonces: usize,
}

pub struct Config {
	pub network: Network,
	pub datadir: PathBuf,
	pub asp_address: String,
}

impl Default for Config {
	fn default() -> Config {
		Config {
			network: Network::Regtest,
			datadir: env::current_dir().unwrap().join("noah-datadir"),
			asp_address: "127.0.0.1:3535".parse().unwrap(),
		}
	}
}

pub struct Wallet {
	config: Config,
	db: database::Db,
	onchain: onchain::Wallet,
	asp: rpc::ArkServiceClient<tonic::transport::Channel>,
	vtxo_seed: bip32::ExtendedPrivKey,
	// ASP info
	ark_info: ArkInfo,
}

impl Wallet {
	/// Create new wallet.
	pub async fn create(config: Config) -> anyhow::Result<Wallet> {
		info!("Creating new noah Wallet at {}", config.datadir.display());

		// create dir if not exit, but check that it's empty
		fs::create_dir_all(&config.datadir).context("can't create dir")?;
		if fs::read_dir(&config.datadir).context("can't read dir")?.next().is_some() {
			bail!("dir is not empty");
		}

		// generate seed
		let mnemonic = bip39::Mnemonic::generate(12).expect("12 is valid");

		// write it to file
		fs::write(config.datadir.join("mnemonic"), mnemonic.to_string().as_bytes())
			.context("failed to write mnemonic")?;

		// from then on we can open the wallet
		Ok(Wallet::open(config).await.context("failed to open")?)
	}

	/// Open existing wallet.
	pub async fn open(config: Config) -> anyhow::Result<Wallet> {
		info!("Opening noah Wallet at {}", config.datadir.display());

		// read mnemonic file
		let mnemonic_path = config.datadir.join("mnemonic");
		let mnemonic_str = fs::read_to_string(&mnemonic_path)
			.with_context(|| format!("failed to read mnemonic file at {}", mnemonic_path.display()))?;
		let mnemonic = bip39::Mnemonic::from_str(&mnemonic_str).context("broken mnemonic")?;

		// create on-chain wallet
		let seed = mnemonic.to_seed("");
		let onchain = onchain::Wallet::create(config.network, seed, &config.datadir)
			.context("failed to create onchain wallet")?;

		// open db
		let db = database::Db::open(&config.datadir.join("db")).context("failed to open db")?;

		let vtxo_seed = {
			let master = bip32::ExtendedPrivKey::new_master(config.network, &seed).unwrap();
			master.derive_priv(&SECP, &[350.into()]).unwrap()
		};

		let asp_endpoint = tonic::transport::Uri::from_str(&config.asp_address)
			.context("invalid asp addr")?;
		let mut asp = rpc::ArkServiceClient::connect(asp_endpoint)
			.await.context("failed to connect to asp")?;

		let ark_info = {
			let res = asp.get_ark_info(arkd_rpc_client::Empty{})
				.await.context("ark info request failed")?.into_inner();
			ArkInfo {
				asp_pubkey: PublicKey::from_slice(&res.pubkey).context("asp pubkey")?,
				nb_round_nonces: res.nb_round_nonces as usize,
			}
		};

		Ok(Wallet { config, db, onchain, asp, vtxo_seed, ark_info })
	}

	pub fn get_new_onchain_address(&mut self) -> anyhow::Result<Address> {
		self.onchain.new_address()
	}

	pub fn onchain_balance(&mut self) -> anyhow::Result<Amount> {
		self.onchain.sync()
	}

	pub async fn offchain_balance(&self) -> anyhow::Result<Amount> {
		let mut sum = Amount::ZERO;
		for vtxo in self.db.get_all_vtxos()? {
			sum += vtxo.spec().amount;
			debug!("Vtxo {}: {}", vtxo.id(), vtxo.spec().amount);
		}
		Ok(sum)
	}

	//TODO(stevenroose) remove
	pub async fn drop_vtxos(&self) -> anyhow::Result<()> {
		for vtxo in self.db.get_all_vtxos()? {
			self.db.remove_vtxo(vtxo.id())?;
		}
		Ok(())
	}

	// Onboard a vtxo with the given vtxo amount.
	//
	// NB we will spend a little more on-chain to cover minrelayfee.
	pub async fn onboard(&mut self, amount: Amount) -> anyhow::Result<()> {
		let current_height = self.onchain.tip()?.0;
		//TODO(stevenroose) impl key derivation
		let key = KeyPair::from_secret_key(
			&SECP, &self.vtxo_seed.derive_priv(&SECP, &[0.into()]).unwrap().private_key,
		);
		let spec = ark::VtxoSpec {
			user_pubkey: key.public_key(),
			asp_pubkey: self.ark_info.asp_pubkey,
			expiry_height: current_height + 14 * 144,
			exit_delta: 144,
			amount: amount,
		};
		let onboard_amount = amount + ark::onboard::onboard_surplus();
		let addr = Address::from_script(&ark::onboard::onboard_spk(&spec), self.config.network).unwrap();

		// We create the onboard tx template, but don't sign it yet.
		let onboard_tx = self.onchain.prepare_tx(addr, onboard_amount)?;
		let utxo = OutPoint::new(onboard_tx.unsigned_tx.txid(), 0);

		// We ask the ASP to cosign our onboard unlock tx.
		let (user_part, priv_user_part) = ark::onboard::new_user(spec, utxo);
		trace!("User part for onboard: {:#?}", user_part);
		let asp_part = {
			let res = self.asp.request_onboard_cosign(arkd_rpc_client::OnboardCosignRequest {
				user_part: {
					let mut buf = Vec::new();
					ciborium::into_writer(&user_part, &mut buf).unwrap();
					buf
				},
			}).await.context("error requesting onboard cosign")?;
			ciborium::from_reader::<ark::onboard::AspPart, _>(&res.into_inner().asp_part[..])
				.context("invalid ASP part in response")?
		};

		// Store vtxo first before we actually make the on-chain tx.
		let vtxo = ark::onboard::finish(user_part, asp_part, priv_user_part, &key); 
		self.db.store_vtxo(vtxo).context("db error storing vtxo")?;

		let tx = self.onchain.finish_tx(onboard_tx)?;
		trace!("Broadcasting onboard tx: {}", bitcoin::consensus::encode::serialize_hex(&tx));
		self.onchain.broadcast_tx(&tx)?;

		info!("Onboard successfull");

		Ok(())
	}

	/// Exit all vtxo onto the chain.
	pub async fn start_unilateral_exit(&mut self) -> anyhow::Result<()> {
		let vtxos = self.db.get_all_vtxos()?;
		info!("Starting unilateral exit of {} vtxos...", vtxos.len());
		for vtxo in vtxos {
			let id = vtxo.id();
			match vtxo {
				Vtxo::Onboard { spec, utxo, unlock_tx_signature } => {
					let unlock_tx = ark::onboard::create_unlock_tx(
						&spec, utxo, Some(&unlock_tx_signature),
					);
					debug!("Broadcasting unlock tx for vtxo {}: {}", id, unlock_tx.txid());
					if let Err(e) = self.onchain.broadcast_tx(&unlock_tx) {
						error!("Error broadcasting unlock tx for onboard vtxo {}: {}", id, e);
					}
				},
				Vtxo::Round { spec: _, utxo: _, leaf_idx: _, exit_branch } => {
					debug!("Broadcasting {} txs of exit branch for vtxo {}", exit_branch.len(), id);
					for tx in exit_branch {
						if let Err(e) = self.onchain.broadcast_tx(&tx) {
							error!("Error broadcasting exit branch tx {} for vtxo {}: {}",
								tx.txid(), id, e,
							);
						}
					}
				},
			}
			//TODO(stevenroose) store something in db that we started this process
		}
		Ok(())
	}

	pub async fn send_payment(&mut self, destination: Destination) -> anyhow::Result<()> {
		// Prepare the payment.
		let input_vtxos = self.db.get_all_vtxos()?;
		let vtxo_ids = input_vtxos.iter().map(|v| v.id()).collect::<HashSet<_>>();
		let vtxo_key = self.vtxo_seed.to_keypair(&SECP);
		let change = {
			let sum = input_vtxos.iter().map(|v| v.amount()).sum::<Amount>();
			if sum < destination.amount {
				bail!("Balance too low");
			} else if sum == destination.amount {
				info!("No change, emptying wallet.");
				None
			} else {
				let amount = sum - destination.amount;
				info!("Adding change destinatioin for {}", amount);
				Some(Destination {
					pubkey: vtxo_key.public_key(),
					amount,
				})
			}
		};

		let mut events = self.asp.subscribe_rounds(rpc::Empty {}).await?.into_inner();

		// Wait for the next round start.
		trace!("Waiting for a round start.");
		let mut round_id = loop {
			match events.next().await.context("events stream broke")??.event.unwrap() {
				rpc::round_event::Event::Start(rpc::RoundStart { round_id }) => break round_id,
				_ => {},
			}
		};

		'round: loop {
			debug!("Participating in round {}", round_id);

			// Prepare round participation info.
			let cosign_key = KeyPair::new(&SECP, &mut rand::thread_rng());
			let (sec_nonces, pub_nonces) = {
				let mut secs = Vec::with_capacity(self.ark_info.nb_round_nonces);
				let mut pubs = Vec::with_capacity(self.ark_info.nb_round_nonces);
				for _ in 0..self.ark_info.nb_round_nonces {
					let (s, p) = musig::nonce_pair(&cosign_key);
					secs.push(s);
					pubs.push(p);
				}
				(secs, pubs)
			};

			// The round has now started. We can submit our payment.
			trace!("Submitting payment request");
			self.asp.submit_payment(rpc::SubmitPaymentRequest {
				cosign_pubkey: cosign_key.public_key().serialize().to_vec(),
				input_vtxos: input_vtxos.iter().map(|v| v.encode()).collect(),
				destinations: Some(&destination).iter().chain(change.as_ref().iter()).map(|d| {
					rpc::Destination {
						amount: d.amount.to_sat(),
						public_key: d.pubkey.serialize().to_vec(),
					}
				}).collect(),
				public_nonces: pub_nonces.iter().map(|n| n.serialize().to_vec()).collect(),
			}).await?;

			// Wait for proposal from asp.
			let (vtxo_tree, round_tx, vtxo_signers, vtxo_agg_nonces, forfeit_nonces) = loop {
				//TODO(stevenroose) should we really gracefully handle ASP malformed data?
				// panicking seems kinda ok since if we can't understand the ASP,
				// what are we even doing?
				match events.next().await.context("events stream broke")??.event.unwrap() {
					rpc::round_event::Event::Proposal(p) => {
						assert_eq!(p.round_id, round_id, "missing messages");
						let vtxos = VtxoTreeSpec::decode(&p.vtxos_spec)
							.context("decoding vtxo spec")?;
						let tx = bitcoin::consensus::deserialize::<Transaction>(&p.round_tx)
							.context("decoding round tx")?;
						let cosigners = p.vtxos_signers.into_iter().map(|k| {
							PublicKey::from_slice(&k).context("invalid pubkey")
						}).collect::<anyhow::Result<Vec<_>>>()?;
						let vtxo_nonces = p.vtxos_agg_nonces.into_iter().map(|k| {
							musig::MusigAggNonce::from_slice(&k).context("invalid agg nonce")
						}).collect::<anyhow::Result<Vec<_>>>()?;

						// Directly filter the forfeit nonces only for out inputs.
						let forfeit_nonces = p.forfeit_nonces.into_iter().filter_map(|f| {
							let id = VtxoId::from_slice(&f.input_vtxo_id)
								.expect("invalid vtxoid from asp"); //TODO(stevenroose) maybe handle?
							if vtxo_ids.contains(&id) {
								let nonces = f.pub_nonces.into_iter().map(|s| {
									musig::MusigPubNonce::from_slice(&s)
										.expect("invalid forfeit nonce from asp")
								}).collect::<Vec<_>>();
								Some((id, nonces))
							} else {
								None
							}
						}).collect::<HashMap<_, _>>();

						break (vtxos, tx, cosigners, vtxo_nonces, forfeit_nonces);
					},
					// If a new round started meanwhile, pick up on that one.
					rpc::round_event::Event::Start(rpc::RoundStart { round_id: id }) => {
						error!("Unexpected new round start...");
						round_id = id;
						continue 'round;
					},
					//TODO(stevenroose) make this robust
					other => panic!("Unexpected message: {:?}", other),
				}
			};

			let vtxos_utxo = OutPoint::new(round_tx.txid(), 0);
			let conns_utxo = OutPoint::new(round_tx.txid(), 1);

			// Make forfeit signatures.
			let connectors = ConnectorChain::new(
				forfeit_nonces.len(), conns_utxo, self.ark_info.asp_pubkey,
			);
			let forfeit_signatures = input_vtxos.iter().map(|v| {
				let sigs = connectors.connectors().enumerate().map(|(i, conn)| {
					let (sighash, _tx) = ark::forfeit::forfeit_sighash(v, conn);
					let asp_nonce = forfeit_nonces.get(&v.id())
						.with_context(|| format!("missing asp forfeit nonce for {}", v.id()))?
						.get(i)
						.context("asp didn't provide enough forfeit nonces")?;

					let (nonce, sig) = musig::deterministic_partial_sign(
						&vtxo_key,
						[vtxo_key.public_key(), self.ark_info.asp_pubkey],
						[asp_nonce.clone()],
						sighash.to_byte_array(),
						Some(v.spec().exit_taptweak().to_byte_array()),
					);
					Ok((nonce, sig))
				}).collect::<anyhow::Result<Vec<_>>>()?;
				Ok((v.id(), sigs))
			}).collect::<anyhow::Result<HashMap<_, _>>>()?;

			// Make vtxo signatures from top to bottom, just like sighashes are returned.
			let sighashes = vtxo_tree.sighashes(vtxos_utxo);
			assert_eq!(sighashes.len(), vtxo_agg_nonces.len());
			let signatures = iter::zip(sec_nonces.into_iter(), iter::zip(sighashes, vtxo_agg_nonces))
				.map(|(sec_nonce, (sighash, agg_nonce))| {
					musig::partial_sign(
						vtxo_signers.iter().copied(),
						agg_nonce,
						&cosign_key,
						sec_nonce,
						sighash.to_byte_array(),
						Some(vtxo_tree.cosign_taptweak().to_byte_array()),
						None,
					).0
				}).collect::<Vec<_>>();
			trace!("Sending signatures to ASP");
			self.asp.provide_signatures(rpc::RoundSignatures {
				forfeit: forfeit_signatures.into_iter().map(|(id, sigs)| {
					rpc::ForfeitSignatures {
						input_vtxo_id: id.bytes().to_vec(),
						pub_nonces: sigs.iter().map(|s| s.0.serialize().to_vec()).collect(),
						signatures: sigs.iter().map(|s| s.1.serialize().to_vec()).collect(),
					}
				}).collect(),
				vtxo: Some(rpc::VtxoSignatures {
					pubkey: cosign_key.public_key().serialize().to_vec(),
					signatures: signatures.iter().map(|s| s.serialize().to_vec()).collect(),
				}),
			}).await?;

			// Wait for the finishing of the round.
			trace!("Waiting for round finish...");
			let (vtxos, round_tx) = match events.next().await.context("events stream broke")??.event.unwrap() {
				rpc::round_event::Event::Finished(f) => {
					assert_eq!(f.round_id, round_id);
					let vtxos = SignedVtxoTree::decode(&f.signed_vtxos)
						.context("invalid vtxo tree from asp")?;
					let tx = bitcoin::consensus::deserialize::<Transaction>(&f.round_tx)
						.context("invalid round tx from asp")?;
					(vtxos, tx)
				},
				// If a new round started meanwhile, pick up on that one.
				rpc::round_event::Event::Start(rpc::RoundStart { round_id: id }) => {
					error!("Unexpected new round start...");
					round_id = id;
					continue 'round;
				},
				//TODO(stevenroose) make this robust
				other => panic!("Unexpected message: {:?}", other),
			};

			// First we also broadcast the tx.
			info!("Round finished, broadcasting round tx {}", round_tx.txid());
			if let Err(e) = self.onchain.broadcast_tx(&round_tx) {
				warn!("Couldn't broadcast round_tx: {}", e);
			}

			// Now we have to extract our own vtxos from the tree.
			// Initially this will just be one, our change.
			if let Some(change) = change {
				let leaf_idx = {
					let mut iter = vtxos.spec().find_leaf_idxs(&change);
					let ret = iter.next().context("asp didn't include our change")?;
					if iter.next().is_some() {
						error!("Our change was included twice??");
					}
					ret
				};
				let exit_branch = vtxos.exit_branch(leaf_idx).unwrap();
				let vtxo = Vtxo::Round {
					spec: VtxoSpec {
						user_pubkey: change.pubkey,
						asp_pubkey: self.ark_info.asp_pubkey,
						expiry_height: vtxos.spec().expiry_height,
						exit_delta: vtxos.spec().exit_delta,
						amount: change.amount,
					},
					utxo: vtxos_utxo,
					leaf_idx: leaf_idx,
					exit_branch: exit_branch,
				};
				self.db.store_vtxo(vtxo).context("failed to store vtxo")?;
			} else {
				info!("We used up all our money..");
			}

			// And remove the input vtxos.
			for v in input_vtxos {
				self.db.remove_vtxo(v.id()).context("failed to drop input vtxo")?;
			}

			info!("Finished payment");
			break;
		}

		Ok(())
	}
}
