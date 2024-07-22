

#[macro_use] extern crate anyhow;
#[macro_use] extern crate log;
#[macro_use] extern crate serde;


mod database;
mod psbtext;
mod rpc;
mod rpcserver;
mod round;
mod util;

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use bdk_bitcoind_rpc::bitcoincore_rpc::{RawTx, RpcApi};
use bitcoin::{bip32, sighash, psbt, taproot, Amount, Address, OutPoint, Transaction, Witness};
use bitcoin::secp256k1::{self, Keypair};
use tokio::sync::{Mutex, RwLock};

use ark::util::KeypairExt;
use ark::musig;

use crate::psbtext::{PsbtInputExt, RoundMeta};
use crate::round::{RoundEvent, RoundInput};

const DB_MAGIC: &str = "bdk_wallet";

lazy_static::lazy_static! {
	/// Global secp context.
	static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}


#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
	pub network: bitcoin::Network,
	pub public_rpc_address: SocketAddr,
	pub public_rpc_tls_cert_path: Option<PathBuf>,
	pub public_rpc_tls_key_path: Option<PathBuf>,
	pub admin_rpc_address: Option<SocketAddr>,
	pub bitcoind_url: String,
	pub bitcoind_cookie: String,

	pub round_interval: Duration,
	pub round_submit_time: Duration,
	pub round_sign_time: Duration,
	pub nb_round_nonces: usize,
	pub vtxo_expiry_delta: u16,
	pub vtxo_exit_delta: u16,
}

// NB some random defaults to have something
impl Default for Config {
	fn default() -> Config {
		Config {
			network: bitcoin::Network::Regtest,
			public_rpc_address: "0.0.0.0:3535".parse().unwrap(),
			public_rpc_tls_cert_path: None,
			public_rpc_tls_key_path: None,
			admin_rpc_address: Some("127.0.0.1:3536".parse().unwrap()),
			bitcoind_url: "http://127.0.0.1:38332".into(),
			bitcoind_cookie: "~/.bitcoin/signet/.cookie".into(),
			round_interval: Duration::from_secs(10),
			round_submit_time: Duration::from_secs(2),
			round_sign_time: Duration::from_secs(2),
			nb_round_nonces: 100,
			vtxo_expiry_delta: 1 * 24 * 6, // 1 day
			vtxo_exit_delta: 2 * 6, // 2 hrs
		}
	}
}

pub struct RoundHandle {
	/// Whenever a round is going on, this lock will be held.
	/// This helps us schedule tasks like db cleanups without
	/// interfering with rounds.
	round_busy: RwLock<()>,
	round_event_tx: tokio::sync::broadcast::Sender<RoundEvent>,
	round_input_tx: tokio::sync::mpsc::UnboundedSender<RoundInput>,
	round_trigger_tx: tokio::sync::mpsc::Sender<()>,
}

pub struct App {
	config: Config,
	db: database::Db,
	master_xpriv: bip32::Xpriv,
	master_key: Keypair,
	wallet: Mutex<bdk_wallet::Wallet>,
	wallet_store: Mutex<bdk_file_store::Store<bdk_wallet::wallet::ChangeSet>>,
	bitcoind: bdk_bitcoind_rpc::bitcoincore_rpc::Client,
	rounds: Option<RoundHandle>,
}

impl App {
	pub fn create(datadir: &Path, config: Config) -> anyhow::Result<()> {
		info!("Creating arkd server at {}", datadir.display());
		trace!("Config: {:?}", config);

		// create dir if not exit, but check that it's empty
		fs::create_dir_all(&datadir).context("can't create dir")?;
		if fs::read_dir(&datadir).context("can't read dir")?.next().is_some() {
			bail!("dir is not empty");
		}

		// write the config to disk
		let config_str = serde_json::to_string_pretty(&config)
			.expect("serialization can't error");
		fs::write(datadir.join("config.json"), config_str.as_bytes())
			.context("failed to write config file")?;

		// create mnemonic and store in empty db
		let db_path = datadir.join("arkd_db");
		info!("Loading db at {}", db_path.display());
		let db = database::Db::open(&db_path).context("failed to open db")?;
		let mnemonic = bip39::Mnemonic::generate(12).expect("12 is valid");
		db.store_master_mnemonic_and_seed(&mnemonic)
			.context("failed to store mnemonic")?;

		Ok(())
	}

	pub fn open(datadir: &Path) -> anyhow::Result<Arc<Self>> {
		info!("Starting arkd at {}", datadir.display());

		let config = {
			let path = datadir.join("config.json");
			let bytes = fs::read(&path)
				.with_context(|| format!("failed to read config file: {}", path.display()))?;
			serde_json::from_slice::<Config>(&bytes).context("invalid config file")?
		};
		trace!("Config: {:?}", config);

		let db_path = datadir.join("arkd_db");
		info!("Loading db at {}", db_path.display());
		let db = database::Db::open(&db_path).context("failed to open db")?;

		let seed = db.get_master_seed()
			.context("db error")?
			.context("db doesn't contain seed")?;
		let (master_key, xpriv) = {
			let seed_xpriv = bip32::Xpriv::new_master(config.network, &seed).unwrap();
			let path = bip32::DerivationPath::from_str("m/0").unwrap();
			let xpriv = seed_xpriv.derive_priv(&SECP, &path).unwrap();
			let keypair = Keypair::from_secret_key(&SECP, &xpriv.private_key);
			(keypair, xpriv)
		};

		let db_path = datadir.join("wallet.db");
		info!("Loading wallet db from {}", db_path.display());
		let mut file_store = bdk_file_store::Store::<bdk_wallet::wallet::ChangeSet>::open_or_create_new(
			DB_MAGIC.as_bytes(), db_path,
			)?;
		let wallet = {
			let change_set = file_store.aggregate_changesets()?;

			let edesc = format!("tr({}/84'/0'/0'/0/*)", xpriv);
			let idesc = format!("tr({}/84'/0'/0'/1/*)", xpriv);

			debug!("Opening BDK wallet with descriptor {}", edesc);
			bdk_wallet::Wallet::new_or_load(&edesc, &idesc, change_set, config.network)
				.context("failed to create or load bdk wallet")?
		};

		let bitcoind = bdk_bitcoind_rpc::bitcoincore_rpc::Client::new(
			&config.bitcoind_url,
			bdk_bitcoind_rpc::bitcoincore_rpc::Auth::CookieFile(config.bitcoind_cookie.as_str().into()),
		).context("failed to create bitcoind rpc client")?;


		Ok(Arc::new(App {
			config,
			db,
			master_xpriv: xpriv,
			master_key,
			wallet: Mutex::new(wallet),
			wallet_store: Mutex::new(file_store),
			bitcoind,
			rounds: None,
		}))
	}

	pub fn start(self: &mut Arc<Self>) -> anyhow::Result<tokio::task::JoinHandle<anyhow::Result<()>>> {
		let mut_self = Arc::get_mut(self).context("can only start if we are unique Arc")?;

		let (round_event_tx, _rx) = tokio::sync::broadcast::channel(8);
		let (round_input_tx, round_input_rx) = tokio::sync::mpsc::unbounded_channel();
		let (round_trigger_tx, round_trigger_rx) = tokio::sync::mpsc::channel(1);

		mut_self.rounds = Some(RoundHandle {
			round_busy: RwLock::new(()),
			round_event_tx,
			round_input_tx,
			round_trigger_tx,
		});

		let app = self.clone();
		let jh = tokio::spawn(async move {
			//TODO(stevenroose) make this block less redundant
			if app.config.admin_rpc_address.is_some() {
				tokio::select! {
					ret = rpcserver::run_public_rpc_server(app.clone()) => {
						ret.context("error from public gRPC server")
					},
					ret = rpcserver::run_admin_rpc_server(app.clone()) => {
						ret.context("error from admin gRPC server")
					},
					ret = round::run_round_scheduler(app.clone(), round_input_rx, round_trigger_rx) => {
						ret.context("error from round scheduler")
					},
				}
			} else {
				tokio::select! {
					ret = rpcserver::run_public_rpc_server(app.clone()) => {
						ret.context("error from public gRPC server")
					},
					ret = round::run_round_scheduler(app.clone(), round_input_rx, round_trigger_rx) => {
						ret.context("error from round scheduler")
					},
				}
			}
		});

		Ok(jh)
	}

	pub fn try_rounds(&self) -> anyhow::Result<&RoundHandle> {
		self.rounds.as_ref().context("no round scheduler started yet")
	}

	pub fn rounds(&self) -> &RoundHandle {
		self.try_rounds().expect("should only call this in round scheduler code")
	}

	pub async fn onchain_address(&self) -> anyhow::Result<Address> {
		let mut wallet = self.wallet.lock().await;
		let ret = wallet.next_unused_address(bdk_wallet::KeychainKind::External).address;
		// should always return the same address
		debug_assert_eq!(ret, wallet.next_unused_address(bdk_wallet::KeychainKind::External).address);
		Ok(ret)
	}

	pub async fn sync_onchain_wallet(& self) -> anyhow::Result<Amount> {
		let mut wallet = self.wallet.lock().await;
		let mut file_store = self.wallet_store.lock().await;
		let prev_tip = wallet.latest_checkpoint();
		// let keychain_spks = self.wallet.spks_of_all_keychains();

		debug!("Starting onchain sync at block height {}", prev_tip.height());
		let mut emitter = bdk_bitcoind_rpc::Emitter::new(&self.bitcoind, prev_tip.clone(), prev_tip.height());
		while let Some(em) = emitter.next_block()? {
			wallet.apply_block_connected_to(&em.block, em.block_height(), em.connected_to())?;

			if em.block_height() % 10_000 == 0 {
				debug!("Synced until block {}, committing...", em.block_height());
				if let Some(change_set) = wallet.take_staged() {
					file_store.append_changeset(&change_set)?;
				}
			}
		}

		// mempool
		let mempool = emitter.mempool()?;
		wallet.apply_unconfirmed_txs(mempool.iter().map(|(tx, time)| (tx, *time)));
		if let Some(change_set) = wallet.take_staged() {
			file_store.append_changeset(&change_set)?;
		}

		// rebroadcast unconfirmed txs
		// NB during some round failures we commit a tx but fail to broadcast it,
		// so this ensures we still broadcast them afterwards
		for tx in wallet.transactions() {
			if !tx.chain_position.is_confirmed() {
				let bc = self.bitcoind.send_raw_transaction(tx.tx_node.tx.raw_hex());
				if let Err(e) = bc {
					warn!("Error broadcasting pending tx: {}", e);
				}
			}
		}

		let balance = wallet.balance();
		Ok(balance.total())
	}

	pub async fn drain(
		&self,
		address: Address<bitcoin::address::NetworkUnchecked>,
	) -> anyhow::Result<Transaction> {
		//TODO(stevenroose) also claim all expired round vtxos here!

		let addr = address.require_network(self.config.network)?;

		let mut file_store = self.wallet_store.lock().await;
		let mut wallet = self.wallet.lock().await;
		let mut b = wallet.build_tx();
		b.drain_to(addr.script_pubkey());
		b.drain_wallet();
		let mut psbt = b.finish().context("error building tx")?;
		let finalized = wallet.sign(&mut psbt, bdk_wallet::SignOptions::default())?;
		assert!(finalized);
		let tx = psbt.extract_tx()?;
		if let Some(change_set) = wallet.take_staged() {
			file_store.append_changeset(&change_set)?;
		};
		drop(wallet);

		if let Err(e) = self.bitcoind.send_raw_transaction(tx.raw_hex()) {
			error!("Error broadcasting tx: {}", e);
			error!("Try yourself: {}", tx.raw_hex());
		}

		Ok(tx)
	}

	pub fn cosign_onboard(&self, user_part: ark::onboard::UserPart) -> ark::onboard::AspPart {
		info!("Cosigning onboard request for utxo {}", user_part.utxo);
		ark::onboard::new_asp(&user_part, &self.master_key)
	}

	pub fn cosign_oor(
		&self,
		payment: &ark::oor::OorPayment,
		user_nonces: &[musig::MusigPubNonce],
	) -> anyhow::Result<(Vec<musig::MusigPubNonce>, Vec<musig::MusigPartialSignature>)> {
		let ids = payment.inputs.iter().map(|v| v.id()).collect::<Vec<_>>();
		if let Some(dup) = self.db.atomic_check_mark_oors_cosigned(ids.iter().copied())? {
			bail!("attempted to double sign OOR for vtxo {}", dup)
		} else {
			info!("Cosigning OOR tx {} with inputs: {:?}", payment.txid(), ids);
			let (nonces, sigs) = payment.sign_asp(&self.master_key, &user_nonces);
			Ok((nonces, sigs))
		}
	}

	/// Returns a set of UTXOs from previous rounds that can be spent.
	///
	/// It fills in the PSBT inputs with the fields required to sign,
	/// for signing use [sign_round_utxo_inputs].
	fn spendable_expired_vtxos(&self, height: u32) -> anyhow::Result<Vec<SpendableUtxo>> {
		let pubkey = self.master_key.public_key();

		let expired_rounds = self.db.get_expired_rounds(height)?;
		let mut ret = Vec::with_capacity(2 * expired_rounds.len());
		for round_txid in expired_rounds {
			let round = self.db.get_round(round_txid)?.expect("db has round");

			// First add the vtxo tree utxo.
			let (
				spend_cb, spend_script, spend_lv, spend_merkle,
			) = round.signed_tree.spec.expiry_scriptspend();
			let mut psbt_in = psbt::Input {
				witness_utxo: Some(round.tx.output[0].clone()),
				sighash_type: Some(sighash::TapSighashType::Default.into()),
				tap_internal_key: Some(round.signed_tree.spec.cosign_agg_pk),
				tap_scripts: [(spend_cb, (spend_script, spend_lv))].into_iter().collect(),
				tap_merkle_root: Some(spend_merkle),
				non_witness_utxo: None,
				..Default::default()
			};
			psbt_in.set_round_meta(round_txid, RoundMeta::Vtxo);
			ret.push(SpendableUtxo {
				point: OutPoint::new(round_txid, 0),
				psbt: psbt_in,
				weight: ark::tree::signed::NODE_SPEND_WEIGHT,
			});

			// Then add the connector output.
			// NB this is safe because we will use SIGHASH_ALL.
			let mut psbt_in = psbt::Input {
				witness_utxo: Some(round.tx.output[1].clone()),
				sighash_type: Some(sighash::TapSighashType::Default.into()),
				tap_internal_key: Some(pubkey.x_only_public_key().0),
				non_witness_utxo: None,
				..Default::default()
			};
			psbt_in.set_round_meta(round_txid, RoundMeta::Connector);
			ret.push(SpendableUtxo {
				point: OutPoint::new(round_txid, 1),
				psbt: psbt_in,
				weight: ark::connectors::INPUT_WEIGHT,
			});
		}

		Ok(ret)
	}

	fn sign_round_utxo_inputs(&self, psbt: &mut psbt::Psbt) -> anyhow::Result<()> {
		let mut shc = sighash::SighashCache::new(&psbt.unsigned_tx);
		let prevouts = psbt.inputs.iter()
			.map(|i| i.witness_utxo.clone().unwrap())
			.collect::<Vec<_>>();

		let connector_keypair = self.master_key.for_keyspend();
		for (idx, input) in psbt.inputs.iter_mut().enumerate() {
			if let Some((_round, meta)) = input.get_round_meta().context("corrupt psbt")? {
				match meta {
					RoundMeta::Vtxo => {
						let (control, (script, lv)) = input.tap_scripts.iter().next()
							.context("corrupt psbt: missing tap_scripts")?;
						let leaf_hash = taproot::TapLeafHash::from_script(script, *lv);
						let sighash = shc.taproot_script_spend_signature_hash(
							idx,
							&sighash::Prevouts::All(&prevouts),
							leaf_hash,
							sighash::TapSighashType::Default,
						).expect("all prevouts provided");
						trace!("Signing expired VTXO input for sighash {}", sighash);
						let sig = SECP.sign_schnorr(&sighash.into(), &self.master_key);
						let wit = Witness::from_slice(
							&[&sig[..], script.as_bytes(), &control.serialize()],
						);
						debug_assert_eq!(wit.size(), ark::tree::signed::NODE_SPEND_WEIGHT);
						input.final_script_witness = Some(wit);
					},
					RoundMeta::Connector => {
						let sighash = shc.taproot_key_spend_signature_hash(
							idx,
							&sighash::Prevouts::All(&prevouts),
							sighash::TapSighashType::Default,
						).expect("all prevouts provided");
						trace!("Signing expired connector input for sighash {}", sighash);
						let sig = SECP.sign_schnorr(&sighash.into(), &connector_keypair);
						input.final_script_witness = Some(Witness::from_slice(&[sig[..].to_vec()]));
					},
				}
			}
		}

		Ok(())
	}

	// ** SOME ADMIN COMMANDS **

	pub fn get_master_mnemonic(&self) -> anyhow::Result<String> {
		Ok(self.db.get_master_mnemonic()?.expect("app running"))
	}

	pub fn drop_all_oor_conflicts(&self) -> anyhow::Result<()> {
		self.db.clear_oor_cosigned()
	}
}

pub(crate) struct SpendableUtxo {
	pub point: OutPoint,
	pub psbt: psbt::Input,
	pub weight: usize,
}

impl SpendableUtxo {
	pub fn amount(&self) -> Amount {
		self.psbt.witness_utxo.as_ref().unwrap().value
	}
}
