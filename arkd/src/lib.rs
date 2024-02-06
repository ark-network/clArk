

#[macro_use] extern crate anyhow;
#[macro_use] extern crate log;
#[macro_use] extern crate serde;


mod database;
mod rpc;
mod rpcserver;
mod round;
mod util;

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use bitcoin::{Amount, Address};
use bitcoin::bip32;
use bitcoin::secp256k1::{self, KeyPair};
use tokio::sync::Mutex;

use round::{RoundEvent, RoundInput};

const DB_MAGIC: &str = "bdk_wallet";

lazy_static::lazy_static! {
	/// Global secp context.
	static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}


pub struct Config {
	pub network: bitcoin::Network,
	pub public_rpc_address: SocketAddr,
	pub datadir: PathBuf,

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
			public_rpc_address: "127.0.0.1:3535".parse().unwrap(),
			datadir: env::current_dir().unwrap().join("arkd-datadir"),
			round_interval: Duration::from_secs(10),
			round_submit_time: Duration::from_secs(2),
			round_sign_time: Duration::from_secs(2),
			nb_round_nonces: 100,
			vtxo_expiry_delta: 1 * 24 * 6, // 1 day
			vtxo_exit_delta: 2 * 6, // 2 hrs
		}
	}
}

pub struct App {
	config: Config,
	db: database::Db,
	master_key: KeyPair,
	wallet: Mutex<bdk::Wallet<bdk_file_store::Store<'static, bdk::wallet::ChangeSet>>>,
	bitcoind: bdk_bitcoind_rpc::bitcoincore_rpc::Client,
	// electrum: electrum_client::Client,
	
	round_event_tx: tokio::sync::broadcast::Sender<RoundEvent>,
	round_input_tx: tokio::sync::mpsc::UnboundedSender<RoundInput>,
}

impl App {
	pub fn start(config: Config) -> anyhow::Result<(Arc<Self>, tokio::task::JoinHandle<anyhow::Result<()>>)> {
		let db_path = config.datadir.join("arkd_db");
		info!("Loading db at {}", db_path.display());
		let db = database::Db::open(&db_path).context("failed to open db")?;

		// check if this db is new
		let seed = match db.get_master_seed().context("db error")? {
			Some(s) => s,
			None => {
				// db is new, insert mnemonic and seed
				let mnemonic = bip39::Mnemonic::generate(12).expect("12 is valid");
				db.store_master_mnemonic_and_seed(&mnemonic)
					.context("failed to store mnemonic")?;
				mnemonic.to_seed("").to_vec()
			}
		};
		let (master_key, xpriv) = {
			let seed_xpriv = bip32::ExtendedPrivKey::new_master(config.network, &seed).unwrap();
			let path = bip32::DerivationPath::from_str("m/0").unwrap();
			let xpriv = seed_xpriv.derive_priv(&SECP, &path).unwrap();
			let keypair = KeyPair::from_secret_key(&SECP, &xpriv.private_key);
			(keypair, xpriv)
		};

		let wallet = {
			let db_path = config.datadir.join("wallet.db");
			info!("Loading wallet db from {}", db_path.display());
			let db = bdk_file_store::Store::<bdk::wallet::ChangeSet>::open_or_create_new(
				DB_MAGIC.as_bytes(), db_path,
			)?;

			let desc = format!("tr({})", xpriv);
			debug!("Opening BDK wallet with descriptor {}", desc);
			bdk::Wallet::new_or_load(&desc, None, db, config.network)
				.context("failed to create or load bdk wallet")?
		};

		// let electrum_client = electrum_client::Client::new("ssl://electrum.blockstream.info:60002").unwrap();
		let bitcoind = bdk_bitcoind_rpc::bitcoincore_rpc::Client::new(
			"127.0.0.1:18443".into(),
			bdk_bitcoind_rpc::bitcoincore_rpc::Auth::UserPass("user".into(), "pass".into()),
		).context("failed to create bitcoind rpc client")?;

		let (round_event_tx, _rx) = tokio::sync::broadcast::channel(8);
		let (round_input_tx, round_input_rx) = tokio::sync::mpsc::unbounded_channel();

		let ret = Arc::new(App {
			config: config,
			db: db,
			master_key: master_key,
			wallet: Mutex::new(wallet),
			bitcoind: bitcoind,

			round_event_tx: round_event_tx,
			round_input_tx: round_input_tx,
		});

		let app = ret.clone();
		let jh = tokio::spawn(async move {
			tokio::select! {
				ret = rpcserver::run_public_rpc_server(app.clone()) => {
					ret.context("error from gRPC server")
				},
				ret = round::run_round_scheduler(app.clone(), round_input_rx) => {
					ret.context("error from round scheduler")
				},
			}
		});

		Ok((ret, jh))
	}

	pub async fn onchain_address(self: &Arc<Self>) -> anyhow::Result<Address> {
		let mut wallet = self.wallet.lock().await;
		let ret = wallet.try_get_address(bdk::wallet::AddressIndex::New)?.address;
		// should always return the same address
		debug_assert_eq!(ret, wallet.try_get_address(bdk::wallet::AddressIndex::New)?.address);
		Ok(ret)
	}

	pub async fn sync_onchain_wallet(self: &Arc<Self>) -> anyhow::Result<Amount> {
		let mut wallet = self.wallet.lock().await;
		let prev_tip = wallet.latest_checkpoint();
		// let keychain_spks = self.wallet.spks_of_all_keychains();

		let mut emitter = bdk_bitcoind_rpc::Emitter::new(&self.bitcoind, prev_tip.clone(), prev_tip.height());
		while let Some(em) = emitter.next_block()? {
			wallet.apply_block_connected_to(&em.block, em.block_height(), em.connected_to())?;
			wallet.commit()?;
		}

		// mempool
		let mempool = emitter.mempool()?;
		wallet.apply_unconfirmed_txs(mempool.iter().map(|(tx, time)| (tx, *time)));
		wallet.commit()?;

		// // electrum
		// let (
		// 	ElectrumUpdate {
		// 		chain_update,
		// 		relevant_txids,
		// 	},
		// 	keychain_update,
		// ) = self.electrum.full_scan(prev_tip, keychain_spks, STOP_GAP, BATCH_SIZE)?;
		// let missing = relevant_txids.missing_full_txs(self.wallet.as_ref());
		// let graph_update = relevant_txids.into_confirmation_time_tx_graph(&self.electrum, None, missing)?;
		// let wallet_update = Update {
		// 	last_active_indices: keychain_update,
		// 	graph: graph_update,
		// 	chain: Some(chain_update),
		// };
		// self.wallet.apply_update(wallet_update)?;
		// self.wallet.commit()?;

		let balance = wallet.get_balance();
		Ok(Amount::from_sat(balance.total()))
	}

	pub fn cosign_onboard(self: &Arc<Self>, user_part: ark::onboard::UserPart) -> ark::onboard::AspPart {
		info!("Cosigning onboard request for utxo {}", user_part.utxo);
		ark::onboard::new_asp(&user_part, &self.master_key)
	}
}
