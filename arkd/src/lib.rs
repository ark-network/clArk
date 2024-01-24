

#[macro_use] extern crate log;
#[macro_use] extern crate serde;


mod database;
mod rpc;
mod rpcserver;
mod round;

use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{bail, Context};
use bitcoin::{Amount, Address};
use bitcoin::bip32;
use bitcoin::secp256k1::{self, KeyPair, PublicKey};
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
			public_rpc_address: "127.0.0.1:350350".parse().unwrap(),
			datadir: "./".parse().unwrap(),
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
	pub fn start(config: Config) -> anyhow::Result<Arc<Self>> {
		let db = database::Db::open(&config.datadir.join("db"))
			.context("failed to open db")?;

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
		let master_key = {
			let xpriv = bip32::ExtendedPrivKey::new_master(config.network, &seed).unwrap();
			let deriv = bip32::DerivationPath::from_str("m/0").unwrap();
			KeyPair::from_secret_key(&SECP, &xpriv.derive_priv(&SECP, &deriv).unwrap().private_key)
		};

		let wallet = {
			let db_path = config.datadir.join("wallet_db");
			fs::create_dir_all(&db_path).context("failed to crate wallet dir")?;
			let db = bdk_file_store::Store::<bdk::wallet::ChangeSet>::open_or_create_new(
				DB_MAGIC.as_bytes(), db_path,
			)?;

			let desc = format!("tr({})", master_key.display_secret());
			bdk::Wallet::new_or_load(&desc, None, db, config.network)
				.context("failed to create or load bdk wallet")?
		};

		// let electrum_client = electrum_client::Client::new("ssl://electrum.blockstream.info:60002").unwrap();
		let bitcoind = bdk_bitcoind_rpc::bitcoincore_rpc::Client::new(
			"127.0.0.1:8332".into(),
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
		let _ = tokio::spawn(async move {
			rpcserver::run_public_rpc_server(app).await.expect("grpc server failed");
		});

		let app = ret.clone();
		let _ = tokio::spawn(async move {
			round::run_round_scheduler(app, round_input_rx).await.expect("round scheduler error")
		});

		Ok(ret)
	}

	pub fn onchain_address(self: &Arc<Self>) -> anyhow::Result<Address> {
		let mut wallet = self.wallet.blocking_lock();
		let ret = wallet.try_get_address(bdk::wallet::AddressIndex::New)?.address;
		// should always return the same address
		debug_assert_eq!(ret, wallet.try_get_address(bdk::wallet::AddressIndex::New)?.address);
		Ok(ret)
	}

	pub fn sync_onchain_wallet(self: &Arc<Self>) -> anyhow::Result<Amount> {
		let mut wallet = self.wallet.blocking_lock();
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
		ark::onboard::new_asp(&user_part, &self.master_key)
	}
}
