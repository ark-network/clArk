

mod database;
mod rpc;

use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::str::FromStr;

use anyhow::{bail, Context};
use bitcoin::{Amount, Address};
use bitcoin::bip32;
use bitcoin::secp256k1::{self, PublicKey, SecretKey};

const DB_MAGIC: &str = "bdk_wallet";

lazy_static::lazy_static! {
	/// Global secp context.
	static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}


pub struct Config {
	pub network: bitcoin::Network,
	pub public_rpc_address: SocketAddr,
	pub datadir: PathBuf,
}

pub struct App {
	config: Config,
	db: database::Db,
	master_key: SecretKey,
	master_pubkey: PublicKey,
	wallet: Mutex<bdk::Wallet<bdk_file_store::Store<'static, bdk::wallet::ChangeSet>>>,
	bitcoind: bdk_bitcoind_rpc::bitcoincore_rpc::Client,
	// electrum: electrum_client::Client,
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
			xpriv.derive_priv(&SECP, &deriv).unwrap().private_key
		};
		let master_pubkey = master_key.public_key(&SECP);

		let wallet = {
			let db_path = config.datadir.join("wallet_db");
			fs::create_dir_all(&db_path).context("failed to crate wallet dir")?;
			let db = bdk_file_store::Store::<bdk::wallet::ChangeSet>::open_or_create_new(
				DB_MAGIC.as_bytes(), db_path,
			)?;

			// let desc = miniscript::Descriptor::Tr(
			// 	miniscript::descriptor::Tr::new(master_key.clone(), None)
			// );
			let desc = format!("tr({})", master_key.display_secret());
			bdk::Wallet::new_or_load(&desc, None, db, config.network)
				.context("failed to create or load bdk wallet")?
		};

		// let electrum_client = electrum_client::Client::new("ssl://electrum.blockstream.info:60002").unwrap();
		let bitcoind = bdk_bitcoind_rpc::bitcoincore_rpc::Client::new(
			"127.0.0.1:8332".into(),
			bdk_bitcoind_rpc::bitcoincore_rpc::Auth::UserPass("user".into(), "pass".into()),
		).context("failed to create bitcoind rpc client")?;

		let ret = Arc::new(App {
			config: config,
			db: db,
			master_key: master_key,
			master_pubkey: master_pubkey,
			wallet: Mutex::new(wallet),
			bitcoind: bitcoind,
		});
		ret.start_public_rpc_server();

		Ok(ret)
	}

	pub fn onchain_address(self: &Arc<Self>) -> anyhow::Result<Address> {
		let mut wallet = self.wallet.lock().unwrap();
		let ret = wallet.try_get_address(bdk::wallet::AddressIndex::New)?.address;
		// should always return the same address
		debug_assert_eq!(ret, wallet.try_get_address(bdk::wallet::AddressIndex::New)?.address);
		Ok(ret)
	}

	pub fn sync_onchain_wallet(self: &Arc<Self>) -> anyhow::Result<Amount> {
		let mut wallet = self.wallet.lock().unwrap();
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

	pub async fn start_public_rpc_server(self: &Arc<Self>) {
		let addr = self.config.public_rpc_address;
		let server = rpc::ArkServiceServer::new(self.clone());
		//TODO(stevenroose) capture thread so we can cancel later
		let _ = tokio::spawn(async move {
			tonic::transport::Server::builder()
				.add_service(server)
				.serve(addr)
				.await
		});
	}
}

#[tonic::async_trait]
impl rpc::ArkService for Arc<App> {
	async fn get_ark_info(
		&self,
		_: tonic::Request<rpc::Empty>,
	) -> Result<tonic::Response<rpc::ArkInfo>, tonic::Status> {
		let ret = rpc::ArkInfo {
			pubkey: self.master_pubkey.serialize().to_vec(),
			xonly_pubkey: self.master_pubkey.x_only_public_key().0.serialize().to_vec(),
		};
		Ok(tonic::Response::new(ret))
	}
	async fn request_onboard_cosign(
		&self,
		req: tonic::Request<rpc::OnboardCosignRequest>,
	) -> Result<tonic::Response<rpc::OnboardCosignResponse>, tonic::Status> {
		unimplemented!();
	}
}

