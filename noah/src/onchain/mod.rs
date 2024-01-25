const DB_MAGIC: &str = "onchain_bdk";
const STOP_GAP: usize = 50;
const BATCH_SIZE: usize = 5;

use std::fs;
use std::io::Write;
use std::path::Path;
use std::str::FromStr;

use anyhow::Context;
use bdk::wallet::Update;
use bdk::SignOptions;
use bdk_electrum::{
	electrum_client::{self, ElectrumApi},
	ElectrumExt, ElectrumUpdate,
};
use bdk_file_store::Store;
use bitcoin::{Address, Amount, BlockHash, Network, Transaction, Txid};
use bitcoin::psbt::PartiallySignedTransaction as Psbt; //TODO(stevenroose) when v0.31
use bitcoin::bip32;
use miniscript::Descriptor;


pub struct Wallet {
	wallet: bdk::Wallet<Store<'static, bdk::wallet::ChangeSet>>,
	bitcoind: bdk_bitcoind_rpc::bitcoincore_rpc::Client,
}

impl Wallet {
	pub fn create(network: Network, seed: [u8; 64], dir: &Path) -> anyhow::Result<Wallet> {
		let db_path = dir.join("onchain.db");
		let db = Store::<bdk::wallet::ChangeSet>::open_or_create_new(DB_MAGIC.as_bytes(), db_path)?;

		//TODO(stevenroose) taproot?
		let xpriv = bip32::ExtendedPrivKey::new_master(network, &seed).expect("valid seed");
		let edesc = format!("wpkh({}/84'/0'/0'/0/*)", xpriv);
		let idesc = format!("wpkh({}/84'/0'/0'/1/*)", xpriv);

		let mut wallet = bdk::Wallet::new_or_load(&edesc, Some(&idesc), db, network)
			.context("failed to create or load bdk wallet")?;
		
		// sync
		// let electrum_client = electrum_client::Client::new("ssl://electrum.blockstream.info:60002").unwrap();
		let bitcoind = bdk_bitcoind_rpc::bitcoincore_rpc::Client::new(
			"127.0.0.1:18443".into(),
			bdk_bitcoind_rpc::bitcoincore_rpc::Auth::UserPass("user".into(), "pass".into()),
		).context("failed to create bitcoind rpc client")?;

		Ok(Wallet {
			wallet: wallet,
			bitcoind: bitcoind,
		})
	}

	pub fn tip(&self) -> anyhow::Result<(u32, BlockHash)> {
		let he = bdk_bitcoind_rpc::bitcoincore_rpc::RpcApi::get_block_count(&self.bitcoind)?;
		let ha = bdk_bitcoind_rpc::bitcoincore_rpc::RpcApi::get_block_hash(&self.bitcoind, he)?;
		Ok((he as u32, ha))
	}

	pub fn sync(&mut self) -> anyhow::Result<Amount> {
		let prev_tip = self.wallet.latest_checkpoint();
		// let keychain_spks = self.wallet.spks_of_all_keychains();

		let mut emitter = bdk_bitcoind_rpc::Emitter::new(&self.bitcoind, prev_tip.clone(), prev_tip.height());
		while let Some(em) = emitter.next_block()? {
			self.wallet.apply_block_connected_to(&em.block, em.block_height(), em.connected_to())?;
			self.wallet.commit()?;
		}

		// mempool
		let mempool = emitter.mempool()?;
		self.wallet.apply_unconfirmed_txs(mempool.iter().map(|(tx, time)| (tx, *time)));
		self.wallet.commit()?;

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

		let balance = self.wallet.get_balance();
		Ok(Amount::from_sat(balance.total()))
	}

	pub fn prepare_tx(&mut self, dest: Address, amount: Amount) -> anyhow::Result<Psbt> {
		let mut tx_builder = self.wallet.build_tx();
		tx_builder
			.add_recipient(dest.script_pubkey(), amount.to_sat())
			.enable_rbf();
		Ok(tx_builder.finish()?)
	}

	pub fn finish_tx(&mut self, mut psbt: Psbt) -> anyhow::Result<Transaction> {
		let finalized = self.wallet.sign(&mut psbt, SignOptions::default())?;
		assert!(finalized);
		Ok(psbt.extract_tx())
	}

	pub fn broadcast_tx(&self, tx: &Transaction) -> anyhow::Result<Txid> {
		bdk_bitcoind_rpc::bitcoincore_rpc::RpcApi::send_raw_transaction(&self.bitcoind, tx)?;
		// self.electrum.transaction_broadcast(&tx)?;
		Ok(tx.txid())
	}

	pub fn send_money(&mut self, dest: Address, amount: Amount) -> anyhow::Result<Txid> {
		let mut psbt = self.prepare_tx(dest, amount)?;
		let tx = self.finish_tx(psbt)?;
		self.broadcast_tx(&tx)
	}

	pub fn new_address(&mut self) -> anyhow::Result<Address> {
		Ok(self.wallet.try_get_address(bdk::wallet::AddressIndex::New)?.address)
	}
}
