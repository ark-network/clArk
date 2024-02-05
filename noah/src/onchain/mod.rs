

use std::path::Path;

use anyhow::Context;
use bdk::SignOptions;
use bdk_file_store::Store;
use bitcoin::{
	bip32, psbt, Address, Amount, BlockHash, Network, OutPoint, ScriptBuf, Sequence, Transaction,
	TxOut, Txid,
};
use bitcoin::psbt::PartiallySignedTransaction as Psbt; //TODO(stevenroose) when v0.31

use crate::exit;
use crate::psbt::PsbtInputExt;

const P2TR_DUST: u64 = 330;
const P2WPKH_DUST: u64 = 294;
const DB_MAGIC: &str = "onchain_bdk";

const TX_ALREADY_IN_CHAIN_ERROR: i32 = -27;

pub struct Wallet {
	wallet: bdk::Wallet<Store<'static, bdk::wallet::ChangeSet>>,
	bitcoind: bdk_bitcoind_rpc::bitcoincore_rpc::Client,
}

impl Wallet {
	pub fn create(network: Network, seed: [u8; 64], dir: &Path) -> anyhow::Result<Wallet> {
		let db_path = dir.join("bdkwallet.db");
		let db = Store::<bdk::wallet::ChangeSet>::open_or_create_new(DB_MAGIC.as_bytes(), db_path)?;

		//TODO(stevenroose) taproot?
		let xpriv = bip32::ExtendedPrivKey::new_master(network, &seed).expect("valid seed");
		let edesc = format!("tr({}/84'/0'/0'/0/*)", xpriv);
		let idesc = format!("tr({}/84'/0'/0'/1/*)", xpriv);

		let wallet = bdk::Wallet::new_or_load(&edesc, Some(&idesc), db, network)
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

	pub fn bitcoind(&self) -> &bdk_bitcoind_rpc::bitcoincore_rpc::Client {
		&self.bitcoind
	}

	pub fn tip(&self) -> anyhow::Result<(u32, BlockHash)> {
		let he = bdk_bitcoind_rpc::bitcoincore_rpc::RpcApi::get_block_count(&self.bitcoind)?;
		let ha = bdk_bitcoind_rpc::bitcoincore_rpc::RpcApi::get_block_hash(&self.bitcoind, he)?;
		Ok((he as u32, ha))
	}

	pub fn sync(&mut self) -> anyhow::Result<Amount> {
		debug!("Starting wallet sync...");

		let prev_tip = self.wallet.latest_checkpoint();
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

	/// Fee rate to use for regular txs like onboards.
	fn regular_fee_rate(&self) -> bdk::FeeRate {
		//TODO(stevenroose) get from somewhere
		bdk::FeeRate::from_sat_per_vb(10.0)
	}

	/// Fee rate to use for urgent txs like exits.
	fn urgent_fee_rate(&self) -> bdk::FeeRate {
		//TODO(stevenroose) get from somewhere
		bdk::FeeRate::from_sat_per_vb(100.0)
	}

	pub fn prepare_tx(&mut self, dest: Address, amount: Amount) -> anyhow::Result<Psbt> {
		let fee_rate = self.regular_fee_rate();
		let mut b = self.wallet.build_tx();
		b.ordering(bdk::wallet::tx_builder::TxOrdering::Untouched);
		b.add_recipient(dest.script_pubkey(), amount.to_sat());
		b.fee_rate(fee_rate);
		b.enable_rbf();
		Ok(b.finish()?)
	}

	pub fn finish_tx(&mut self, mut psbt: Psbt) -> anyhow::Result<Transaction> {
		let finalized = self.wallet.sign(&mut psbt, SignOptions::default())
			.context("failed to sign")?;
		assert!(finalized);
		self.wallet.commit().context("error committing wallet")?;
		Ok(psbt.extract_tx())
	}

	pub fn broadcast_tx(&self, tx: &Transaction) -> anyhow::Result<Txid> {
		// self.electrum.transaction_broadcast(&tx)?;
		match bdk_bitcoind_rpc::bitcoincore_rpc::RpcApi::send_raw_transaction(&self.bitcoind, tx) {
			Ok(_) => Ok(tx.txid()),
			Err(bdk_bitcoind_rpc::bitcoincore_rpc::Error::JsonRpc(
				bdk_bitcoind_rpc::bitcoincore_rpc::jsonrpc::Error::Rpc(e))
			) if e.code == TX_ALREADY_IN_CHAIN_ERROR => Ok(tx.txid()),
			Err(e) => Err(e.into()),
		}
	}

	pub fn send_money(&mut self, dest: Address, amount: Amount) -> anyhow::Result<Txid> {
		self.sync().context("sync error")?;
		let psbt = self.prepare_tx(dest, amount)?;
		let tx = self.finish_tx(psbt)?;
		self.broadcast_tx(&tx)
	}

	pub fn new_address(&mut self) -> anyhow::Result<Address> {
		Ok(self.wallet.try_get_address(bdk::wallet::AddressIndex::New)?.address)
	}

	fn add_anchors<A, B, C>(b: &mut bdk::TxBuilder<A, B, C>, anchors: &[OutPoint])
	where 
		B: bdk::wallet::coin_selection::CoinSelectionAlgorithm,
		C: bdk::wallet::tx_builder::TxBuilderContext,
	{
		for utxo in anchors {
			let psbt_in = psbt::Input {
				witness_utxo: Some(ark::fee::dust_anchor()),
				final_script_witness: Some(ark::fee::dust_anchor_witness()),
				//TODO(stevenroose) BDK wants this here, but it shouldn't
				non_witness_utxo: Some(Transaction {
					version: 2,
					lock_time: bitcoin::absolute::LockTime::ZERO,
					input: vec![],
					output: vec![ark::fee::dust_anchor(); utxo.vout as usize + 1],
				}),
				..Default::default()
			};
			b.add_foreign_utxo(*utxo, psbt_in, 33).expect("adding foreign utxo");
		}
	}

	pub fn spend_fee_anchors(
		&mut self,
		anchors: &[OutPoint],
		package_vsize: usize,
	) -> anyhow::Result<Transaction> {
		self.sync().context("sync error")?;

		// Since BDK doesn't support adding extra weight for fees, we have to
		// first build the tx regularly, and then build it again.
		// Since we have to guarantee that we have enough money in the inputs,
		// we will "fake" create an output on the first attempt. This might
		// overshoot the fee, but we prefer that over undershooting it.

		let urgent_fee_rate = self.urgent_fee_rate();
		let package_fee = urgent_fee_rate.fee_vb(package_vsize);

		// Since BDK doesn't allow tx without recipients, we add a drain output.
		let change_addr = self.wallet.try_get_internal_address(bdk::wallet::AddressIndex::New)?;

		let template_size = {
			let mut b = self.wallet.build_tx();
			Wallet::add_anchors(&mut b, anchors);
			b.add_recipient(change_addr.address.script_pubkey(), package_fee + P2TR_DUST);
			b.fee_rate(urgent_fee_rate);
			let mut psbt = b.finish().expect("failed to craft anchor spend template");
			let finalized = self.wallet.sign(&mut psbt, SignOptions::default())
				.expect("failed to sign anchor spend template");
			assert!(finalized);
			psbt.extract_tx().vsize()
		};

		let total_vsize = template_size + package_vsize;
		let total_fee = self.urgent_fee_rate().fee_vb(total_vsize);

		// Then build actual tx.
		let mut b = self.wallet.build_tx();
		trace!("setting version to 2");
		Wallet::add_anchors(&mut b, anchors);
		b.drain_to(change_addr.address.script_pubkey());
		b.fee_absolute(total_fee);
		let psbt = b.finish().expect("failed to craft anchor spend tx");
		let tx = self.finish_tx(psbt).context("error finalizing anchor spend tx")?;
		self.broadcast_tx(&tx).context("failed to broadcast fee anchor spend")?;
		Ok(tx)
	}

	pub fn create_exit_claim_tx(&mut self, inputs: &[exit::ClaimInput]) -> anyhow::Result<Psbt> {
		assert!(!inputs.is_empty());
		self.sync().context("sync error")?;

		let urgent_fee_rate = self.urgent_fee_rate();

		// Since BDK doesn't allow tx without recipients, we add a drain output.
		let change_addr = self.wallet.try_get_internal_address(bdk::wallet::AddressIndex::New)?;

		let mut b = self.wallet.build_tx();
		b.version(2);
		for input in inputs {
			let mut psbt_in = psbt::Input::default();
			psbt_in.set_claim_input(input);
			psbt_in.witness_utxo = Some(TxOut {
				script_pubkey: input.spec.exit_spk(),
				value: input.spec.amount.to_sat(),
			});
			b.add_foreign_utxo_with_sequence(
				input.utxo,
				psbt_in,
				input.satisfaction_weight(),
				Sequence::from_height(input.spec.exit_delta),
			).expect("error adding foreign utxo for claim input");
		}
		b.drain_to(change_addr.address.script_pubkey());
		b.fee_rate(urgent_fee_rate);

		Ok(b.finish().context("failed to craft claim tx")?)
	}
}
