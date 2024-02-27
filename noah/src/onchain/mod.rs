
mod chain;
pub use self::chain::ChainSource;

use std::iter;
use std::path::Path;

use anyhow::Context;
use bdk::SignOptions;
use bdk_file_store::Store;
use bdk_esplora::EsploraAsyncExt;
use bitcoin::{
	bip32, psbt, Address, Amount, Network, OutPoint, Sequence, Transaction, TxOut, Txid,
};
use bitcoin::psbt::PartiallySignedTransaction as Psbt; //TODO(stevenroose) when v0.31

use crate::exit;
use crate::psbtext::PsbtInputExt;
use self::chain::ChainSourceClient;

const DB_MAGIC: &str = "onchain_bdk";

pub struct Wallet {
	wallet: bdk::Wallet<Store<'static, bdk::wallet::ChangeSet>>,
	chain_source: ChainSourceClient,
}

impl Wallet {
	pub fn create(
		network: Network,
		seed: [u8; 64],
		dir: &Path,
		chain_source: ChainSource,
	) -> anyhow::Result<Wallet> {
		let db_path = dir.join("bdkwallet.db");
		let db = Store::<bdk::wallet::ChangeSet>::open_or_create_new(DB_MAGIC.as_bytes(), db_path)?;

		//TODO(stevenroose) taproot?
		let xpriv = bip32::ExtendedPrivKey::new_master(network, &seed).expect("valid seed");
		let edesc = format!("tr({}/84'/0'/0'/0/*)", xpriv);
		let idesc = format!("tr({}/84'/0'/0'/1/*)", xpriv);

		let wallet = bdk::Wallet::new_or_load(&edesc, Some(&idesc), db, network)
			.context("failed to create or load bdk wallet")?;
		
		let chain_source = ChainSourceClient::new(chain_source)?;
		Ok(Wallet { wallet, chain_source })
	}

	pub async fn tip(&self) -> anyhow::Result<u32> {
		self.chain_source.tip().await
	}

	pub async fn broadcast_tx(&self, tx: &Transaction) -> anyhow::Result<()> {
		self.chain_source.broadcast_tx(tx).await
	}

	pub async fn txout_confirmations(&self, outpoint: OutPoint) -> anyhow::Result<Option<u32>> {
		self.chain_source.txout_confirmations(outpoint).await
	}

	pub async fn sync(&mut self) -> anyhow::Result<Amount> {
		debug!("Starting wallet sync...");

		let prev_tip = self.wallet.latest_checkpoint();
		match self.chain_source {
			ChainSourceClient::Bitcoind(ref bitcoind) => {
				let mut emitter = bdk_bitcoind_rpc::Emitter::new(
					bitcoind, prev_tip.clone(), prev_tip.height(),
				);
				while let Some(em) = emitter.next_block()? {
					self.wallet.apply_block_connected_to(
						&em.block, em.block_height(), em.connected_to(),
					)?;
					self.wallet.commit()?;
				}

				let mempool = emitter.mempool()?;
				self.wallet.apply_unconfirmed_txs(mempool.iter().map(|(tx, time)| (tx, *time)));
				self.wallet.commit()?;
			},
			ChainSourceClient::Esplora(ref client) => {
				const STOP_GAP: usize = 50;

				let prev_tip = self.wallet.latest_checkpoint();
				let keychain_spks = self.wallet.spks_of_all_keychains().into_iter().collect();
				let (update_graph, last_active_indices) =
					client.full_scan(keychain_spks, STOP_GAP, 4).await?;
				let missing_heights = update_graph.missing_heights(self.wallet.local_chain());
				let chain_update = client.update_local_chain(prev_tip, missing_heights).await?;
				let update = bdk::wallet::Update {
					last_active_indices,
					graph: update_graph,
					chain: Some(chain_update),
				};
				self.wallet.apply_update(update)?;
				self.wallet.commit()?;
			},
		}

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

	pub async fn send_money(&mut self, dest: Address, amount: Amount) -> anyhow::Result<Txid> {
		self.sync().await.context("sync error")?;
		let psbt = self.prepare_tx(dest, amount)?;
		let tx = self.finish_tx(psbt)?;
		self.broadcast_tx(&tx).await?;
		Ok(tx.txid())
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
					output: iter::repeat(TxOut::default()).take(utxo.vout as usize)
						.chain([ark::fee::dust_anchor()]).collect(),
				}),
				..Default::default()
			};
			b.add_foreign_utxo(*utxo, psbt_in, 33).expect("adding foreign utxo");
		}
	}

	pub async fn spend_fee_anchors(
		&mut self,
		anchors: &[OutPoint],
		package_vsize: usize,
	) -> anyhow::Result<Transaction> {
		self.sync().await.context("sync error")?;

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
			b.add_recipient(change_addr.address.script_pubkey(), package_fee + ark::P2TR_DUST_SAT);
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
		self.broadcast_tx(&tx).await.context("failed to broadcast fee anchor spend")?;
		Ok(tx)
	}

	pub async fn create_exit_claim_tx(&mut self, inputs: &[exit::ClaimInput]) -> anyhow::Result<Psbt> {
		assert!(!inputs.is_empty());
		self.sync().await.context("sync error")?;

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
