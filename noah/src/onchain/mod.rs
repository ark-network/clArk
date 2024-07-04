
mod chain;
pub use self::chain::ChainSource;

use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;

use anyhow::Context;
use bdk_wallet::{KeychainKind, SignOptions};
use bdk_file_store::Store;
use bdk_esplora::EsploraAsyncExt;
use bitcoin::{
	bip32, psbt, Address, Amount, Network, OutPoint, Script, Sequence, Transaction, TxOut, Txid
};
use bitcoin::psbt::Psbt; //TODO(stevenroose) when v0.31

use crate::exit;
use crate::psbtext::PsbtInputExt;
use self::chain::ChainSourceClient;

const DB_MAGIC: &str = "onchain_bdk";

pub struct Wallet {
	wallet: bdk_wallet::Wallet,
	file_store: Store<bdk_wallet::wallet::ChangeSet>,
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
		let mut db = Store::<bdk_wallet::wallet::ChangeSet>::open_or_create_new(DB_MAGIC.as_bytes(), db_path)?;
		let change_set = db.aggregate_changesets()?;

		//TODO(stevenroose) taproot?
		let xpriv = bip32::Xpriv::new_master(network, &seed).expect("valid seed");
		let edesc = format!("tr({}/84'/0'/0'/0/*)", xpriv);
		let idesc = format!("tr({}/84'/0'/0'/1/*)", xpriv);

		let wallet = bdk_wallet::Wallet::new_or_load(&edesc, &idesc, change_set, network)
			.context("failed to create or load bdk wallet")?;
		
		let chain_source = ChainSourceClient::new(chain_source)?;
		Ok(Wallet { wallet, chain_source, file_store: db })
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

	fn generate_inspect(kind: KeychainKind) -> impl FnMut(u32, &Script) + Send + Sync + 'static {
        let mut once = Some(());
        let mut stdout = std::io::stdout();
        move |spk_i, _| {
            match once.take() {
                Some(_) => print!("\nScanning keychain [{:?}]", kind),
                None => print!(" {:<3}", spk_i),
            };
            stdout.flush().expect("must flush");
        }
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
					if let Some(change_set) = self.wallet.take_staged() {
						self.file_store.append_changeset(&change_set)?;
					}
				}

				let mempool = emitter.mempool()?;
				self.wallet.apply_unconfirmed_txs(mempool.iter().map(|(tx, time)| (tx, *time)));
				if let Some(change_set) = self.wallet.take_staged() {
					self.file_store.append_changeset(&change_set)?;
				}
			},
			ChainSourceClient::Esplora(ref client) => {
				let request = self.wallet.start_full_scan().inspect_spks_for_all_keychains({
					let mut once = BTreeSet::<KeychainKind>::new();
					move |keychain, spk_i, _| {
						match once.insert(keychain) {
							true => print!("\nScanning keychain [{:?}]", keychain),
							false => print!(" {:<3}", spk_i),
						}
						std::io::stdout().flush().expect("must flush")
					}
				}).inspect_spks_for_keychain(
					KeychainKind::External,
					Self::generate_inspect(KeychainKind::External),
					)
					.inspect_spks_for_keychain(
						KeychainKind::Internal,
						Self::generate_inspect(KeychainKind::Internal),
						);
				const STOP_GAP: usize = 50;
				const PARALLEL_REQUESTS: usize = 5;

				let mut update = client
					.full_scan(request, STOP_GAP, PARALLEL_REQUESTS)
					.await?;
				let now = std::time::UNIX_EPOCH.elapsed().unwrap().as_secs();
				let _ = update.graph_update.update_last_seen_unconfirmed(now);

				self.wallet.apply_update(update)?;
				if let Some(change_set) = self.wallet.take_staged() {
					self.file_store.append_changeset(&change_set)?;
				}
			},
		}

		let balance = self.wallet.balance();
		Ok(balance.total())
	}

	/// Fee rate to use for regular txs like onboards.
	fn regular_fee_rate_bdk(&self) -> bitcoin::FeeRate {
		//TODO(stevenroose) get from somewhere
		bitcoin::FeeRate::from_sat_per_vb(10).unwrap()
	}

	/// Fee rate to use for regular txs like onboards.
	pub fn regular_fee_rate(&self) -> bitcoin::FeeRate {
		bitcoin::FeeRate::from_sat_per_vb(10).unwrap()
	}

	/// Fee rate to use for urgent txs like exits.
	fn urgent_fee_rate_bdk(&self) -> bitcoin::FeeRate {
		//TODO(stevenroose) get from somewhere
		bitcoin::FeeRate::from_sat_per_vb(100).unwrap()
	}

	pub fn prepare_tx(&mut self, dest: Address, amount: Amount) -> anyhow::Result<Psbt> {
		let fee_rate = self.regular_fee_rate_bdk();
		let mut b = self.wallet.build_tx();
		b.ordering(bdk_wallet::wallet::tx_builder::TxOrdering::Untouched);
		b.add_recipient(dest.script_pubkey(), amount);
		b.fee_rate(fee_rate);
		b.enable_rbf();
		Ok(b.finish()?)
	}

	pub fn finish_tx(&mut self, mut psbt: Psbt) -> anyhow::Result<Transaction> {
		let opts = SignOptions {
			trust_witness_utxo: true,
			..Default::default()
		};
		let finalized = self.wallet.sign(&mut psbt, opts).context("failed to sign")?;
		assert!(finalized);
		if let Some(change_set) = self.wallet.take_staged() {
			self.file_store.append_changeset(&change_set)?;
		}
		Ok(psbt.extract_tx()?)
	}

	pub async fn send_money(&mut self, dest: Address, amount: Amount) -> anyhow::Result<Txid> {
		self.sync().await.context("sync error")?;
		let psbt = self.prepare_tx(dest, amount)?;
		let tx = self.finish_tx(psbt)?;
		self.broadcast_tx(&tx).await?;
		Ok(tx.compute_txid())
	}

	pub fn new_address(&mut self) -> anyhow::Result<Address> {
		Ok(self.wallet.next_unused_address(KeychainKind::External).address)
	}

	fn add_anchors<A>(b: &mut bdk_wallet::TxBuilder<A>, anchors: &[OutPoint])
	where 
		A: bdk_wallet::wallet::coin_selection::CoinSelectionAlgorithm,
	{
		for utxo in anchors {
			let psbt_in = psbt::Input {
				witness_utxo: Some(ark::fee::dust_anchor()),
				final_script_witness: Some(ark::fee::dust_anchor_witness()),
				non_witness_utxo: None,
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

		let urgent_fee_rate = self.urgent_fee_rate_bdk();
		let package_fee = urgent_fee_rate.fee_vb(package_vsize.try_into()?).unwrap();

		// Since BDK doesn't allow tx without recipients, we add a drain output.
		let change_addr = self.wallet.next_unused_address(KeychainKind::Internal);

		let template_size = {
			let mut b = self.wallet.build_tx();
			Wallet::add_anchors(&mut b, anchors);
			b.add_recipient(change_addr.address.script_pubkey(), package_fee + Amount::from_sat(ark::P2TR_DUST_SAT));
			b.fee_rate(urgent_fee_rate);
			let mut psbt = b.finish().expect("failed to craft anchor spend template");
			let opts = SignOptions {
				trust_witness_utxo: true,
				..Default::default()
			};
			let finalized = self.wallet.sign(&mut psbt, opts)
				.expect("failed to sign anchor spend template");
			assert!(finalized);
			psbt.extract_tx()?.vsize()
		};

		let total_vsize = template_size + package_vsize;
		let total_fee = self.urgent_fee_rate_bdk().fee_vb(total_vsize as u64).unwrap();

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

		let urgent_fee_rate = self.urgent_fee_rate_bdk();

		// Since BDK doesn't allow tx without recipients, we add a drain output.
		let change_addr = self.wallet.next_unused_address(KeychainKind::Internal);

		let mut b = self.wallet.build_tx();
		b.version(2);
		for input in inputs {
			let mut psbt_in = psbt::Input::default();
			psbt_in.set_claim_input(input);
			psbt_in.witness_utxo = Some(TxOut {
				script_pubkey: input.spec.exit_spk(),
				value: input.spec.amount,
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
