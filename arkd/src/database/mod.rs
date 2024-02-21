
use std::io;
use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context};
use bitcoin::{Amount, OutPoint, Transaction, Txid};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::schnorr;
use rocksdb::{
	BoundColumnFamily, FlushOptions, OptimisticTransactionOptions, WriteBatchWithTransaction,
	WriteOptions,
};


use ark::{VtxoId, VtxoSpec};
use ark::tree::signed::SignedVtxoTree;


// COLUMN FAMILIES

/// mapping VtxoId -> ForfeitVtxo
const CF_FORFEIT_VTXO: &str = "forfeited_vtxos";
/// mapping Txid -> serialized StoredRound
const CF_ROUND: &str = "rounds";
/// set [expiry][txid]
const CF_ROUND_EXPIRY: &str = "rounds_by_expiry";

// ROOT ENTRY KEYS

const MASTER_SEED: &str = "master_seed";
const MASTER_MNEMONIC: &str = "master_mnemonic";


/// A vtxo that has been forfeited and is now ours.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum ForfeitVtxo {
	//TODO(stevenroose) for the forfeit sigs to make sense here, they need to include the round id
	//that they were spent in so that the connectors can be found!
	Onboard {
		spec: VtxoSpec,
		utxo: OutPoint,
		forfeit_sigs: Vec<schnorr::Signature>,
	},
	Round {
		spec: VtxoSpec,
		round_id: Txid,
		point: OutPoint,
		leaf_idx: usize,
		forfeit_sigs: Vec<schnorr::Signature>,
	},
}

impl ForfeitVtxo {
	pub fn id(&self) -> VtxoId {
		match self {
			Self::Onboard { utxo, .. } => (*utxo).into(),
			Self::Round { point, .. } => (*point).into(),
		}
	}

	pub fn amount(&self) -> Amount {
		match self {
			Self::Onboard { spec, .. } => spec.amount,
			Self::Round { spec, .. } => spec.amount,
		}
	}

	fn encode(&self) -> Vec<u8> {
		let mut buf = Vec::new();
		ciborium::into_writer(self, &mut buf).unwrap();
		buf
	}

	fn decode(bytes: &[u8]) -> Result<Self, ciborium::de::Error<io::Error>> {
		ciborium::from_reader(bytes)
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RoundExpiryKey {
	expiry: u32,
	id: Txid,
}

impl RoundExpiryKey {
	fn new(expiry: u32, id: Txid) -> Self {
		Self { expiry, id }
	}

	fn encode(&self) -> [u8; 36] {
		let mut ret = [0u8; 36];
		ret[0..4].copy_from_slice(&self.expiry.to_le_bytes());
		ret[4..].copy_from_slice(&self.id[..]);
		ret
	}

	fn decode(b: &[u8]) -> Self {
		assert_eq!(b.len(), 36, "corrupt round expiry key");
		Self {
			expiry: {
				let mut buf = [0u8; 4];
				buf[..].copy_from_slice(&b[0..4]);
				u32::from_le_bytes(buf)
			},
			id: Txid::from_slice(&b[4..]).unwrap(),
		}
	}
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StoredRound {
	pub tx: Transaction,
	pub signed_tree: SignedVtxoTree,
}

impl StoredRound {
	pub fn id(&self) -> Txid {
		self.tx.txid()
	}

	fn encode(&self) -> Vec<u8> {
		let mut buf = Vec::new();
		ciborium::into_writer(self, &mut buf).unwrap();
		buf
	}

	fn decode(bytes: &[u8]) -> Result<Self, ciborium::de::Error<io::Error>> {
		ciborium::from_reader(bytes)
	}
}


pub struct Db {
	db: rocksdb::OptimisticTransactionDB<rocksdb::MultiThreaded>,
}

impl Db {
	pub fn open(path: &Path) -> anyhow::Result<Db> {
		let mut opts = rocksdb::Options::default();
		opts.create_if_missing(true);
		opts.create_missing_column_families(true);

		let cfs = [CF_FORFEIT_VTXO, CF_ROUND, CF_ROUND_EXPIRY];
		let db = rocksdb::OptimisticTransactionDB::open_cf(&opts, path, cfs)
			.context("failed to open db")?;
		Ok(Db { db })
	}

	fn cf_forfeit_vtxo<'a>(&'a self) -> Arc<BoundColumnFamily<'a>> {
		self.db.cf_handle(CF_FORFEIT_VTXO).expect("db missing forfeit vtxo cf")
	}

	fn cf_round<'a>(&'a self) -> Arc<BoundColumnFamily<'a>> {
		self.db.cf_handle(CF_ROUND).expect("db missing round cf")
	}

	fn cf_round_expiry<'a>(&'a self) -> Arc<BoundColumnFamily<'a>> {
		self.db.cf_handle(CF_ROUND_EXPIRY).expect("db missing round expiry cf")
	}

	pub fn get_master_seed(&self) -> anyhow::Result<Option<Vec<u8>>> {
		Ok(self.db.get(MASTER_SEED)?)
	}

	pub fn store_master_mnemonic_and_seed(&self, mnemonic: &bip39::Mnemonic) -> anyhow::Result<()> {
		let mut b = WriteBatchWithTransaction::<true>::default();
		b.put(MASTER_MNEMONIC, mnemonic.to_string().as_bytes());
		b.put(MASTER_SEED, mnemonic.to_seed("").to_vec());
		let mut opts = WriteOptions::default();
		opts.set_sync(true);
		self.db.write_opt(b, &opts)?;
		Ok(())
	}

	pub fn store_round(&self, round_tx: Transaction, vtxos: SignedVtxoTree) -> anyhow::Result<()> {
		let round = StoredRound {
			tx: round_tx,
			signed_tree: vtxos,
		};
		let id = round.id();
		let encoded_round = round.encode();
		let expiry_key = RoundExpiryKey::new(round.signed_tree.spec.expiry_height, id);

		let mut opts = WriteOptions::default();
		opts.set_sync(true);
		let mut oopts = OptimisticTransactionOptions::new();
		oopts.set_snapshot(false);

		//TODO(stevenroose) consider writing a macro for this sort of block
		loop {
			let tx = self.db.transaction_opt(&opts, &oopts);
			tx.put_cf(&self.cf_round(), id, &encoded_round)?;
			tx.put_cf(&self.cf_round_expiry(), expiry_key.encode(), [])?;

			match tx.commit() {
				Ok(()) => break,
				Err(e) if e.kind() == rocksdb::ErrorKind::TryAgain => continue,
				Err(e) if e.kind() == rocksdb::ErrorKind::Busy => continue,
				Err(e) => bail!("failed to commit db tx: {}", e),
			}
		}

		let mut opts = FlushOptions::default();
		opts.set_wait(true); //TODO(stevenroose) is this needed?
		self.db.flush_cfs_opt(
			&[&self.cf_round(), &self.cf_forfeit_vtxo(), &self.cf_round_expiry()], &opts,
		).context("error flushing db")?;

		Ok(())
	}

	pub fn remove_round(&self, id: Txid) -> anyhow::Result<()> {
		let round = match self.get_round(id)? {
			Some(r) => r,
			None => return Ok(()),
		};
		let expiry_key = RoundExpiryKey::new(round.signed_tree.spec.expiry_height, id);

		let opts = WriteOptions::default();
		let oopts = OptimisticTransactionOptions::new();

		//TODO(stevenroose) consider writing a macro for this sort of block
		loop {
			let tx = self.db.transaction_opt(&opts, &oopts);
			tx.delete_cf(&self.cf_round(), id)?;
			tx.delete_cf(&self.cf_round_expiry(), expiry_key.encode())?;

			match tx.commit() {
				Ok(()) => break,
				Err(e) if e.kind() == rocksdb::ErrorKind::TryAgain => continue,
				Err(e) if e.kind() == rocksdb::ErrorKind::Busy => continue,
				Err(e) => bail!("failed to commit db tx: {}", e),
			}
		}
		Ok(())
	}

	pub fn get_round(&self, id: Txid) -> anyhow::Result<Option<StoredRound>> {
		Ok(self.db.get_pinned_cf(&self.cf_round(), id)?.map(|b| {
			StoredRound::decode(&b).expect("corrupt db")
		}))
	}

	/// Get all round IDs of rounds that expired before or on [height].
	pub fn get_expired_rounds(&self, height: u32) -> anyhow::Result<Vec<Txid>> {
		let mut ret = Vec::new();

		let mut iter = self.db.raw_iterator_cf(&self.cf_round_expiry());
		iter.seek_to_first();
		while iter.valid() {
			if let Some(key) = iter.key() {
				let expkey = RoundExpiryKey::decode(key);
				if expkey.expiry > height {
					break;
				}
				ret.push(expkey.id);
				iter.next();
			} else {
				break;
			}
		}
		iter.status().context("round expiry iterator error")?;

		Ok(ret)
	}

	pub fn get_fresh_round_ids(&self, start_height: u32) -> anyhow::Result<Vec<Txid>> {
		let mut ret = Vec::new();

		let mut iter = self.db.raw_iterator_cf(&self.cf_round_expiry());
		iter.seek(&start_height.to_le_bytes());
		while iter.valid() {
			if let Some(key) = iter.key() {
				ret.push(RoundExpiryKey::decode(key).id);
				iter.next();
			} else {
				break;
			}
		}
		iter.status().context("round expiry iterator error")?;

		Ok(ret)
	}

	pub fn store_forfeit_vtxo(&self, vtxo: ForfeitVtxo) -> anyhow::Result<()> {
		self.db.put_cf(&self.cf_forfeit_vtxo(), vtxo.id(), vtxo.encode())?;
		Ok(())
	}
}

//TODO(stevenroose) write test to make sure the iterator in get_fresh_round_ids doesn't skip
//any rounds on the same height.
