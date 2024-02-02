
use std::io;
use std::path::Path;

use anyhow::{bail, Context};
use bitcoin::{Amount, OutPoint, Transaction, Txid};
use bitcoin::secp256k1::schnorr;
use sled::transaction as tx;

use ark::{VtxoId, VtxoSpec};
use ark::tree::signed::SignedVtxoTree;


// TREE KEYS

const FORFEIT_VTXO_TREE: &str = "forfeited_vtxos";
const ROUND_TREE: &str = "rounds";


// ENTRY KEYS

const MASTER_SEED: &str = "master_seed";
const MASTER_MNEMONIC: &str = "master_mnemonic";
const FRESH_ROUND_IDS: &str = "fresh_round_ids";


pub struct Db {
	db: sled::Db,
}

/// A vtxo that has been forfeited and is now ours.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum ForfeitVtxo {
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


impl Db {
	pub fn open(path: &Path) -> anyhow::Result<Db> {
		Ok(Db {
			db: sled::open(path).context("failed to open db")?,
		})
	}
	
	/// Utility function for transactions that fixes the annoying generics.
	fn transaction(&self,
		f: impl Fn(&tx::TransactionalTree) -> tx::ConflictableTransactionResult<(), ()>,
	) -> anyhow::Result<()> {
		if let Err(e) = self.db.transaction(f) {
			bail!("db error in transaction: {:?}", e)
		} else {
			Ok(())
		}
	}

	pub fn get_master_seed(&self) -> anyhow::Result<Option<Vec<u8>>> {
		Ok(self.db.get(MASTER_SEED)?.map(|iv| iv.to_vec()))
	}

	pub fn store_master_mnemonic_and_seed(&self, mnemonic: &bip39::Mnemonic) -> anyhow::Result<()> {
		Ok(self.transaction(|tx| {
			tx.insert(MASTER_MNEMONIC, mnemonic.to_string().as_bytes())?;
			tx.insert(MASTER_SEED, mnemonic.to_seed("").to_vec())?;
			Ok(())
		})?)
	}

	pub fn store_round(&self, round_tx: Transaction, vtxos: SignedVtxoTree) -> anyhow::Result<()> {
		let round = StoredRound {
			tx: round_tx,
			signed_tree: vtxos,
		};
		if self.db.open_tree(ROUND_TREE)?.insert(round.id(), round.encode())?.is_some() {
			warn!("Round with id {} already present!", round.id());
		}

		let mut fresh = self.get_fresh_round_ids()?;
		fresh.push(round.id());
		let mut buf = Vec::new();
		ciborium::into_writer(&fresh, &mut buf).unwrap();
		self.db.insert(FRESH_ROUND_IDS, buf)?;

		Ok(())
	}

	pub fn get_round(&self, id: Txid) -> anyhow::Result<Option<StoredRound>> {
		Ok(self.db.open_tree(ROUND_TREE)?.get(id)?.map(|b| {
			StoredRound::decode(&b).expect("corrupt db")
		}))
	}

	pub fn get_fresh_round_ids(&self) -> anyhow::Result<Vec<Txid>> {
		Ok(self.db.get(FRESH_ROUND_IDS)?.map(|b| {
			ciborium::from_reader(&b[..]).expect("corrupt db")
		}).unwrap_or_default())
	}

	pub fn store_forfeit_vtxo(&self, vtxo: ForfeitVtxo) -> anyhow::Result<()> {
		if self.db.open_tree(FORFEIT_VTXO_TREE)?.insert(vtxo.id(), vtxo.encode())?.is_some() {
			warn!("Forfeit vtxo with id {} already present!", vtxo.id());
		}
		Ok(())
	}
}
