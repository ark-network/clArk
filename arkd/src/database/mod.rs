
use std::io;
use std::path::Path;

use anyhow::{bail, Context};
use bitcoin::{Amount, OutPoint};
use bitcoin::secp256k1::schnorr;
use serde::{Deserialize, Serialize};
use sled::transaction as tx;

use ark::{Vtxo, VtxoId};


// TREE KEYS

const VTXO_TREE: &str = "noah_vtxos";


// ENTRY KEYS

const MASTER_SEED: &str = "master_seed";
const MASTER_MNEMONIC: &str = "master_mnemonic";


pub struct Db {
	db: sled::Db,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum StoredVtxo {
	Onboard {
		#[serde(skip)]
		utxo: OutPoint,
		spec: ark::onboard::Spec,
		exit_tx_signature: schnorr::Signature,
	}
}

impl StoredVtxo {
	pub fn id(&self) -> VtxoId {
		match self {
			StoredVtxo::Onboard { utxo, .. } => VtxoId::new(*utxo),
		}
	}

	pub fn amount(&self) -> Amount {
		match self {
			StoredVtxo::Onboard { spec, .. } => spec.amount,
		}
	}

	fn encode(&self) -> Vec<u8> {
		let mut buf = Vec::new();
		ciborium::into_writer(self, &mut buf).unwrap();
		buf
	}

	fn decode(id: VtxoId, bytes: &[u8]) -> Result<Self, ciborium::de::Error<io::Error>> {
		let mut ret = ciborium::from_reader(bytes)?;
		match ret {
			StoredVtxo::Onboard { ref mut utxo, .. } => *utxo = id.utxo(),
		}
		Ok(ret)
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

	pub fn get_vtxo(&self, id: VtxoId) -> anyhow::Result<Option<StoredVtxo>> {
		Ok(if let Some(bytes) = self.db.open_tree(VTXO_TREE)?.get(id)? {
			Some(StoredVtxo::decode(id, &bytes).context("db corruption")?)
		} else {
			None
		})
	}

	pub fn register_onboard_vtxo(&self, vtxo: Vtxo) -> anyhow::Result<()> {
		let id = vtxo.id();
		let utxo = vtxo.utxo();
		let stored = match vtxo {
			Vtxo::Onboard { spec, exit_tx_signature, .. } => StoredVtxo::Onboard {
				utxo: utxo, spec, exit_tx_signature,
			},
			_ => bail!("vtxo was not an onboard vtxo"),
		};
		self.db.open_tree(VTXO_TREE)?.insert(id, stored.encode())?;
		Ok(())
	}
}
