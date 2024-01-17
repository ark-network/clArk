
use std::path::Path;

use anyhow::{bail, Context};
use bitcoin::consensus::encode;
use sled::transaction as tx;

use ark::Vtxo;

const VTXO_TREE: &str = "noah_vtxos";


pub struct Db {
	db: sled::Db,
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

	pub fn store_vtxo(&self, vtxo: Vtxo) -> anyhow::Result<()> {
		self.db.open_tree(VTXO_TREE)?.insert(vtxo.id(), vtxo.encode())?;
		Ok(())
	}
}
