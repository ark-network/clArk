
use std::path::Path;

use anyhow::{bail, Context};

use sled::transaction as tx;

use ark::{Vtxo, VtxoId};

use crate::exit;

const VTXO_TREE: &str = "noah_vtxos";
const CLAIM_INPUTS: &str = "claim_inputs";


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

	pub fn get_all_vtxos(&self) -> anyhow::Result<Vec<Vtxo>> {
		self.db.open_tree(VTXO_TREE)?.iter().map(|v| {
			let (_key, val) = v?;
			Ok(Vtxo::decode(&val)?)
		}).collect()
	}

	pub fn remove_vtxo(&self, id: VtxoId) -> anyhow::Result<Option<Vtxo>> {
		Ok(self.db.open_tree(VTXO_TREE)?.remove(&id)?.map(|b| Vtxo::decode(&b)).transpose()?)
	}

	/// This overrides the existing list of exit claim inputs with the new list.
	pub fn store_claim_inputs(&self, inputs: &[exit::ClaimInput]) -> anyhow::Result<()> {
		let mut buf = Vec::new();
		ciborium::into_writer(&inputs, &mut buf).unwrap();
		self.db.insert(CLAIM_INPUTS, buf)?;
		Ok(())
	}

	/// Gets the current list of exit claim inputs.
	pub fn get_claim_inputs(&self) -> anyhow::Result<Vec<exit::ClaimInput>> {
		match self.db.get(CLAIM_INPUTS)? {
			Some(buf) => Ok(ciborium::from_reader(&buf[..]).expect("corrupt db")),
			None => Ok(Vec::new()),
		}
	}
}
