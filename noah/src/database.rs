
use std::path::Path;

use anyhow::{bail, Context};

use sled::transaction as tx;

use ark::{Vtxo, VtxoId};

use crate::exit;

// Trees

const VTXO_TREE: &str = "noah_vtxos";
const FORFEIT_VTXO_TREE: &str = "noah_forfeited_vtxos";

// Top-level entries

const CLAIM_INPUTS: &str = "claim_inputs";
const LAST_ARK_SYNC_HEIGHT: &str = "last_round_sync_height";


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
	#[allow(unused)] // for future use
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

	pub fn get_vtxo(&self, id: VtxoId) -> anyhow::Result<Option<Vtxo>> {
		Ok(self.db.open_tree(VTXO_TREE)?.get(id)?.map(|b| {
			Vtxo::decode(&b).expect("corrupt db: invalid vtxo")
		}))
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

	pub fn get_last_ark_sync_height(&self) -> anyhow::Result<u32> {
		if let Some(b) = self.db.get(LAST_ARK_SYNC_HEIGHT)? {
			assert_eq!(4, b.len());
			Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
		} else {
			Ok(0)
		}
	}

	pub fn store_last_ark_sync_height(&self, height: u32) -> anyhow::Result<()> {
		self.db.insert(LAST_ARK_SYNC_HEIGHT, height.to_be_bytes().to_vec())?;
		Ok(())
	}

	pub fn store_forfeited_vtxo(&self, id: VtxoId, height: u32) -> anyhow::Result<()> {
		self.db.open_tree(VTXO_TREE)?.insert(id, height.to_be_bytes().to_vec())?;
		Ok(())
	}

	pub fn has_forfeited_vtxo(&self, id: VtxoId) -> anyhow::Result<bool> {
		Ok(self.db.open_tree(VTXO_TREE)?.get(id)?.is_some())
	}
	//TODO(stevenroose) regularly prune forfeit vtxos based on height
}
