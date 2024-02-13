
use std::collections::HashSet;
use std::path::Path;

use anyhow::{bail, Context};
use bitcoin::Amount;
use sled::transaction as tx;

use ark::{Vtxo, VtxoId};

use crate::exit;

// Trees

const VTXO_TREE: &str = "noah_vtxos";
const VTXO_EXPIRY_TREE: &str = "noah_vtxo_by_expiry";
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
		//TODO(stevenroose) should be a transaction but can't do cross-tree txs
		let expiry = vtxo.spec().expiry_height;
		self.db.open_tree(VTXO_TREE)?.insert(vtxo.id(), vtxo.encode())?;
		self.db.open_tree(VTXO_EXPIRY_TREE)?.fetch_and_update(expiry.to_le_bytes(), |vsb| {
			let mut vs = vsb.map(|b| {
				ciborium::from_reader::<HashSet<VtxoId>, _>(&b[..])
					.expect("corrupt db: invalid vtxo list")
			}).unwrap_or_default();
			vs.insert(vtxo.id());
			let mut buf = Vec::with_capacity(4 + vs.len() * VtxoId::ENCODE_SIZE);
			ciborium::into_writer(&vs, &mut buf).unwrap();
			Some(buf)
		})?;
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
			Ok(Vtxo::decode(&val).expect("corrupt db: invalid vtxo"))
		}).collect()
	}

	/// Get the soonest-expiring vtxos with total value at least [min_value].
	pub fn get_expiring_vtxos(&self, min_value: Amount) -> anyhow::Result<Vec<Vtxo>> {
		let mut ret = Vec::new();
		let mut total_amount = Amount::ZERO;
		for res in self.db.open_tree(VTXO_EXPIRY_TREE)?.iter().values() {
			let vsb = res?;
			let vs = ciborium::from_reader::<HashSet<VtxoId>, _>(&vsb[..])
				.expect("corrupt db: invalid vtxo list");
			for id in vs {
				let vtxo = self.get_vtxo(id)?.expect("corrupt db: missing vtxo from expiry");
				total_amount += vtxo.spec().amount;
				ret.push(vtxo);
				if total_amount >= min_value {
					return Ok(ret);
				}
			}
		}
		bail!("Not enough money, total balance: {}", total_amount);
	}

	pub fn remove_vtxo(&self, id: VtxoId) -> anyhow::Result<Option<Vtxo>> {
		//TODO(stevenroose) should be a transaction but can't do cross-tree txs
		if let Some(v) = self.db.open_tree(VTXO_TREE)?.remove(&id)? {
			let ret = Vtxo::decode(&v).expect("corrupt db: invalid vtxo");
			let expiry = ret.spec().expiry_height;
			self.db.open_tree(VTXO_EXPIRY_TREE)?.fetch_and_update(expiry.to_le_bytes(), |vsb| {
				let vsb = vsb.expect("corrupt db: expiry entry missing");
				let mut vs = ciborium::from_reader::<HashSet<VtxoId>, _>(&vsb[..])
					.expect("corrupt db: invalid vtxo list");
				vs.remove(&id);
				if !vs.is_empty() {
					let mut buf = Vec::with_capacity(4 + vs.len() * VtxoId::ENCODE_SIZE);
					ciborium::into_writer(&vs, &mut buf).unwrap();
					Some(buf)
				} else {
					None
				}
			})?;
			Ok(Some(ret))
		} else {
			Ok(None)
		}
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
			Some(buf) => Ok(ciborium::from_reader(&buf[..])
				.expect("corrupt db: claim inputs")),
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
		self.db.insert(LAST_ARK_SYNC_HEIGHT, height.to_le_bytes().to_vec())?;
		Ok(())
	}

	pub fn store_forfeited_vtxo(&self, id: VtxoId, height: u32) -> anyhow::Result<()> {
		self.db.open_tree(FORFEIT_VTXO_TREE)?.insert(id, height.to_le_bytes().to_vec())?;
		Ok(())
	}

	pub fn has_forfeited_vtxo(&self, id: VtxoId) -> anyhow::Result<bool> {
		Ok(self.db.open_tree(FORFEIT_VTXO_TREE)?.get(id)?.is_some())
	}
	//TODO(stevenroose) regularly prune forfeit vtxos based on height
}
