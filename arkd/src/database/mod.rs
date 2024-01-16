
use std::path::Path;

use anyhow::{bail, Context};
use sled::transaction as tx;

const MASTER_SEED: &str = "master_seed";
const MASTER_MNEMONIC: &str = "master_mnemonic";

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
}
