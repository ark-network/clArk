

pub mod musig;
pub mod onboard;
mod util;


use std::io::{self, Write};

use bitcoin::{Amount, OutPoint, Script, ScriptBuf, TxOut};
use bitcoin::hashes::Hash;
use bitcoin::opcodes;
use bitcoin::secp256k1::{self, schnorr, PublicKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};


lazy_static::lazy_static! {
	/// Global secp context.
	static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}


#[derive(Debug, Deserialize, Serialize)]
pub enum Vtxo {
	Onboard {
		utxo: OutPoint,
		spec: onboard::Spec,
		exit_tx_signature: schnorr::Signature,
	}
}

impl Vtxo {
	pub fn utxo(&self) -> OutPoint {
		match self {
			Vtxo::Onboard { utxo, .. } => *utxo,
		}
	}

	/// This is the same as [utxo] but encoded as a byte array.
	pub fn id(&self) -> [u8; 36] {
		let utxo = self.utxo();
		let mut ret = [0u8; 36];
		ret[0..32].copy_from_slice(&utxo.txid[..]);
		ret[32..].copy_from_slice(&utxo.vout.to_le_bytes());
		ret
	}

	pub fn encode(&self) -> Vec<u8> {
		let mut buf = Vec::new();
		ciborium::into_writer(self, &mut buf).unwrap();
		buf
	}
}
