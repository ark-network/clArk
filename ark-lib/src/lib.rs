

pub mod connectors;
pub mod forfeit;
pub mod musig;
pub mod onboard;
pub mod tree;
mod util;


use std::{fmt, io};

use bitcoin::{Amount, OutPoint, Txid};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{self, schnorr, PublicKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};


#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct Destination {
	pub pubkey: PublicKey,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VtxoId([u8; 36]);

impl VtxoId {
	pub fn new(utxo: OutPoint) -> VtxoId {
		let mut ret = [0u8; 36];
		ret[0..32].copy_from_slice(&utxo.txid[..]);
		ret[32..].copy_from_slice(&utxo.vout.to_le_bytes());
		VtxoId(ret)
	}

	pub fn from_slice(b: &[u8]) -> Result<VtxoId, &'static str> {
		if b.len() == 36 {
			let mut ret = [0u8; 36];
			ret[..].copy_from_slice(&b[0..36]);
			Ok(Self(ret))
		} else {
			Err("invalid vtxo id length")
		}
	}

	pub fn utxo(self) -> OutPoint {
		let vout = [self.0[32], self.0[33], self.0[34], self.0[35]];
		OutPoint::new(Txid::from_slice(&self.0[0..32]).unwrap(), u32::from_le_bytes(vout))
	}

	pub fn bytes(self) -> [u8; 36] {
		self.0
	}
}

impl AsRef<[u8]> for VtxoId {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

impl fmt::Display for VtxoId {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		fmt::Display::fmt(&self.utxo(), f)
	}
}

impl fmt::Debug for VtxoId {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		fmt::Display::fmt(self, f)
	}
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
	/// This is the same as [utxo] but encoded as a byte array.
	pub fn id(&self) -> VtxoId {
		VtxoId::new(self.utxo())
	}

	pub fn utxo(&self) -> OutPoint {
		match self {
			Vtxo::Onboard { utxo, .. } => *utxo,
		}
	}

	pub fn amount(&self) -> Amount {
		match self {
			Vtxo::Onboard { spec, .. } => spec.amount,
		}
	}

	pub fn is_onboard(&self) -> bool {
		match self {
			Vtxo::Onboard { .. } => true,
		}
	}

	pub fn user_pubkey(&self) -> PublicKey {
		match self {
			Vtxo::Onboard { spec, .. } => spec.user_key,
		}
	}

	pub fn asp_pubkey(&self) -> PublicKey {
		match self {
			Vtxo::Onboard { spec, .. } => spec.asp_pubkey,
		}
	}

	pub fn exit_delta(&self) -> u16 {
		match self {
			Vtxo::Onboard { spec, .. } => spec.exit_delta,
		}
	}

	pub fn combined_pubkey(&self) -> XOnlyPublicKey {
		match self {
			Vtxo::Onboard { spec, .. } => spec.combined_pubkey(),
		}
	}

	pub fn encode(&self) -> Vec<u8> {
		let mut buf = Vec::new();
		ciborium::into_writer(self, &mut buf).unwrap();
		buf
	}

	pub fn decode(bytes: &[u8]) -> Result<Self, ciborium::de::Error<io::Error>> {
		ciborium::from_reader(bytes)
	}
}
