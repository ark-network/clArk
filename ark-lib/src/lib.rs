
#[macro_use] extern crate serde;

pub mod connectors;
pub mod forfeit;
pub mod musig;
pub mod onboard;
pub mod tree;
mod util;


use std::{fmt, io};

use bitcoin::{Amount, OutPoint, Transaction, Txid};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{schnorr, PublicKey, XOnlyPublicKey};


#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct Destination {
	pub pubkey: PublicKey,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VtxoId([u8; 36]);

impl VtxoId {
	pub fn from_slice(b: &[u8]) -> Result<VtxoId, &'static str> {
		if b.len() == 36 {
			let mut ret = [0u8; 36];
			ret[..].copy_from_slice(&b[0..36]);
			Ok(Self(ret))
		} else {
			Err("invalid vtxo id length; must be 36 bytes")
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

impl From<OutPoint> for VtxoId {
	fn from(p: OutPoint) -> VtxoId {
		let mut ret = [0u8; 36];
		ret[0..32].copy_from_slice(&p.txid[..]);
		ret[32..].copy_from_slice(&p.vout.to_le_bytes());
		VtxoId(ret)
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VtxoSpec {
	pub user_pubkey: PublicKey,
	pub asp_pubkey: PublicKey,
	pub expiry_height: u32,
	pub exit_delta: u16,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
}

impl VtxoSpec {
	/// Get the musig-combined user + asp pubkey.
	pub fn combined_pubkey(&self) -> XOnlyPublicKey {
		musig::combine_keys([self.user_pubkey, self.asp_pubkey])
	}
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum Vtxo {
	Onboard {
		spec: VtxoSpec,
		/// The on-chain utxo of the onboard tx.
		utxo: OutPoint,
		exit_tx_signature: schnorr::Signature,
	},
	Round {
		spec: VtxoSpec,
		/// The on-chain utxo of the vtxo tree.
		utxo: OutPoint,
		leaf_idx: usize,
		exit_branch: Vec<Transaction>,
	},
}

impl Vtxo {
	/// This is the same as [utxo] but encoded as a byte array.
	pub fn id(&self) -> VtxoId {
		self.point().into()
	}

	/// The outpoint from which to build forfeit or OOR txs.
	///
	/// This can be an on-chain utxo or an off-chain vtxo.
	pub fn point(&self) -> OutPoint {
		match self {
			Vtxo::Onboard { utxo, .. } => *utxo,
			Vtxo::Round { exit_branch, .. } => {
				OutPoint::new(exit_branch.last().unwrap().txid(), 0).into()
			},
		}
	}

	pub fn spec(&self) -> &VtxoSpec {
		match self {
			Vtxo::Onboard { spec, .. } => spec,
			Vtxo::Round { spec, .. } => spec,
		}
	}

	pub fn amount(&self) -> Amount {
		self.spec().amount
	}

	pub fn is_onboard(&self) -> bool {
		match self {
			Vtxo::Onboard { .. } => true,
			_ => false,
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
