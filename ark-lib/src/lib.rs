
#[macro_use] extern crate serde;

pub mod connectors;
pub mod fee;
pub mod forfeit;
pub mod musig;
pub mod onboard;
pub mod tree;
pub mod util;
#[cfg(test)]
mod napkin;


use std::{fmt, io};

use bitcoin::{taproot, Amount, FeeRate, OutPoint, Script, ScriptBuf, Transaction, Txid, TxOut, Weight};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{schnorr, PublicKey, XOnlyPublicKey};

pub const P2TR_DUST_VB: u64 = 110;
/// 330 satoshis
pub const P2TR_DUST_SAT: u64 = P2TR_DUST_VB * 3;
pub const P2TR_DUST: Amount = Amount::from_sat(P2TR_DUST_SAT);

pub const P2WPKH_DUST_VB: u64 = 90;
/// 294 satoshis
pub const P2WPKH_DUST_SAT: u64 = P2WPKH_DUST_VB * 3;
pub const P2WPKH_DUST: Amount = Amount::from_sat(P2WPKH_DUST_SAT);

pub const P2PKH_DUST_VB: u64 = 182;
/// 546 satoshis
pub const P2PKH_DUST_SAT: u64 = P2PKH_DUST_VB * 3;
pub const P2PKH_DUST: Amount = Amount::from_sat(P2PKH_DUST_SAT);

pub const P2SH_DUST_VB: u64 = 180;
/// 540 satoshis
pub const P2SH_DUST_SAT: u64 = P2PKH_DUST_VB * 3;
pub const P2SH_DUST: Amount = Amount::from_sat(P2SH_DUST_SAT);

pub const P2WSH_DUST_VB: u64 = 110;
/// 330 satoshis
pub const P2WSH_DUST_SAT: u64 = P2TR_DUST_VB * 3;
pub const P2WSH_DUST: Amount = Amount::from_sat(P2WSH_DUST_SAT);


#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct VtxoRequest {
	pub pubkey: PublicKey,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct OffboardRequest {
	pub script_pubkey: ScriptBuf,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
}

impl OffboardRequest {
	pub fn calculate_fee(script: &Script, fee_rate: FeeRate) -> Option<Amount> {
		// NB We calculate the required extra fee as the "dust" fee for the given feerate.
		// We take Bitcoin's dust amounts, which are calculated at 3 sat/vb, but then
		// calculated for the given feerate. For more on dust, see:
		// https://bitcoin.stackexchange.com/questions/10986/what-is-meant-by-bitcoin-dust

		let vb = if script.is_p2pkh() {
			P2PKH_DUST_VB
		} else if script.is_p2sh() {
			P2SH_DUST_VB
		} else if script.is_v0_p2wpkh() {
			P2WPKH_DUST_VB
		} else if script.is_v0_p2wsh() {
			P2WSH_DUST_VB
		} else if script.is_v1_p2tr() {
			P2TR_DUST_VB
		} else if script.is_op_return() {
			bitcoin::consensus::encode::VarInt(script.len() as u64).len() as u64
				+ script.len() as u64
				+ 8
				// the input data (scriptSig and witness length fields included)
				+ 36 + 4 + 1 + 1
		} else {
			return None;
		};
		Some(fee_rate * Weight::from_vb(vb).expect("no overflow"))
	}

	/// Validate that the offboard has a valid script.
	pub fn validate(&self) -> Result<(), &'static str> {
		if Self::calculate_fee(&self.script_pubkey, FeeRate::ZERO).is_none() {
			Err("invalid script")
		} else {
			Ok(())
		}
	}

	/// Convert into a tx output.
	pub fn to_txout(&self) -> TxOut {
		TxOut {
			script_pubkey: self.script_pubkey.clone(),
			value: self.amount.to_sat(),
		}
	}

	/// Returns the fee charged for the user to make this offboard given the fee rate.
	///
	/// Always returns [Some] if [OffboardRequest::validate] returns [Ok].
	pub fn fee(&self, fee_rate: FeeRate) -> Option<Amount> {
		Self::calculate_fee(&self.script_pubkey, fee_rate)
	}
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VtxoId([u8; 36]);

impl VtxoId {
	/// Size in bytes of an encoded [VtxoId].
	pub const ENCODE_SIZE: usize = 36;

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

impl serde::Serialize for VtxoId {
	fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
		s.serialize_bytes(self.as_ref())
	}
}

impl<'de> serde::Deserialize<'de> for VtxoId {
	fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
		struct Visitor;
		impl<'de> serde::de::Visitor<'de> for Visitor {
			type Value = VtxoId;
			fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				write!(f, "a VtxoId")
			}
			fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
				VtxoId::from_slice(v).map_err(serde::de::Error::custom)
			}
		}
		d.deserialize_bytes(Visitor)
	}
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VtxoSpec {
	pub user_pubkey: PublicKey,
	pub asp_pubkey: PublicKey,
	pub expiry_height: u32,
	pub exit_delta: u16,
	/// The amount of the vtxo itself, this is either the reveal tx our the
	/// vtxo tree output. It does not include budget for fees, so f.e. to
	/// calculate the onboard amount needed for this vtxo, fee budget should
	/// be added.
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
}

impl VtxoSpec {
	/// Get the musig-combined user + asp pubkey.
	pub fn combined_pubkey(&self) -> XOnlyPublicKey {
		musig::combine_keys([self.user_pubkey, self.asp_pubkey])
	}

	pub fn exit_clause(&self) -> ScriptBuf {
		util::delayed_sign(self.exit_delta, self.user_pubkey.x_only_public_key().0)
	}

	pub fn exit_taproot(&self) -> taproot::TaprootSpendInfo {
		bitcoin::taproot::TaprootBuilder::new()
			.add_leaf(0, self.exit_clause()).unwrap()
			.finalize(&util::SECP, self.combined_pubkey()).unwrap()
	}

	pub fn exit_taptweak(&self) -> taproot::TapTweakHash {
		self.exit_taproot().tap_tweak()
	}

	pub fn exit_spk(&self) -> ScriptBuf {
		ScriptBuf::new_v1_p2tr_tweaked(self.exit_taproot().output_key())
	}
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum Vtxo {
	Onboard {
		spec: VtxoSpec,
		/// The on-chain utxo of the onboard tx.
		utxo: OutPoint,
		reveal_tx_signature: schnorr::Signature,
	},
	Round {
		spec: VtxoSpec,
		/// The on-chain utxo of the vtxo tree.
		utxo: OutPoint,
		leaf_idx: usize,
		//TODO(stevenroose) reduce this to just storing the signatures
		// and calculate branch on exit
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
