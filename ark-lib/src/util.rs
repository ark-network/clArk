
use bitcoin::{Amount, Script, ScriptBuf, TxOut};
use bitcoin::{opcodes, taproot};
use bitcoin::secp256k1::{self, PublicKey, XOnlyPublicKey};

use crate::musig;

/// Dust value of 330 satoshis.
///
/// This is the dust value for p2tr and p2wsh outputs.
pub const DUST: Amount = Amount::from_sat(330);

/// The size in bytes of a dust fee anchor created with [dust_fee_anchor].
pub const DUST_FEE_ANCHOR_SIZE: usize = 43;

lazy_static::lazy_static! {
	/// Global secp context.
	pub static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

/// Create a tapscript that is a checksig and a relative timelock.
pub fn delayed_sign(delay_blocks: u16, pubkey: XOnlyPublicKey) -> ScriptBuf {
	let csv = bitcoin::blockdata::transaction::Sequence::from_height(delay_blocks);
	bitcoin::Script::builder()
		.push_int(csv.to_consensus_u32().try_into().unwrap())
		.push_opcode(opcodes::all::OP_CSV)
		.push_opcode(opcodes::all::OP_DROP)
		.push_slice(pubkey.serialize())
		.push_opcode(opcodes::all::OP_CHECKSIG)
		.into_script()
}

/// Create a tapscript that is a checksig and an absolute.
pub fn timelock_sign(timelock_height: u32, pubkey: XOnlyPublicKey) -> ScriptBuf {
	let lt = bitcoin::absolute::LockTime::from_height(timelock_height).unwrap();
	bitcoin::Script::builder()
		.push_int(lt.to_consensus_u32().try_into().unwrap())
		.push_opcode(opcodes::all::OP_CSV)
		.push_opcode(opcodes::all::OP_DROP)
		.push_slice(pubkey.serialize())
		.push_opcode(opcodes::all::OP_CHECKSIG)
		.into_script()
}

/// Create a p2wsh OP_TRUE fee anchor with the dust amount.
pub fn dust_fee_anchor() -> TxOut {
	TxOut {
		script_pubkey: {
			let s = Script::builder().push_opcode(opcodes::OP_TRUE).into_script();
			ScriptBuf::new_v0_p2wsh(&s.wscript_hash())
		},
		value: DUST.to_sat(),
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn test_dust_fee_anchor_size() {
		let a = dust_fee_anchor();
		assert_eq!(DUST_FEE_ANCHOR_SIZE, bitcoin::consensus::serialize(&a).len());
	}
}
