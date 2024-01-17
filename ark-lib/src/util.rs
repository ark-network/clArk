
use bitcoin::{Amount, Script, ScriptBuf, TxOut};
use bitcoin::opcodes;
use bitcoin::secp256k1::XOnlyPublicKey;

/// Taproot-compatible dust value of 330 satoshis.
pub const DUST: Amount = Amount::from_sat(330);

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

/// Create an OP_TRUE fee anchor with the dust amount.
pub fn dust_fee_anchor() -> TxOut {
	TxOut {
		script_pubkey: Script::builder().push_opcode(opcodes::OP_TRUE).into_script(),
		value: DUST.to_sat(),
	}
}
