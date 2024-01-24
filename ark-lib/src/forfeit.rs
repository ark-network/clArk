

use bitcoin::{OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use bitcoin::sighash::{self, SighashCache, TapSighash, TapSighashType};

use crate::{util, Vtxo, VtxoSpec};
use crate::connectors::ConnectorChain;


pub const SIGNED_FORFEIT_TX_VSIZE: u64 = 0;

pub fn create_forfeit_tx(vtxo: &Vtxo, connector: OutPoint) -> Transaction {
	// NB we gain the dust from the connector and lose the dust from the fee anchor
	let leftover = vtxo.amount().to_sat() - SIGNED_FORFEIT_TX_VSIZE; // @ 1 sat/vb
	Transaction {
		version: 2,
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![
			TxIn {
				previous_output: vtxo.point(),
				sequence: Sequence::ZERO,
				script_sig: ScriptBuf::new(),
				witness: Witness::new(),
			},
			TxIn {
				previous_output: connector,
				sequence: Sequence::ZERO,
				script_sig: ScriptBuf::new(),
				witness: Witness::new(),
			},
		],
		output: vec![
			TxOut {
				value: leftover,
				script_pubkey: ScriptBuf::new_v1_p2tr(&util::SECP, vtxo.spec().combined_pubkey(), None),
			},
			util::dust_fee_anchor(),
		],
	}
}

pub fn forfeit_sighash(vtxo: &Vtxo, connector: OutPoint) -> (TapSighash, Transaction) {
	let spec = vtxo.spec();
	let exit_spk = util::exit_spk(spec.user_pubkey, spec.asp_pubkey, spec.exit_delta);
	let exit_prevout = TxOut {
		script_pubkey: exit_spk,
		value: spec.amount.to_sat(),
	};
	let connector_prevout = TxOut {
		script_pubkey: ConnectorChain::output_script(spec.asp_pubkey),
		value: util::DUST.to_sat(),
	};
	let tx = create_forfeit_tx(vtxo, connector);
	let sighash = SighashCache::new(&tx).taproot_key_spend_signature_hash(
		0, &sighash::Prevouts::All(&[exit_prevout, connector_prevout]), TapSighashType::All,
	).expect("sighash error");
	(sighash, tx)
}
