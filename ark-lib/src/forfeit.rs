

use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use bitcoin::sighash::{self, SighashCache, TapSighash, TapSighashType};

use crate::{fee, util, Vtxo};
use crate::connectors::ConnectorChain;


//TODO(stevenroose) fix
pub const SIGNED_FORFEIT_TX_VSIZE: u64 = 0;

pub fn create_forfeit_tx(vtxo: &Vtxo, connector: OutPoint) -> Transaction {
	// NB we gain the dust from the connector and lose the dust from the fee anchor
	let leftover = vtxo.amount() - Amount::from_sat(SIGNED_FORFEIT_TX_VSIZE); // @ 1 sat/vb
	//TODO(stevenroose) improve this hack
	let vtxo_fee_anchor_point = {
		let mut point = vtxo.point();
		point.vout = vtxo.vtxo_tx().output.len() as u32 - 1;
		point
	};
	Transaction {
		version: bitcoin::transaction::Version::TWO,
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![
			TxIn {
				previous_output: vtxo.point(),
				sequence: Sequence::MAX,
				script_sig: ScriptBuf::new(),
				witness: Witness::new(),
			},
			TxIn {
				previous_output: connector,
				sequence: Sequence::MAX,
				script_sig: ScriptBuf::new(),
				witness: Witness::new(),
			},
			//TODO(stevenroose) we don't need to spend dust anchors
			TxIn {
				previous_output: vtxo_fee_anchor_point,
				sequence: Sequence::MAX,
				script_sig: ScriptBuf::new(),
				witness: fee::dust_anchor_witness(),
			},
		],
		output: vec![
			TxOut {
				value: leftover,
				script_pubkey: ScriptBuf::new_p2tr(&util::SECP, vtxo.spec().combined_pubkey(), None),
			},
			fee::dust_anchor(),
		],
	}
}

pub fn forfeit_sighash(vtxo: &Vtxo, connector: OutPoint) -> (TapSighash, Transaction) {
	let spec = vtxo.spec();
	let exit_spk = spec.exit_spk();
	let exit_prevout = TxOut {
		script_pubkey: exit_spk,
		value: vtxo.amount(),
	};
	let connector_prevout = TxOut {
		script_pubkey: ConnectorChain::output_script(spec.asp_pubkey),
		value: fee::DUST,
	};
	let tx = create_forfeit_tx(vtxo, connector);
	let sighash = SighashCache::new(&tx).taproot_key_spend_signature_hash(
		0,
		&sighash::Prevouts::All(&[exit_prevout, connector_prevout, fee::dust_anchor()]),
		TapSighashType::Default,
	).expect("sighash error");
	(sighash, tx)
}
