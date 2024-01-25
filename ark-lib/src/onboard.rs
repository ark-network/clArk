
//! Onboard flow:
//!
//! * User starts by using the [new_user] function that crates the user's parts.
//! * ASP does a deterministic sign and sends ASP part using [new_asp].
//! * User also signs and combines sigs using [finish] and stores vtxo.

use bitcoin::{taproot, Amount, OutPoint, Sequence, ScriptBuf, Transaction, TxIn, TxOut, Witness};
use bitcoin::blockdata::locktime::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{schnorr, KeyPair};
use bitcoin::sighash::{self, SighashCache, TapSighash};

use crate::{musig, util, Vtxo, VtxoSpec};


/// The total signed tx vsize of an unlock tx.
const UNLOCK_TX_VSIZE: usize = 154;

fn onboard_taproot(spec: &VtxoSpec) -> taproot::TaprootSpendInfo {
	let expiry = util::timelock_sign(spec.expiry_height, spec.asp_pubkey.x_only_public_key().0);
	bitcoin::taproot::TaprootBuilder::new()
		.add_leaf(0, expiry).unwrap()
		.finalize(&util::SECP, spec.combined_pubkey()).unwrap()
}

pub fn onboard_taptweak(spec: &VtxoSpec) -> taproot::TapTweakHash {
	onboard_taproot(spec).tap_tweak()
}

pub fn onboard_spk(spec: &VtxoSpec) -> ScriptBuf {
	ScriptBuf::new_v1_p2tr_tweaked(onboard_taproot(spec).output_key())
}

/// The additional amount that needs to be sent into the onboard tx.
pub fn onboard_fee() -> Amount {
	util::DUST + Amount::from_sat(UNLOCK_TX_VSIZE as u64) // 1 sat/vb
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserPart {
	pub spec: VtxoSpec,
	pub utxo: OutPoint,
	#[serde(with = "musig::serde::pubnonce")]
	pub nonce: musig::MusigPubNonce,
}

#[derive(Debug)]
pub struct PrivateUserPart {
	pub session_id_bytes: [u8; 32],
	pub sec_nonce: musig::MusigSecNonce,
}

pub fn new_user(spec: VtxoSpec, utxo: OutPoint) -> (UserPart, PrivateUserPart) {
	let session_id_bytes = rand::random::<[u8; 32]>();
	let session_id = musig::MusigSessionId::assume_unique_per_nonce_gen(session_id_bytes);
	let agg = musig::key_agg([spec.user_pubkey, spec.asp_pubkey]);

	let (unlock_sighash, _tx) = unlock_tx_sighash(&spec, utxo);
	let (sec_nonce, pub_nonce) = agg.nonce_gen(
		&musig::SECP,
		session_id,
		musig::pubkey_to(spec.user_pubkey),
		musig::zkp::Message::from_digest(unlock_sighash.to_byte_array()),
		Some(rand::random()),
	).expect("nonce gen");

	let user_part = UserPart {
		spec, utxo, nonce: pub_nonce,
	};
	let private_user_part = PrivateUserPart {
		session_id_bytes, sec_nonce,
	};
	(user_part, private_user_part)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AspPart {
	#[serde(with = "musig::serde::pubnonce")]
	pub nonce: musig::MusigPubNonce,
	#[serde(with = "musig::serde::partialsig")]
	pub signature: musig::MusigPartialSignature,
}

pub fn new_asp(user: &UserPart, key: &KeyPair) -> AspPart {
	let (unlock_sighash, _unlock_tx) = unlock_tx_sighash(&user.spec, user.utxo);
	let msg = unlock_sighash.to_byte_array();
	let tweak = onboard_taptweak(&user.spec);
	let (pub_nonce, sig) = musig::deterministic_partial_sign(
		key, [user.spec.user_pubkey], [user.nonce], msg, Some(tweak.to_byte_array()),
	);
	AspPart {
		nonce: pub_nonce,
		signature: sig,
	}
}

pub fn create_unlock_tx(
	spec: &VtxoSpec,
	utxo: OutPoint,
	signature: Option<&schnorr::Signature>,
) -> Transaction {
	Transaction {
		version: 2,
		lock_time: LockTime::ZERO,
		input: vec![TxIn {
			previous_output: utxo,
			script_sig: ScriptBuf::new(),
			sequence: Sequence::ZERO,
			witness: {
				let mut ret = Witness::new();
				if let Some(sig) = signature {
					ret.push(&sig[..]);
				}
				ret
			},
		}],
		output: vec![
			TxOut {
				script_pubkey: spec.exit_spk(),
				value: spec.amount.to_sat(),
			},
			util::dust_fee_anchor(),
		],
	}
}

pub fn unlock_tx_sighash(spec: &VtxoSpec, utxo: OutPoint) -> (TapSighash, Transaction) {
	let unlock_tx = create_unlock_tx(spec, utxo, None);
	let mut cache = SighashCache::new(&unlock_tx);
	let prev = TxOut {
		script_pubkey: onboard_spk(&spec),
		value: spec.amount.to_sat(),
	};
	let sighash = cache.taproot_key_spend_signature_hash(
		0,
		&sighash::Prevouts::All(&[&prev]),
		sighash::TapSighashType::All,
	).expect("sighash calc error");
	(sighash, unlock_tx)
}

pub fn finish(
	user: UserPart,
	private: PrivateUserPart,
	asp: AspPart,
	key: &KeyPair,
) -> Vtxo {
	let (unlock_sighash, _unlock_tx) = unlock_tx_sighash(&user.spec, user.utxo);
	let agg_nonce = musig::nonce_agg([user.nonce, asp.nonce]);
	let (_user_sig, final_sig) = musig::partial_sign(
		[user.spec.user_pubkey, user.spec.asp_pubkey],
		agg_nonce,
		key,
		private.sec_nonce,
		unlock_sighash.to_byte_array(),
		Some(user.spec.exit_taptweak().to_byte_array()),
		Some(&[asp.signature]),
	);
	assert!(final_sig.is_some());

	Vtxo::Onboard {
		utxo: user.utxo,
		spec: user.spec,
		unlock_tx_signature: final_sig.unwrap(),
	}
}

/// Returns [None] when [Vtxo] is not an onboard vtxo.
pub fn signed_unlock_tx(vtxo: &Vtxo) -> Option<Transaction> {
	if let Vtxo::Onboard { ref spec, utxo, unlock_tx_signature } = vtxo {
		let ret = create_unlock_tx(spec, *utxo, Some(unlock_tx_signature));
		assert_eq!(ret.vsize(), UNLOCK_TX_VSIZE);
		Some(ret)
	} else {
		None
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn test_flow_assertions() {
		let key = KeyPair::new(&util::SECP, &mut rand::thread_rng());
		let utxo = "0000000000000000000000000000000000000000000000000000000000000001:1".parse().unwrap();
		let spec = VtxoSpec {
			user_pubkey: key.public_key(),
			asp_pubkey: key.public_key(),
			expiry_height: 2,
			exit_delta: 1,
			amount: Amount::from_btc(1.0).unwrap(),
		};
		let (user, upriv) = new_user(spec, utxo);
		let asp = new_asp(&user, &key);
		let vtxo = finish(user, upriv, asp, &key);
		let _unlock_tx = signed_unlock_tx(&vtxo).unwrap();
	}
}
