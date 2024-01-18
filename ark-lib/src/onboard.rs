
//! Onboard flow:
//!
//! * User starts by using the [new_user] function that crates the user's parts.
//! * ASP does a deterministic sign and sends ASP part using [new_asp].
//! * User also signs and combines sigs using [finish] and stores vtxo.

use bitcoin::{Amount, OutPoint, Sequence, ScriptBuf, Transaction, TxIn, TxOut, Witness};
use bitcoin::blockdata::locktime::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::sighash::{self, SighashCache, TapSighash};
use serde::{Deserialize, Serialize};

use crate::{musig, util, Vtxo};

#[derive(Debug, Serialize, Deserialize)]
pub struct Spec {
	pub user_key: PublicKey,
	pub asp_key: PublicKey,
	pub expiry_delta: u16,
	pub exit_delta: u16,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
}

pub fn onboard_spk(spec: &Spec) -> ScriptBuf {
	let expiry = util::delayed_sign(spec.expiry_delta, spec.asp_key.x_only_public_key().0);
	let taproot = bitcoin::taproot::TaprootBuilder::new()
		.add_leaf(0, expiry).unwrap()
		.finalize(&util::SECP, musig::combine_keys([spec.user_key, spec.asp_key])).unwrap();
	ScriptBuf::new_v1_p2tr_tweaked(taproot.output_key())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserPart {
	pub spec: Spec,
	pub utxo: OutPoint,
	#[serde(with = "musig::serde::pubnonce")]
	pub nonce: musig::MusigPubNonce,
}

#[derive(Debug)]
pub struct PrivateUserPart {
	pub session_id_bytes: [u8; 32],
	pub sec_nonce: musig::MusigSecNonce,
}

pub fn new_user(spec: Spec, utxo: OutPoint) -> (UserPart, PrivateUserPart) {
	let session_id_bytes = rand::random::<[u8; 32]>();
	let session_id = musig::MusigSessionId::assume_unique_per_nonce_gen(session_id_bytes);
	let agg = musig::key_agg([spec.user_key, spec.asp_key]);

	let (unlock_sighash, unlock_tx) = unlock_tx_sighash(&spec, utxo);
	let (sec_nonce, pub_nonce) = agg.nonce_gen(
		&musig::SECP,
		session_id,
		musig::pubkey_to(spec.user_key),
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

pub fn new_asp(user: &UserPart, seckey: SecretKey) -> AspPart {
	let (unlock_sighash, _unlock_tx) = unlock_tx_sighash(&user.spec, user.utxo);
	let msg = unlock_sighash.to_byte_array();
	let (pub_nonce, sig) = musig::deterministic_partial_sign(seckey, [user.spec.user_key], [user.nonce], msg);
	AspPart {
		nonce: pub_nonce,
		signature: sig,
	}
}

pub fn create_unlock_tx(spec: &Spec, utxo: OutPoint) -> Transaction {
	let exit_timeout = util::delayed_sign(spec.exit_delta, spec.user_key.x_only_public_key().0);
	let unlock_tr = bitcoin::taproot::TaprootBuilder::new()
		.add_leaf(0, exit_timeout).unwrap()
		.finalize(&util::SECP, musig::combine_keys([spec.user_key, spec.asp_key])).unwrap();
	let unlock_spk = ScriptBuf::new_v1_p2tr_tweaked(unlock_tr.output_key());
	Transaction {
		version: 2,
		lock_time: LockTime::ZERO,
		input: vec![TxIn {
			previous_output: utxo,
			script_sig: ScriptBuf::new(),
			sequence: Sequence::ZERO,
			witness: Witness::new(),
		}],
		output: vec![
			TxOut {
				script_pubkey: unlock_spk,
				value: (spec.amount - util::DUST).to_sat(),
			},
			util::dust_fee_anchor(),
		],
	}
}

pub fn unlock_tx_sighash(spec: &Spec, utxo: OutPoint) -> (TapSighash, Transaction) {
	let unlock_tx = create_unlock_tx(spec, utxo);
	let mut cache = SighashCache::new(&unlock_tx);
	let prev = TxOut {
		script_pubkey: onboard_spk(&spec),
		value: spec.amount.to_sat(),
	};
	let sighash = cache.taproot_key_spend_signature_hash(
		0,
		&sighash::Prevouts::One(0, &prev),
		sighash::TapSighashType::All,
	).expect("sighash calc error");
	(sighash, unlock_tx)
}

pub fn finish(
	user: UserPart,
	private: PrivateUserPart,
	asp: AspPart,
	privkey: SecretKey,
) -> Vtxo {
	let (unlock_sighash, _unlock_tx) = unlock_tx_sighash(&user.spec, user.utxo);
	let (_user_sig, final_sig) = musig::partial_sign(
		privkey,
		[user.spec.user_key, user.spec.asp_key],
		private.sec_nonce,
		[user.nonce, asp.nonce],
		unlock_sighash.to_byte_array(),
		Some(&[asp.signature]),
	);
	assert!(final_sig.is_some());

	Vtxo::Onboard {
		utxo: user.utxo,
		spec: user.spec,
		exit_tx_signature: final_sig.unwrap(),
	}
}
