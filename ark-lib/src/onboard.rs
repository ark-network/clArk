
//! Onboard flow:
//!
//! * User starts by using the [new_user] function that crates the user's parts.
//! * ASP does a deterministic sign and sends ASP part using [new_asp].
//! * User also signs and combines sigs using [finish] and stores vtxo.

use bitcoin::{Amount, OutPoint, Sequence, ScriptBuf, Transaction, TxIn, TxOut, Witness};
use bitcoin::blockdata::locktime::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{KeyPair, PublicKey, SecretKey, XOnlyPublicKey};
use bitcoin::sighash::{self, SighashCache, TapSighash};

use crate::{musig, util, Vtxo, VtxoSpec};

pub fn onboard_spk(spec: &VtxoSpec) -> ScriptBuf {
	let expiry = util::timelock_sign(spec.expiry_height, spec.asp_pubkey.x_only_public_key().0);
	let taproot = bitcoin::taproot::TaprootBuilder::new()
		.add_leaf(0, expiry).unwrap()
		.finalize(&util::SECP, spec.combined_pubkey()).unwrap();
	ScriptBuf::new_v1_p2tr_tweaked(taproot.output_key())
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

	let (unlock_sighash, unlock_tx) = unlock_tx_sighash(&spec, utxo);
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
	let (pub_nonce, sig) = musig::deterministic_partial_sign(key, [user.spec.user_pubkey], [user.nonce], msg);
	AspPart {
		nonce: pub_nonce,
		signature: sig,
	}
}

pub fn create_unlock_tx(spec: &VtxoSpec, utxo: OutPoint) -> Transaction {
	let exit_spk = util::exit_spk(spec.user_pubkey, spec.asp_pubkey, spec.exit_delta);
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
				script_pubkey: exit_spk,
				value: (spec.amount - util::DUST).to_sat(),
			},
			util::dust_fee_anchor(),
		],
	}
}

pub fn unlock_tx_sighash(spec: &VtxoSpec, utxo: OutPoint) -> (TapSighash, Transaction) {
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
		Some(&[asp.signature]),
	);
	assert!(final_sig.is_some());

	Vtxo::Onboard {
		utxo: user.utxo,
		spec: user.spec,
		exit_tx_signature: final_sig.unwrap(),
	}
}
