
pub use secp256k1_zkp as secp;
pub use secp256k1_zkp::{
	MusigAggNonce, MusigKeyAggCache, MusigPubNonce, MusigPartialSignature, MusigSecNonce,
	MusigSession, MusigSessionId, Message,
};
use bitcoin::secp256k1::{rand, schnorr, PublicKey, SecretKey, XOnlyPublicKey};

lazy_static::lazy_static! {
	/// Global secp context.
	pub static ref SECP: secp256k1_zkp::Secp256k1<secp256k1_zkp::All> = secp256k1_zkp::Secp256k1::new();
}

pub fn xonly_from(pk: secp256k1_zkp::XOnlyPublicKey) -> XOnlyPublicKey {
	XOnlyPublicKey::from_slice(&pk.serialize()).unwrap()
}

pub fn pubkey_to(pk: PublicKey) -> secp256k1_zkp::PublicKey {
	secp256k1_zkp::PublicKey::from_slice(&pk.serialize()).unwrap()
}

pub fn seckey_to(sk: SecretKey) -> secp256k1_zkp::SecretKey {
	secp256k1_zkp::SecretKey::from_slice(&sk.secret_bytes()).unwrap()
}

pub fn sig_from(s: secp256k1_zkp::schnorr::Signature) -> schnorr::Signature {
	schnorr::Signature::from_slice(&s.serialize()).unwrap()
}

pub fn key_agg(keys: &[PublicKey]) -> MusigKeyAggCache {
	let mut keys = keys.iter().map(|k| pubkey_to(*k)).collect::<Vec<_>>();
	keys.sort_by_key(|k| k.serialize());
	MusigKeyAggCache::new(&SECP, &keys)
}

pub fn combine_keys(keys: &[PublicKey]) -> XOnlyPublicKey {
	xonly_from(key_agg(keys).agg_pk())
}

/// Perform a deterministic partial sign for the given message and the
/// given counterparty key and nonce.
pub fn deterministic_partial_sign(
	my_key: SecretKey,
	their_key: PublicKey,
	their_nonce: MusigPubNonce,
	msg: [u8; 32],
) -> (MusigPubNonce, MusigPartialSignature) {
	let my_pubkey = my_key.public_key(&crate::SECP);
	//TODO(stevenroose) consider taking keypair for efficiency
	let keypair = secp256k1_zkp::Keypair::from_seckey_slice(&SECP, &my_key.secret_bytes()).unwrap();
	let agg = key_agg(&[their_key, my_pubkey]);

	let session_id = MusigSessionId::assume_unique_per_nonce_gen(rand::random());

	let msg = Message::from_digest(msg);
	let (sec_nonce, pub_nonce) = secp::new_musig_nonce_pair(
		&SECP, session_id, Some(&agg), Some(seckey_to(my_key)), pubkey_to(my_pubkey), Some(msg), None,
	).expect("asp nonce gen error");

	let agg_nonce = MusigAggNonce::new(&SECP, &[their_nonce, pub_nonce]);
	let session = MusigSession::new(&SECP, &agg, agg_nonce, msg);
	let sig = session.partial_sign(&SECP, sec_nonce, &keypair, &agg)
		.expect("asp partial sign error");
	(pub_nonce, sig)
}

pub fn partial_sign(
	privkey: SecretKey,
	pubkeys: &[PublicKey],
	sec_nonce: MusigSecNonce,
	pub_nonces: &[MusigPubNonce],
	sighash: [u8; 32],
	other_sigs: Option<&[MusigPartialSignature]>,
) -> (MusigPartialSignature, Option<schnorr::Signature>) {
	let agg = key_agg(pubkeys);
	let agg_nonce = MusigAggNonce::new(&SECP, pub_nonces);
	let msg = secp256k1_zkp::Message::from_digest(sighash);
	let session = MusigSession::new(&SECP, &agg, agg_nonce, msg);
	//TODO(stevenroose) consider taking keypair for efficiency
	let keypair = secp256k1_zkp::Keypair::from_seckey_slice(&SECP, &privkey.secret_bytes()).unwrap();
	let my_sig = session.partial_sign(&SECP, sec_nonce, &keypair, &agg).expect("musig partial sign error");
	let final_sig = if let Some(others) = other_sigs {
		let mut sigs = Vec::with_capacity(others.len() + 1);
		sigs.extend_from_slice(others);
		sigs.push(my_sig);
		Some(session.partial_sig_agg(&sigs))
	} else {
		None
	};
	(my_sig, final_sig.map(sig_from))
}

//TODO(stevenroose) probably get rid of all this by having native byte serializers in secp
pub mod serde {
	use super::*;
	use ::serde::{Deserializer, Serializer};
	use ::serde::de::{self, Error};

	struct BytesVisitor;
	impl<'de> de::Visitor<'de> for BytesVisitor {
		type Value = Vec<u8>;
		fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
			write!(f, "a byte object")
		}
		fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
			Ok(v.to_vec())
		}
		fn visit_borrowed_bytes<E: de::Error>(self, v: &'de [u8]) -> Result<Self::Value, E> {
			Ok(v.to_vec())
		}
		fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
			Ok(v)
		}
	}

	pub mod pubnonce {
		use super::*;
		pub fn serialize<S: Serializer>(pub_nonce: &MusigPubNonce, s: S) -> Result<S::Ok, S::Error> {
			s.serialize_bytes(&pub_nonce.serialize())
		}
		pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<MusigPubNonce, D::Error> {
			let v = d.deserialize_byte_buf(BytesVisitor)?;
			MusigPubNonce::from_slice(&v).map_err(D::Error::custom)
		}
	}
	pub mod partialsig {
		use super::*;
		pub fn serialize<S: Serializer>(sig: &MusigPartialSignature, s: S) -> Result<S::Ok, S::Error> {
			s.serialize_bytes(&sig.serialize())
		}
		pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<MusigPartialSignature, D::Error> {
			let v = d.deserialize_byte_buf(BytesVisitor)?;
			MusigPartialSignature::from_slice(&v).map_err(D::Error::custom)
		}
	}
}
