

use std::iter;

use bitcoin::{
	Address, Amount, Network, OutPoint, Script, ScriptBuf, Sequence, Transaction, TxIn,
	TxOut, Witness,
};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{self, KeyPair, PublicKey};
use bitcoin::sighash::{self, SighashCache, TapSighashType};

use crate::{fee, util};


/// The size in vbytes of each connector tx.
const TX_SIZE: u64 = 154;


/// A chain of connector outputs.
///
/// Each connector is a p2tr keyspend output for the provided key.
/// Each connector has the p2tr dust value.
#[derive(Debug)]
pub struct ConnectorChain {
	len: usize,
	spk: ScriptBuf,
	utxo: OutPoint,
}

impl ConnectorChain {
	/// The total size in vbytes of the connector tree.
	pub fn total_vsize(len: usize) -> u64 {
		assert_ne!(len, 0);
		(len - 1) as u64 * TX_SIZE
	}

	/// The budget needed for a chain of length [len] to pay for
	/// - dust on 2 outputs per tx
	/// - minrelayfee per tx
	pub fn required_budget(len: usize) -> Amount {
		assert_ne!(len, 0);
		Amount::from_sat(
			// We need n times dust for connectors.
			len as u64 * fee::DUST.to_sat()
			// Then we need minrelayfee to make sure we can pay for every tx in chain.
			+ Self::total_vsize(len)
		)
	}

	/// Create the scriptPubkey to create a connector chain using the given publick key.
	pub fn output_script(pubkey: PublicKey) -> ScriptBuf {
		ScriptBuf::new_v1_p2tr(&util::SECP, pubkey.x_only_public_key().0, None)
	}

	/// Create the address to create a connector chain using the given publick key.
	pub fn address(network: Network, pubkey: PublicKey) -> Address {
		Address::from_script(&Self::output_script(pubkey), network).unwrap()
	}

	/// Create a connector output.
	pub fn output(len: usize, pubkey: PublicKey) -> TxOut {
		TxOut {
			script_pubkey: Self::output_script(pubkey),
			value: Self::required_budget(len).to_sat(),
		}
	}

	/// Create a new connector tree.
	///
	/// Before calling this method, a utxo should be created with a scriptPubkey
	/// as specified by [ConnectorChain::output_script] or [ConnectorChain::address].
	/// The amount in this output is expected to be exaclty equal to
	/// [ConnectorChain::required_budget].
	pub fn new(len: usize, utxo: OutPoint, pubkey: PublicKey) -> ConnectorChain {
		assert_ne!(len, 0);
		let spk = Self::output_script(pubkey);

		ConnectorChain { len, spk, utxo }
	}

	/// Iterator over the signed transactions in this chain.
	pub fn iter_signed_txs<'a>(&'a self, sign_key: &'a KeyPair) -> ConnectorTxIter<'a> {
		ConnectorTxIter {
			len: self.len,
			spk: &self.spk,
			sign_key: Some(sign_key),
			prev: self.utxo,
			idx: 0,
		}
	}

	/// Iterator over the transactions in this chain.
	pub fn iter_unsigned_txs(&self) -> ConnectorTxIter {
		ConnectorTxIter {
			len: self.len,
			spk: &self.spk,
			sign_key: None,
			prev: self.utxo,
			idx: 0,
		}
	}

	/// Iterator over the connector outpoints in this chain.
	pub fn connectors<'a>(&'a self) -> ConnectorIter<'a> {
		ConnectorIter {
			txs: self.iter_unsigned_txs(),
			maybe_last: Some(self.utxo),
		}
	}
}

pub struct ConnectorTxIter<'a> {
	len: usize,
	spk: &'a Script,
	sign_key: Option<&'a KeyPair>,

	prev: OutPoint,
	idx: usize,
}

impl<'a> iter::Iterator for ConnectorTxIter<'a> {
	type Item = Transaction;

	fn next(&mut self) -> Option<Self::Item> {
		if self.idx >= self.len - 1 {
			return None;
		}

		let mut ret = Transaction {
			version: 2,
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output: self.prev,
				script_sig: ScriptBuf::new(),
				sequence: Sequence::ZERO,
				witness: Witness::new(),
			}],
			output: vec![
				TxOut {
					script_pubkey: self.spk.to_owned(),
					value: ConnectorChain::required_budget(self.len - self.idx - 1).to_sat(),
				},
				TxOut {
					script_pubkey: self.spk.to_owned(),
					value: fee::DUST.to_sat(),
				},
			],
		};

		if let Some(keypair) = self.sign_key {
			let prevout = TxOut {
				script_pubkey: self.spk.to_owned(),
				value: ConnectorChain::required_budget(self.len - self.idx).to_sat(),
			};
			let mut shc = SighashCache::new(&ret);
			let sighash = shc.taproot_signature_hash(
				0,
				&sighash::Prevouts::All(&[&prevout]),
				None,
				None,
				TapSighashType::Default,
			).expect("sighash error");
			// TODO(stevenroose) use from_digest here after secp version update
			let msg = secp256k1::Message::from_slice(&sighash.to_byte_array()).unwrap();
			let sig = util::SECP.sign_schnorr(&msg, keypair);
			ret.input[0].witness = Witness::from_slice(&[sig[..].to_vec()]);
		}

		self.idx += 1;
		self.prev = OutPoint::new(ret.txid(), 0);
		Some(ret)
	}

	fn size_hint(&self) -> (usize, Option<usize>) {
		let s = self.len - 1;
		(s, Some(s))
	}
}

pub struct ConnectorIter<'a> {
	txs: ConnectorTxIter<'a>,
	maybe_last: Option<OutPoint>,
}

impl<'a> iter::Iterator for ConnectorIter<'a> {
	type Item = OutPoint;

	fn next(&mut self) -> Option<Self::Item> {
		if self.maybe_last.is_none() {
			return None;
		}

		if let Some(tx) = self.txs.next() {
			let txid = tx.txid();
			self.maybe_last = Some(OutPoint::new(txid, 0));
			Some(OutPoint::new(txid, 1))
		} else {
			Some(self.maybe_last.take().expect("broken"))
		}
	}

	fn size_hint(&self) -> (usize, Option<usize>) {
		(self.txs.len, Some(self.txs.len))
	}
}

impl<'a> iter::ExactSizeIterator for ConnectorTxIter<'a> {}
impl<'a> iter::FusedIterator for ConnectorTxIter<'a> {}


#[cfg(test)]
mod test {
	use super::*;
	use bitcoin::Txid;
	use rand;

	#[test]
	fn test_budget() {
		let key = KeyPair::new(&util::SECP, &mut rand::thread_rng());
		let utxo = OutPoint::new(Txid::all_zeros(), 0);

		let chain = ConnectorChain::new(1, utxo, key.public_key());
		assert_eq!(chain.connectors().count(), 1);
		assert_eq!(chain.iter_unsigned_txs().count(), 0);
		assert_eq!(chain.connectors().next().unwrap(), utxo);

		let chain = ConnectorChain::new(2, utxo, key.public_key());
		assert_eq!(chain.connectors().count(), 2);
		assert_eq!(chain.iter_unsigned_txs().count(), 1);
		assert_eq!(chain.iter_signed_txs(&key).count(), 1);
		let tx = chain.iter_signed_txs(&key).next().unwrap();
		assert_eq!(TX_SIZE, tx.vsize() as u64);

		let chain = ConnectorChain::new(100, utxo, key.public_key());
		assert_eq!(chain.connectors().count(), 100);
		assert_eq!(chain.iter_unsigned_txs().count(), 99);
		assert_eq!(chain.iter_signed_txs(&key).count(), 99);
		chain.iter_signed_txs(&key).for_each(|t| assert_eq!(t.vsize() as u64, TX_SIZE));
		let size = chain.iter_signed_txs(&key).map(|t| t.vsize() as u64).sum::<u64>();
		assert_eq!(size, ConnectorChain::total_vsize(100));
		chain.iter_unsigned_txs().for_each(|t| assert_eq!(t.output[1].value, fee::DUST.to_sat()));
		assert_eq!(fee::DUST.to_sat(), chain.iter_unsigned_txs().last().unwrap().output[0].value);

		let total_value = chain.iter_unsigned_txs().map(|t| t.output[1].value).sum::<u64>()
			+ chain.iter_unsigned_txs().last().unwrap().output[0].value
			+ size;
		assert_eq!(ConnectorChain::required_budget(100).to_sat(), total_value);

		// random checks
		let mut txs = chain.iter_unsigned_txs();
		assert_eq!(txs.next().unwrap().output[0].value, ConnectorChain::required_budget(99).to_sat());
		assert_eq!(txs.next().unwrap().output[0].value, ConnectorChain::required_budget(98).to_sat());
	}

	#[test]
	fn test_signatures() {
		let key = KeyPair::new(&util::SECP, &mut rand::thread_rng());
		let utxo = OutPoint::new(Txid::all_zeros(), 0);
		let spk = ConnectorChain::output_script(key.public_key());

		let mut n = 10;
		let chain = ConnectorChain::new(n, utxo, key.public_key());
		for tx in chain.iter_signed_txs(&key) {
			bitcoinconsensus::verify(
				spk.as_bytes(),
				ConnectorChain::required_budget(n).to_sat(),
				&bitcoin::consensus::serialize(&tx),
				0,
			).expect("verification failed");
			n -= 1;
		}
	}
}
