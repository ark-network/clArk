

use std::{cmp, io};
use std::collections::VecDeque;
use std::time::{Duration, SystemTime};

use bitcoin::{
	Address, Amount, Network, OutPoint, Script, ScriptBuf, Sequence, Transaction, Txid, TxIn,
	TxOut, Weight, Witness,
};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{self, schnorr, KeyPair, PublicKey, SecretKey, XOnlyPublicKey};
use bitcoin::sighash::{self, SighashCache, TapSighash, TapSighashType};
use bitcoin::taproot::{TaprootBuilder};
use bitcoin::opcodes;
use serde::{Deserialize, Serialize};

use crate::{musig, util, Destination};
use crate::tree::Tree;


/// Size in vbytes for the leaf txs.
const LEAF_TX_SIZE: u64 = 0;
/// Size in vbytes for a node tx with radix 2.
const NODE2_TX_SIZE: u64 = 0;
/// Size in vbytes for a node tx with radix 3.
const NODE3_TX_SIZE: u64 = 0;
/// Size in vbytes for a node tx with radix 4.
const NODE4_TX_SIZE: u64 = 0;


#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VtxoTreeSpec {
	cosigners: Vec<PublicKey>,
	destinations: Vec<Destination>,
	asp_key: PublicKey,
	expiry_height: u32,
	exit_timeout_blocks: u32,

	#[serde(skip)]
	cosign_key_agg: Option<musig::MusigKeyAggCache>,
}

impl VtxoTreeSpec {
	pub fn new(
		cosigners_with_asp: Vec<PublicKey>,
		destinations: Vec<Destination>,
		asp_key: PublicKey,
		expiry_height: u32,
		exit_timeout_blocks: u32,
	) -> VtxoTreeSpec {
		VtxoTreeSpec {
			cosigners: cosigners_with_asp,
			destinations: destinations,
			asp_key: asp_key,
			expiry_height: expiry_height,
			exit_timeout_blocks: exit_timeout_blocks,
			cosign_key_agg: None,
		}
	}

	pub fn encode(&self) -> Vec<u8> {
		let mut buf = Vec::new();
		ciborium::into_writer(self, &mut buf).unwrap();
		buf
	}

	pub fn decode(bytes: &[u8]) -> Result<Self, ciborium::de::Error<io::Error>> {
		let mut ret: Self = ciborium::from_reader(bytes)?;
		ret.cosign_key_agg = Some(musig::key_agg(ret.cosigners.iter().copied()));
		Ok(ret)
	}

	fn cosign_key_agg(&self) -> &musig::MusigKeyAggCache {
		self.cosign_key_agg.as_ref().unwrap()
	}

	pub fn cosign_agg_pubkey(&self) -> XOnlyPublicKey {
		musig::xonly_from(self.cosign_key_agg().agg_pk())
	}

	/// Calculate the total value needed in the tree.
	///
	/// This accounts for
	/// - all destinations getting their value
	/// - a dust fee anchor at each leaf
	/// - minrelay fee for all intermediate txs
	pub fn total_required_value(&self) -> Amount {
		let dest_sum = self.destinations.iter().map(|d| d.amount.to_sat()).sum::<u64>();

		// all anchor dust + 1 sat/vb for minrelayfee
		let leaf_extra = self.destinations.len() as u64 * util::DUST.to_sat()
			+ self.destinations.len() as u64 * LEAF_TX_SIZE;

		// total minrelayfee requirement for all intermediate nodes
		let nodes_fee = {
			let mut ret = 0;
			let mut left = self.destinations.len();
			while left > 1 {
				let radix = cmp::min(left, 4);
				left -= radix - 1;
				ret += match radix {
					2 => NODE2_TX_SIZE,
					3 => NODE3_TX_SIZE,
					4 => NODE4_TX_SIZE,
					_ => unreachable!(),
				};
			}
			ret
		};

		Amount::from_sat(dest_sum + leaf_extra + nodes_fee)
	}

	/// The expiry clause hidden in the node taproot as only script.
	fn expiry_clause(&self) -> ScriptBuf {
		let pk = self.asp_key.x_only_public_key().0;
		util::timelock_sign(self.expiry_height.try_into().unwrap(), pk)
	}

	pub fn cosign_spk(&self) -> ScriptBuf {
		let cosign_key = musig::xonly_from(self.cosign_key_agg().agg_pk());
		let node_spendinfo = TaprootBuilder::new()
			.add_leaf(0, self.expiry_clause()).unwrap()
			.finalize(&util::SECP, cosign_key).unwrap();
		ScriptBuf::new_v1_p2tr_tweaked(node_spendinfo.output_key())
	}

	fn node_tx(&self, children: &[&Transaction]) -> Transaction {
		Transaction {
			version: 2,
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint::null(),
				sequence: Sequence::ZERO,
				script_sig: ScriptBuf::new(),
				witness: Witness::new(),
			}],
			output: children.iter().map(|child| {
				TxOut {
					script_pubkey: self.cosign_spk(),
					value: child.output.iter().map(|o| o.value).sum(),
				}
			}).collect(),
		}
	}

	fn exit_clause(&self, destination: &Destination) -> ScriptBuf {
		let pk = destination.pubkey.x_only_public_key().0;
		util::delayed_sign(self.exit_timeout_blocks.try_into().unwrap(), pk)
	}

	fn leaf_spk(&self, destination: &Destination) -> ScriptBuf {
		let joint_key = musig::combine_keys([destination.pubkey, self.asp_key]);
		let leaf_spendinfo = TaprootBuilder::new()
			.add_leaf(0, self.exit_clause(destination)).unwrap()
			.finalize(&util::SECP, joint_key).unwrap();
		ScriptBuf::new_v1_p2tr_tweaked(leaf_spendinfo.output_key())
	}

	fn leaf_tx(&self, destination: &Destination) -> Transaction {
		Transaction {
			version: 2,
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint::null(),
				sequence: Sequence::ZERO,
				script_sig: ScriptBuf::new(),
				witness: Witness::new(),
			}],
			output: vec![
				TxOut {
					script_pubkey: self.leaf_spk(destination),
					value: destination.amount.to_sat(),
				},
				util::dust_fee_anchor(),
			],
		}
	}

	pub fn build_tree(&self, utxo: OutPoint) -> Tree<Transaction> {
		let leaves = self.destinations.iter().map(|dest| self.leaf_tx(dest));
		let mut tree = Tree::new(leaves, |children| self.node_tx(children));

		// Iterate over all nodes in reverse order and set the prevouts.
		let mut cursor = tree.nb_nodes() - 1;
		tree.element_at_mut(cursor).unwrap().input[0].previous_output = utxo;
		cursor -= 1;
		while cursor >= tree.nb_leaves() {
			let txid = tree.element_at(cursor).unwrap().txid();
			let nb_children = tree.nb_children_of(cursor).unwrap();
			for i in 0..nb_children {
				let prevout = OutPoint::new(txid, i as u32);
				tree.child_of_mut(cursor, i).unwrap().input[0].previous_output = prevout;
			}
			cursor -= 1;
		}

		tree
	}

	/// Return all sighashes ordered from the root down to the leaves.
	pub fn sighashes(&self, utxo: OutPoint) -> Vec<TapSighash> {
		let tree = self.build_tree(utxo);

		(0..tree.nb_nodes()).rev().map(|idx| {
			let prev = if let Some((parent, child_idx)) = tree.parent_of_with_idx(idx) {
				parent.output[child_idx].clone()
			} else {
				// this is the root
				TxOut {
					script_pubkey: self.cosign_spk(),
					value: self.total_required_value().to_sat(),
				}
			};
			let el = tree.element_at(idx).unwrap();
			SighashCache::new(el).taproot_key_spend_signature_hash(
				0,
				&sighash::Prevouts::All(&[prev]),
				TapSighashType::All,
			).expect("sighash error")
		}).collect()
	}
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SignedVtxoTree {
	spec: VtxoTreeSpec,
	signatures: Vec<schnorr::Signature>,
}

impl SignedVtxoTree {
	pub fn new(spec: VtxoTreeSpec, signatures: Vec<schnorr::Signature>) -> SignedVtxoTree {
		SignedVtxoTree { spec, signatures }
	}

	pub fn encode(&self) -> Vec<u8> {
		let mut buf = Vec::new();
		ciborium::into_writer(self, &mut buf).unwrap();
		buf
	}

	pub fn decode(bytes: &[u8]) -> Result<Self, ciborium::de::Error<io::Error>> {
		let mut ret: Self = ciborium::from_reader(bytes)?;
		ret.spec.cosign_key_agg = Some(musig::key_agg(ret.spec.cosigners.iter().copied()));
		Ok(ret)
	}
}

#[cfg(test)]
mod test {
	use super::*;
}
