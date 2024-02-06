

use std::{cmp, io};

use bitcoin::{
	taproot, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use bitcoin::secp256k1::{self, schnorr, PublicKey, XOnlyPublicKey};
use bitcoin::sighash::{self, SighashCache, TapSighash, TapSighashType};
use bitcoin::taproot::TaprootBuilder;

use crate::{fee, musig, util, VtxoRequest};
use crate::tree::Tree;


/// Size in vbytes for the leaf txs.
const LEAF_TX_VSIZE: u64 = 154;
/// Size in vbytes for a node tx with radix 2.
const NODE2_TX_VSIZE: u64 = 154;
/// Size in vbytes for a node tx with radix 3.
const NODE3_TX_VSIZE: u64 = 197;
/// Size in vbytes for a node tx with radix 4.
const NODE4_TX_VSIZE: u64 = 240;


#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VtxoTreeSpec {
	pub cosigners: Vec<PublicKey>,
	pub vtxos: Vec<VtxoRequest>,
	pub asp_key: PublicKey,
	pub expiry_height: u32,
	pub exit_delta: u16,

	#[serde(skip)]
	cosign_key_agg: Option<musig::MusigKeyAggCache>,
}

impl VtxoTreeSpec {
	pub fn new(
		cosigners_with_asp: Vec<PublicKey>,
		vtxos: Vec<VtxoRequest>,
		asp_key: PublicKey,
		expiry_height: u32,
		exit_delta: u16,
	) -> VtxoTreeSpec {
		VtxoTreeSpec {
			cosign_key_agg: Some(musig::key_agg(cosigners_with_asp.iter().copied())),
			cosigners: cosigners_with_asp,
			vtxos: vtxos,
			asp_key: asp_key,
			expiry_height: expiry_height,
			exit_delta: exit_delta,
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

	/// The aggregated cosigning key without any taptweak performed.
	pub fn cosign_agg_pubkey(&self) -> XOnlyPublicKey {
		musig::xonly_from(self.cosign_key_agg().agg_pk())
	}

	pub fn iter_vtxos(&self) -> impl Iterator<Item = &VtxoRequest> {
		self.vtxos.iter()
	}

	/// Calculate the total value needed in the tree.
	///
	/// This accounts for
	/// - all vtxos getting their value
	/// - a dust fee anchor at each leaf
	/// - minrelay fee for all intermediate txs
	pub fn total_required_value(&self) -> Amount {
		let dest_sum = self.vtxos.iter().map(|d| d.amount.to_sat()).sum::<u64>();

		// all anchor dust + 1 sat/vb for minrelayfee
		let leaf_extra = self.vtxos.len() as u64 * fee::DUST.to_sat()
			+ self.vtxos.len() as u64 * LEAF_TX_VSIZE;

		// total minrelayfee requirement for all intermediate nodes
		let nodes_fee = {
			let mut ret = 0;
			let mut left = self.vtxos.len();
			while left > 1 {
				let radix = cmp::min(left, 4);
				left -= radix;
				ret += match radix {
					2 => NODE2_TX_VSIZE,
					3 => NODE3_TX_VSIZE,
					4 => NODE4_TX_VSIZE,
					_ => unreachable!(),
				};
			}
			ret
		};

		Amount::from_sat(dest_sum + leaf_extra + nodes_fee)
	}

	pub fn find_leaf_idxs<'a>(&'a self, dest: &'a VtxoRequest) -> impl Iterator<Item = usize> + 'a {
		self.vtxos.iter().enumerate().filter_map(move |(i, d)| {
			if d == dest {
				Some(i)
			} else {
				None
			}
		})
	}

	/// The expiry clause hidden in the node taproot as only script.
	fn expiry_clause(&self) -> ScriptBuf {
		let pk = self.asp_key.x_only_public_key().0;
		util::timelock_sign(self.expiry_height.try_into().unwrap(), pk)
	}

	pub fn cosign_taproot(&self) -> taproot::TaprootSpendInfo {
		TaprootBuilder::new()
			.add_leaf(0, self.expiry_clause()).unwrap()
			.finalize(&util::SECP, self.cosign_agg_pubkey()).unwrap()
	}

	pub fn cosign_taptweak(&self) -> taproot::TapTweakHash {
		self.cosign_taproot().tap_tweak()
	}

	pub fn cosign_spk(&self) -> ScriptBuf {
		ScriptBuf::new_v1_p2tr_tweaked(self.cosign_taproot().output_key())
	}

	fn node_tx(&self, children: &[&Transaction]) -> Transaction {
		Transaction {
			version: 2,
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint::null(),
				sequence: Sequence::MAX,
				script_sig: ScriptBuf::new(),
				witness: Witness::new(),
			}],
			output: children.iter().map(|child| {
				let is_leaf = child.output.len() == 2 && child.output[1] == fee::dust_anchor();
				// We add vsize as if it was fee because 1 sat/vb.
				let fee_budget = if is_leaf {
					LEAF_TX_VSIZE
				} else {
					match child.output.len() {
						2 => NODE2_TX_VSIZE,
						3 => NODE3_TX_VSIZE,
						4 => NODE4_TX_VSIZE,
						n => unreachable!("node tx with {} children", n),
					}
				};
				TxOut {
					script_pubkey: self.cosign_spk(),
					value: child.output.iter().map(|o| o.value).sum::<u64>() + fee_budget,
				}
			}).collect(),
		}
	}

	fn exit_clause(&self, payment: &VtxoRequest) -> ScriptBuf {
		let pk = payment.pubkey.x_only_public_key().0;
		util::delayed_sign(self.exit_delta.try_into().unwrap(), pk)
	}

	fn leaf_taproot(&self, payment: &VtxoRequest) -> taproot::TaprootSpendInfo {
		let joint_key = musig::combine_keys([payment.pubkey, self.asp_key]);
		TaprootBuilder::new()
			.add_leaf(0, self.exit_clause(payment)).unwrap()
			.finalize(&util::SECP, joint_key).unwrap()
	}

	fn leaf_spk(&self, payment: &VtxoRequest) -> ScriptBuf {
		ScriptBuf::new_v1_p2tr_tweaked(self.leaf_taproot(payment).output_key())
	}

	fn leaf_tx(&self, payment: &VtxoRequest) -> Transaction {
		Transaction {
			version: 2,
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint::null(),
				sequence: Sequence::MAX,
				script_sig: ScriptBuf::new(),
				witness: Witness::new(),
			}],
			output: vec![
				TxOut {
					script_pubkey: self.leaf_spk(payment),
					value: payment.amount.to_sat(),
				},
				fee::dust_anchor(),
			],
		}
	}

	pub fn build_unsigned_tree(&self, utxo: OutPoint) -> Tree<Transaction> {
		let leaves = self.vtxos.iter().map(|dest| self.leaf_tx(dest));
		let mut tree = Tree::new(leaves, |children| self.node_tx(children));

		// Iterate over all nodes in reverse order and set the prevouts.
		let mut cursor = tree.nb_nodes() - 1;
		// This is the root, set to the tree's on-chain utxo.
		tree.element_at_mut(cursor).unwrap().input[0].previous_output = utxo;
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
		let tree = self.build_unsigned_tree(utxo);

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
				0, &sighash::Prevouts::All(&[prev]), TapSighashType::Default,
			).expect("sighash error")
		}).collect()
	}
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignedVtxoTree {
	pub spec: VtxoTreeSpec,
	pub utxo: OutPoint,
	/// The signatures for the txs as they are layed out in the tree,
	/// from the leaves up to the root.
	signatures: Vec<schnorr::Signature>,
}

impl SignedVtxoTree {
	/// We expect the signatures from top to bottom, the root tx's first and the leaves last.
	pub fn new(spec: VtxoTreeSpec, utxo: OutPoint, mut signatures: Vec<schnorr::Signature>) -> SignedVtxoTree {
		signatures.reverse();
		SignedVtxoTree { spec, utxo, signatures }
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

	fn finalize_tx(tx: &mut Transaction, sig: &schnorr::Signature) {
		// NB all our txs have a single input
		//TODO(stevenroose) check this, but I think taproot keyspecs have a single witness element
		tx.input[0].witness.push(&sig[..]);
	}

	/// Validate the signatures.
	pub fn validate(&self) -> Result<(), String> {
		let pk = self.spec.cosign_taproot().output_key().to_inner();
		let sighashes = self.spec.sighashes(self.utxo);
		for (i, (sighash, sig)) in sighashes.into_iter().rev().zip(self.signatures.iter()).enumerate() {
			//TODO(stevenroose) once we bump secp, replace all Message::from_slice with from_digest
			let msg = secp256k1::Message::from_slice(&sighash[..]).unwrap();
			util::SECP.verify_schnorr(sig, &msg, &pk)
				.map_err(|e| format!("failed signature {}: sh {}; sig {}: {}", i, sighash, sig, e))?;
		}
		Ok(())
	}

	/// Construct the exit branch starting from the root ending in the leaf.
	pub fn exit_branch(&self, leaf_idx: usize) -> Option<Vec<Transaction>> {
		let tree = self.spec.build_unsigned_tree(self.utxo);
		if leaf_idx >= tree.nb_leaves {
			return None;
		}

		let mut branch = Vec::new();
		let mut cursor = leaf_idx;
		loop {
			let mut tx = tree.element_at(cursor).unwrap().clone();
			SignedVtxoTree::finalize_tx(&mut tx, &self.signatures[cursor]);
			branch.push(tx);
			if let Some(p) = tree.parent_idx_of(cursor) {
				cursor = p;
			} else {
				break;
			}
		}
		branch.reverse();

		Some(branch)
	}
}

#[cfg(test)]
mod test {
	use super::*;

	use std::str::FromStr;

	use bitcoin::hashes::sha256;
	use bitcoin::secp256k1::{self, rand, KeyPair};

	#[test]
	fn test_node_tx_sizes() {
		let secp = secp256k1::Secp256k1::new();
		let key1 = KeyPair::new(&secp, &mut rand::thread_rng()); // asp
		let key2 = KeyPair::new(&secp, &mut rand::thread_rng());
		let sha = sha256::Hash::from_str("4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a").unwrap();
		let sig = secp.sign_schnorr(
			&secp256k1::Message::from_slice(&sha[..]).unwrap(), &key1,
		);
		let dest = VtxoRequest {
			pubkey: KeyPair::new(&secp, &mut rand::thread_rng()).public_key(),
			amount: Amount::from_sat(100_000),
		};
		let point = "0000000000000000000000000000000000000000000000000000000000000001:1".parse().unwrap();

		// For 2..5 we should pass all types of radixes.
		let (mut had2, mut had3, mut had4) = (false, false, false);
		for n in 2..5 {
			let spec = VtxoTreeSpec::new(
				vec![key1.public_key(), key2.public_key()],
				vec![dest.clone(); n],
				key1.public_key(),
				100_000,
				2016,
			);
			let unsigned = spec.build_unsigned_tree(point);
			assert!(unsigned.iter().all(|n| !n.element.input[0].previous_output.is_null()));
			let nb_nodes = unsigned.nb_nodes();
			let signed = SignedVtxoTree::new(spec, point, vec![sig.clone(); nb_nodes]);
			for m in 0..n {
				let exit = signed.exit_branch(m).unwrap();

				// Assert it's a valid chain.
				let mut iter = exit.iter().enumerate().peekable();
				while let Some((i, cur)) = iter.next() {
					if let Some((_, next)) = iter.peek() {
						assert_eq!(next.input[0].previous_output.txid, cur.txid(), "{}", i);
					}
				}

				// Assert the node tx sizes match our pre-computed ones.
				let mut iter = exit.iter().rev();
				let leaf = iter.next().unwrap();
				assert_eq!(leaf.vsize() as u64, LEAF_TX_VSIZE);
				for node in iter {
					match node.output.len() {
						2 => {
							assert_eq!(node.vsize() as u64, NODE2_TX_VSIZE);
							had2 = true;
						},
						3 => {
							assert_eq!(node.vsize() as u64, NODE3_TX_VSIZE);
							had3 = true;
						},
						4 => {
							assert_eq!(node.vsize() as u64, NODE4_TX_VSIZE);
							had4 = true;
						},
						_ => unreachable!(),
					}
				}
			}
		}
		assert!(had2 && had3 && had4);
	}
}
