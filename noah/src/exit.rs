
use std::io;
use std::collections::HashSet;

use anyhow::Context;
use bitcoin::{Amount, OutPoint};

use ark::{Vtxo, VtxoSpec};

use crate::Wallet;


#[derive(Debug, Serialize, Deserialize)]
pub enum ClaimInputType {
	Onboard {
		spec: VtxoSpec,
	},
	TreeLeaf {
		spec: VtxoSpec,
	},
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClaimInput {
	pub utxo: OutPoint,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
	pub input_type: ClaimInputType,
}

impl ClaimInput {
	pub fn encode(&self) -> Vec<u8> {
		let mut buf = Vec::new();
		ciborium::into_writer(self, &mut buf).unwrap();
		buf
	}

	pub fn decode(bytes: &[u8]) -> Result<Self, ciborium::de::Error<io::Error>> {
		ciborium::from_reader(bytes)
	}
}

impl Wallet {
	/// Exit all vtxo onto the chain.
	pub async fn start_unilateral_exit(&mut self) -> anyhow::Result<()> {
		let vtxos = self.db.get_all_vtxos()?;

		//TODO(stevenroose) idea, each vtxo will have a fee anchor for us.
		// We should here
		// - collect all fee anchor outputs of broadcasted txs in a list
		// - add up the vsize of all txs we broadcasted
		// - create a new tx using our on-chain wallet that spends all anchors and
		// has an absolute fee that pays our feerate (also todo) for the entire
		// "package" vsize.

		info!("Starting unilateral exit of {} vtxos...", vtxos.len());
		let mut total_size = 0;
		let mut started = Vec::with_capacity(vtxos.len());
		let mut new_claim_inputs = Vec::with_capacity(vtxos.len());
		let mut fee_anchors = Vec::with_capacity(vtxos.len());
		'vtxo: for vtxo in vtxos {
			let id = vtxo.id();
			match vtxo {
				Vtxo::Onboard { spec, utxo, unlock_tx_signature } => {
					let unlock_tx = ark::onboard::create_unlock_tx(
						&spec, utxo, Some(&unlock_tx_signature),
					);

					debug!("Broadcasting unlock tx for vtxo {}: {}", id, unlock_tx.txid());
					if let Err(e) = self.onchain.broadcast_tx(&unlock_tx) {
						error!("Error broadcasting unlock tx for onboard vtxo {}: {}", id, e);
						continue;
					}
					total_size += unlock_tx.vsize();

					started.push(id);
					new_claim_inputs.push(ClaimInput {
						utxo: OutPoint::new(unlock_tx.txid(), 0),
						amount: spec.amount,
						input_type: ClaimInputType::Onboard { spec },
					});
					fee_anchors.push(OutPoint::new(unlock_tx.txid(), 1));
				},
				Vtxo::Round { spec, utxo: _, leaf_idx: _, exit_branch } => {
					debug!("Broadcasting {} txs of exit branch for vtxo {}: {:?}",
						exit_branch.len(), id, exit_branch.iter().map(|t| t.txid()).collect::<Vec<_>>());
					let mut branch_size = 0;
					for tx in &exit_branch {
						if let Err(e) = self.onchain.broadcast_tx(&tx) {
							error!("Error broadcasting exit branch tx {} for vtxo {}: {}",
								tx.txid(), id, e,
							);
							continue 'vtxo;
						}
						branch_size += tx.vsize();
					}
					total_size += branch_size;
					let leaf = exit_branch.last().unwrap();
					started.push(id);
					new_claim_inputs.push(ClaimInput {
						utxo: OutPoint::new(leaf.txid(), 0),
						amount: spec.amount,
						input_type: ClaimInputType::TreeLeaf { spec },
					});
					fee_anchors.push(OutPoint::new(leaf.txid(), 1));
				},
			}
		}

		if new_claim_inputs.len() == 0 {
			return Ok(());
		}

		info!("Got {} outputs to claim, {} fee anchors to spend and {} package vsize to cover",
			new_claim_inputs.len(), fee_anchors.len(), total_size);

		// First we will store the claim inputs so we for sure don't forget about them.
		// We might already have some pending claim inputs.
		let mut claim_inputs = self.db.get_claim_inputs().context("db error getting existing claims")?;
		let mut claim_utxos = claim_inputs.iter().map(|i| i.utxo).collect::<HashSet<_>>();
		for new in new_claim_inputs {
			if claim_utxos.insert(new.utxo) {
				claim_inputs.push(new);
			} else {
				warn!("A claim input for utxo {} already existed", new.utxo);
			}
		}
		self.db.store_claim_inputs(&claim_inputs).context("db error storing claim inputs")?;

		// Then we'll send a tx that will pay the fee for all the txs we made.
		let tx = self.onchain.spend_fee_anchors(&fee_anchors, total_size)?;
		info!("Send anchor spend tx: {}", tx.txid());

		// After we succesfully stored the claim inputs, we can drop the vtxos.
		for id in started {
			if let Err(e) = self.db.remove_vtxo(id) {
				// Don't error here so we can try remove the others.
				warn!("Error removing vtxo {} from db: {}", id, e);
			}
		}
		Ok(())
	}

	pub async fn claim_unilateral_exit(&mut self) -> anyhow::Result<()> {
		unimplemented!();
		let mut inputs = self.db.get_claim_inputs()?;
		
		Ok(())
	}
}
