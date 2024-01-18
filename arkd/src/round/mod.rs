

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin::{Amount};
use bitcoin::secp256k1::PublicKey;

use ark::{VtxoId};
use ark::connectors::ConnectorChain;

use crate::App;
use crate::database::StoredVtxo;

#[derive(Debug)]
pub struct Output {
	pub pubkey: PublicKey,
	pub amount: Amount,
}

#[derive(Debug, Clone)]
pub enum RoundEvent {
	NewRound {
		id: u64,
	},
}

#[derive(Debug)]
pub enum RoundInput {
	RegisterPayment {
		inputs: Vec<StoredVtxo>,
		outputs: Vec<Output>,
	}
}

#[derive(Debug)]
enum RoundState {
	OpenForPayments,
}

fn validate_payment(inputs: &[StoredVtxo], outputs: &[Output]) -> bool {
	let in_set = HashSet::with_capacity(inputs.len());
	let mut in_sum = Amount::ZERO;
	for input in inputs {
		in_sum += input.amount();
		if in_sum > Amount::MAX_MONEY || !in_set.insert(input.id()) {
			return false;
		}
	}

	let mut out_sum = Amount::ZERO;
	for output in outputs {
		out_sum += output.amount;
		if out_sum > in_sum {
			return false;
		}
	}

	true
}

/// This method is called from a tokio thread so it can be long-lasting.
pub async fn run_round_scheduler(
	app: Arc<App>,
	round_input_rx: tokio::sync::mpsc::UnboundedReceiver<RoundInput>,
) -> anyhow::Result<()> {
	let cfg = &app.config;

	// For efficiency, we use some global buffers.
	let mut buf_inputs = Vec::new();
	let mut buf_outputs = Vec::new();
	let mut buf_allowed_inputs = HashSet::new();

	'round: loop {
		tokio::time::sleep(cfg.round_interval).await;
		let round_id = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

		let mut state = RoundState::OpenForPayments;
		buf_inputs.clear();
		buf_outputs.clear();
		buf_allowed_inputs.clear();

		// Start new round, announce.
		app.round_event_tx.send(RoundEvent::NewRound{ id: round_id })?;

		// In this loop we will try to finish the round and make new attempts.
		'attempt: loop {

			// Start receiving payments.
			let timeout = tokio::time::sleep(cfg.round_submit_time);
			'receive: loop {
				tokio::select! {
					_ = timeout => break 'receive,
					input = round_input_rx.recv() => match input.expect("broken channel") {
						RoundInput::RegisterPayment { inputs, outputs } => {
							if !buf_allowed_inputs.is_empty() {
								// This means we're not trying first time and we filter inputs.
								if let Some(bad) = inputs.iter().find(|i| buf_allowed_inputs.contains(&i.id())) {
									warn!("User attempted to submit banned input: {}", bad.id());
									continue 'receive;
								}
							}
							if !validate_payment(&inputs, &outputs) {
								warn!("User submitted bad payment: {:?}", input);
								continue 'receive;
							}
							buf_inputs.extend(inputs);
							buf_outputs.extend(outputs);
						}
						_ => debug!("Received unexpected input: {:?}", input),
					}
				}
			}
			info!("Received {} inputs and {} outputs for round", buf_inputs.len(), buf_outputs.len());

			// Build round tx.
			let connector_output = ConnectorChain::output(buf_inputs.len(), app.master_pubkey);


			break 'attempt;
		}


		break 'round;
	}

	Ok(())
}
