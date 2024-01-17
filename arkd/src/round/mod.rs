

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::App;

#[derive(Debug, Clone)]
pub enum RoundEvent {
	NewRound(u64),
}

#[derive(Debug)]
struct RoundState {
	id: u64,
}

/// This method is called from a tokio thread so it can be long-lasting.
pub async fn run_round_scheduler(app: Arc<App>) -> anyhow::Result<()> {
	let cfg = &app.config;

	loop {
		tokio::time::sleep(cfg.round_interval).await;
		let id = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

		let mut round = RoundState {
			id: id,
		};

		// Start new round, announce.
		app.round_event_tx.send(RoundEvent::NewRound(id))?;
	}
}
