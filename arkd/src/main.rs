
#[macro_use] extern crate log;

use std::{env, fs};
use std::time::Duration;

use arkd::{App, Config};

#[tokio::main]
async fn main() {
	env_logger::builder()
		.filter_module("sled", log::LevelFilter::Off)
		.filter_module("bitcoincore_rpc", log::LevelFilter::Off)
		.filter_level(log::LevelFilter::Trace)
		.init();

	let cfg = Config {
		network: bitcoin::Network::Regtest,
		public_rpc_address: "[::1]:35035".parse().unwrap(),
		datadir: env::current_dir().unwrap().join("test/arkd/"),
		round_interval: Duration::from_secs(10),
		round_submit_time: Duration::from_secs(2),
		round_sign_time: Duration::from_secs(2),
		nb_round_nonces: 100,
		vtxo_expiry_delta: 1 * 24 * 6, // 1 day
		vtxo_exit_delta: 2 * 6, // 2 hrs
		..Default::default()
	};
	fs::create_dir_all(&cfg.datadir).expect("failed to create datadir");

	let (app, jh) = App::start(cfg).unwrap();
	info!("arkd onchain address: {}", app.onchain_address().await.unwrap());
	if let Err(e) = jh.await.unwrap() {
		error!("Shutdown error from arkd: {}", e);
	}

}
