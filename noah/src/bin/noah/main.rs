
#[macro_use] extern crate log;

use std::{env, fs};
use std::path::PathBuf;

use bitcoin::Amount;
use bitcoin::secp256k1::PublicKey;
use clap::Parser;

use ark::Destination;
use noah::{Wallet, Config};


#[derive(Parser)]
#[command(author = "Steven Roose <steven@roose.io>", version, about)]
enum Cli {
	#[command()]
	Create {
		/// The directory in which to start the noah wallet.
		#[arg(long, required = true)]
		datadir: PathBuf,
		/// Force re-create the wallet even if it already exists.
		#[arg(long)]
		force: bool,
	},
	#[command()]
	GetAddress {},
	#[command()]
	Balance {},
	#[command()]
	Onboard {
		amount: Amount,
	},
	#[command()]
	Send {
		pubkey: PublicKey,
		amount: Amount,
	},
	#[command()]
	StartExit {},
	#[command()]
	ClaimExit {},

	/// Dev command to drop the vtxo database.
	#[command()]
	DropVtxos {},
}

#[tokio::main]
async fn main() {
	env_logger::builder()
		.filter_module("sled", log::LevelFilter::Off)
		.filter_module("bitcoincore_rpc", log::LevelFilter::Trace)
		.filter_level(log::LevelFilter::Trace)
		.init();

	//TODO(stevenroose) somehow pass this in
	let mut cfg = Config {
		network: bitcoin::Network::Regtest,
		datadir: env::current_dir().unwrap().join("test/noah/"),
		asp_address: "http://[::1]:35035".parse().unwrap(),
		..Default::default()
	};

	info!("cfg datadir: {}", cfg.datadir.display());
	match Cli::parse() {
		Cli::Create { datadir, force } => {
			if force {
				fs::remove_dir_all(&datadir).unwrap();
			}

			fs::create_dir_all(&datadir).expect("failed to create datadir");
			cfg.datadir = datadir;
			Wallet::create(cfg).await.expect("error creating wallet");
		},
		Cli::GetAddress { } => {
			let mut w = Wallet::open(cfg).await.unwrap();
			info!("Onchain address: {}", w.get_new_onchain_address().unwrap());
		},
		Cli::Balance { } => {
			let mut w = Wallet::open(cfg).await.unwrap();
			info!("Onchain balance: {}", w.onchain_balance().unwrap());
			info!("Offchain balance: {}", w.offchain_balance().await.unwrap());
			let (claimable, unclaimable) = w.unclaimed_exits().await.unwrap();
			if !claimable.is_empty() {
				let sum = claimable.iter().map(|i| i.spec.amount).sum::<Amount>();
				info!("Got {} claimable exits with total value of {}", claimable.len(), sum);
			}
			if !unclaimable.is_empty() {
				let sum = unclaimable.iter().map(|i| i.spec.amount).sum::<Amount>();
				info!("Got {} unclaimable exits with total value of {}", unclaimable.len(), sum);
			}
		},
		Cli::Onboard { amount } => {
			let mut w = Wallet::open(cfg).await.unwrap();
			w.onboard(amount).await.unwrap();
		},
		Cli::Send { pubkey, amount } => {
			let mut w = Wallet::open(cfg).await.unwrap();
			let dest = Destination { pubkey, amount };
			w.send_payment(dest).await.unwrap();
		},
		Cli::StartExit {  } => {
			let mut w = Wallet::open(cfg).await.unwrap();
			w.start_unilateral_exit().await.unwrap();
		},
		Cli::ClaimExit {  } => {
			let mut w = Wallet::open(cfg).await.unwrap();
			w.claim_unilateral_exit().await.unwrap();
		},

		// dev commands

		Cli::DropVtxos {  } => {
			let w = Wallet::open(cfg).await.unwrap();
			w.drop_vtxos().await.unwrap();
			info!("Dropped all vtxos");
		},
	}
}
