
#[macro_use] extern crate log;

use std::fs;
use std::path::PathBuf;

use bitcoin::Amount;
use bitcoin::secp256k1::PublicKey;
use clap::Parser;

use ark::Destination;
use noah::{Wallet, Config};


#[derive(Parser)]
#[command(author = "Steven Roose <steven@roose.io>", version, about)]
struct Cli {
	/// The datadir of the noah wallet.
	#[arg(long, default_value = "./noah")]
	datadir: PathBuf,
	#[command(subcommand)]
	command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
	#[command()]
	Create {
		/// The directory in which to start the noah wallet.
		#[arg(long)]
		datadir: Option<PathBuf>,
		/// Force re-create the wallet even if it already exists.
		#[arg(long)]
		force: bool,
	},
	#[command()]
	GetAddress {},
	/// The the public key used to receive vtxos.
	#[command()]
	GetVtxoPubkey {},
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

	let cli = Cli::parse();

	//TODO(stevenroose) somehow pass this in
	let mut cfg = Config {
		network: bitcoin::Network::Regtest,
		datadir: cli.datadir.canonicalize().expect("canonicalizing path"),
		asp_address: "http://[::1]:35035".parse().unwrap(),
		..Default::default()
	};

	match cli.command {
		Command::Create { datadir, force } => {
			let datadir = if let Some(datadir) = datadir {
				fs::create_dir_all(&datadir).expect("failed to create datadir");
				datadir
			} else {
				cli.datadir
			}.canonicalize().expect("error canonicalizing datadir");

			if force {
				fs::remove_dir_all(&datadir).unwrap();
			}

			fs::create_dir_all(&datadir).expect("failed to create datadir");
			cfg.datadir = datadir;
			let mut w = Wallet::create(cfg).await.expect("error creating wallet");
			info!("Onchain address: {}", w.get_new_onchain_address().unwrap());
		},
		Command::GetAddress { } => {
			let mut w = Wallet::open(cfg).await.unwrap();
			info!("Onchain address: {}", w.get_new_onchain_address().unwrap());
		},
		Command::GetVtxoPubkey { } => {
			let w = Wallet::open(cfg).await.unwrap();
			info!("Vtxo pubkey: {}", w.vtxo_pubkey());
		}
		Command::Balance { } => {
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
		Command::Onboard { amount } => {
			let mut w = Wallet::open(cfg).await.unwrap();
			w.onboard(amount).await.unwrap();
		},
		Command::Send { pubkey, amount } => {
			let mut w = Wallet::open(cfg).await.unwrap();
			let dest = Destination { pubkey, amount };
			w.send_payment(dest).await.unwrap();
		},
		Command::StartExit {  } => {
			let mut w = Wallet::open(cfg).await.unwrap();
			w.start_unilateral_exit().await.unwrap();
		},
		Command::ClaimExit {  } => {
			let mut w = Wallet::open(cfg).await.unwrap();
			w.claim_unilateral_exit().await.unwrap();
		},

		// dev commands

		Command::DropVtxos {  } => {
			let w = Wallet::open(cfg).await.unwrap();
			w.drop_vtxos().await.unwrap();
			info!("Dropped all vtxos");
		},
	}
}
