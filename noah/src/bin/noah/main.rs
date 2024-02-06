
#[macro_use] extern crate log;

use std::{fs, process};
use std::path::PathBuf;

use anyhow::Context;
use bitcoin::{address, Address, Amount};
use bitcoin::secp256k1::PublicKey;
use clap::Parser;

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
		/// Force re-create the wallet even if it already exists.
		#[arg(long)]
		force: bool,
	},
	#[command()]
	GetAddress,
	/// The the public key used to receive vtxos.
	#[command()]
	GetVtxoPubkey,
	#[command()]
	Balance,
	#[command()]
	Onboard {
		amount: Amount,
	},
	#[command()]
	SendOnchain {
		address: Address<address::NetworkUnchecked>,
		amount: Amount,
	},
	#[command()]
	Send {
		pubkey: PublicKey,
		amount: Amount,
	},
	#[command()]
	OffboardAll,
	#[command()]
	StartExit,
	#[command()]
	ClaimExit,

	/// Dev command to drop the vtxo database.
	#[command()]
	DropVtxos,
}

async fn inner_main() -> anyhow::Result<()> {
	env_logger::builder()
		.target(env_logger::Target::Stderr)
		.filter_module("sled", log::LevelFilter::Warn)
		.filter_module("bitcoincore_rpc", log::LevelFilter::Debug)
		.filter_level(log::LevelFilter::Trace)
		.init();

	let cli = Cli::parse();

	//TODO(stevenroose) somehow pass this in
	let cfg = Config {
		network: bitcoin::Network::Regtest,
		datadir: {
			if !cli.datadir.exists() {
				fs::create_dir_all(&cli.datadir).context("failed to create datadir")?;
			}
			cli.datadir.canonicalize().context("canonicalizing path")?
		},
		asp_address: "http://[::1]:35035".parse().unwrap(),
		..Default::default()
	};

	// Handle create command differently.
	if let Command::Create { force } = cli.command {
		if force {
			fs::remove_dir_all(&cfg.datadir)?;
		}

		fs::create_dir_all(&cfg.datadir).context("failed to create datadir")?;
		let mut w = Wallet::create(cfg).await.context("error creating wallet")?;
		info!("Onchain address: {}", w.get_new_onchain_address()?);
		return Ok(());
	}

	let mut w = Wallet::open(cfg.clone()).await.context("error opening wallet")?;
	match cli.command {
		Command::Create { .. } => unreachable!(),
		Command::GetAddress => println!("{}", w.get_new_onchain_address()?),
		Command::GetVtxoPubkey => println!("{}", w.vtxo_pubkey()),
		Command::Balance => {
			info!("Onchain balance: {}", w.onchain_balance()?);
			info!("Offchain balance: {}", w.offchain_balance().await?);
			let (claimable, unclaimable) = w.unclaimed_exits().await?;
			if !claimable.is_empty() {
				let sum = claimable.iter().map(|i| i.spec.amount).sum::<Amount>();
				info!("Got {} claimable exits with total value of {}", claimable.len(), sum);
			}
			if !unclaimable.is_empty() {
				let sum = unclaimable.iter().map(|i| i.spec.amount).sum::<Amount>();
				info!("Got {} unclaimable exits with total value of {}", unclaimable.len(), sum);
			}
		},
		Command::Onboard { amount } => w.onboard(amount).await?,
		Command::SendOnchain { address, amount } => {
			let addr = address.require_network(cfg.network).with_context(|| {
				format!("address is not valid for configured network {}", cfg.network)
			})?;
			w.send_onchain(addr, amount)?;
		},
		Command::Send { pubkey, amount } => w.send_payment(pubkey, amount).await?,
		Command::OffboardAll => w.offboard_all().await?,
		Command::StartExit => w.start_unilateral_exit().await?,
		Command::ClaimExit => w.claim_unilateral_exit().await?,

		// dev commands

		Command::DropVtxos => {
			w.drop_vtxos().await?;
			info!("Dropped all vtxos");
		},
	}
	Ok(())
}

#[tokio::main]
async fn main() {
	if let Err(e) = inner_main().await {
		eprintln!("An error occurred: {}", e);
		// maybe hide second print behind a verbose flag
		eprintln!("");
		eprintln!("{:?}", e);
		process::exit(1);
	}
}
