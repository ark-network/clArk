
#[macro_use] extern crate anyhow;
#[macro_use] extern crate log;

use std::{env, fs, process};
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Context;
use bitcoin::{address, Address, Amount};
use bitcoin::secp256k1::PublicKey;
use clap::Parser;

use noah::{Wallet, Config};


fn default_datadir() -> String {
	home::home_dir().or_else(|| {
		env::current_dir().ok()
	}).unwrap_or_else(|| {
		"./".into()
	}).join(".noah").display().to_string()
}

#[derive(Parser)]
#[command(author = "Steven Roose <steven@roose.io>", version, about)]
struct Cli {
	/// Enable verbose logging.
	#[arg(long, short = 'v')]
	verbose: bool,
	/// The datadir of the noah wallet.
	#[arg(long, default_value_t = default_datadir())]
	datadir: String,
	#[command(subcommand)]
	command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
	/// Create a new wallet.
	///
	/// Configuration will pass in default values when --signet is used, but will
	/// require full configuration for regtest.
	#[command()]
	Create {
		/// Force re-create the wallet even if it already exists.
		#[arg(long)]
		force: bool,

		/// Use regtest network.
		#[arg(long)]
		regtest: bool,
		/// Use signet network.
		#[arg(long)]
		signet: bool,

		#[arg(long)]
		asp: Option<String>,

		/// The esplora HTTP API endpoint.
		#[arg(long)]
		esplora: Option<String>,
		#[arg(long)]
		bitcoind: Option<String>,
		#[arg(long)]
		bitcoind_user: Option<String>,
		#[arg(long)]
		bitcoind_pass: Option<String>,
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
	/// Send using the built-in on-chain wallet.
	#[command()]
	SendOnchain {
		address: Address<address::NetworkUnchecked>,
		amount: Amount,
	},
	/// Send money through Ark.
	#[command()]
	Send {
		/// Destination for the payment, this can either be an on-chain address
		/// or a public key for an Ark payment.
		destination: String,
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

async fn inner_main(cli: Cli) -> anyhow::Result<()> {
	let mut logbuilder = env_logger::builder();
	logbuilder.target(env_logger::Target::Stderr);
	if cli.verbose {
		logbuilder
			.filter_module("sled", log::LevelFilter::Warn)
			.filter_module("rustls", log::LevelFilter::Warn)
			.filter_module("reqwest", log::LevelFilter::Warn)
			.filter_module("bitcoincore_rpc", log::LevelFilter::Debug)
			.filter_level(log::LevelFilter::Trace);
	} else {
		logbuilder
			.filter_module("sled", log::LevelFilter::Off)
			.filter_module("rustls", log::LevelFilter::Off)
			.filter_module("reqwest", log::LevelFilter::Off)
			.filter_module("bitcoincore_rpc", log::LevelFilter::Off)
			.filter_level(log::LevelFilter::Warn);
	}
	logbuilder.init();

	let datadir = {
		let datadir = PathBuf::from(cli.datadir);
		if !datadir.exists() {
			fs::create_dir_all(&datadir).context("failed to create datadir")?;
		}
		datadir.canonicalize().context("canonicalizing path")?
	};

	// Handle create command differently.
	if let Command::Create {
		force, regtest, signet, mut asp, mut esplora, bitcoind, bitcoind_user, bitcoind_pass,
	} = cli.command {
		let net = if regtest && !signet {
			bitcoin::Network::Regtest
		} else if signet && !regtest {
			bitcoin::Network::Signet
		} else {
			bail!("Need to user either --signet and --regtest");
		};

		if signet {
			if asp.is_none() {
				//TODO(stevenroose) fill in our signet asp
				asp = Some("TODO(stevenroose) fill in our signet asp".into());
			}
			if esplora.is_none() && bitcoind.is_none() {
				esplora = Some("http://signet.21m.dev:3003".into());
			}
		}

		//TODO(stevenroose) somehow pass this in
		let cfg = Config {
			network: net,
			asp_address: asp.context("missing ASP address")?,
			esplora_address: esplora,
			bitcoind_address: bitcoind,
			bitcoind_user: bitcoind_user,
			bitcoind_pass: bitcoind_pass,
		};

		if force {
			fs::remove_dir_all(&datadir)?;
		}

		fs::create_dir_all(&datadir).context("failed to create datadir")?;
		let mut w = Wallet::create(&datadir, cfg).await.context("error creating wallet")?;
		info!("Onchain address: {}", w.get_new_onchain_address()?);
		return Ok(());
	}

	let mut w = Wallet::open(&datadir).await.context("error opening wallet")?;
	let net = w.config().network;

	match cli.command {
		Command::Create { .. } => unreachable!(),
		Command::GetAddress => println!("{}", w.get_new_onchain_address()?),
		Command::GetVtxoPubkey => println!("{}", w.vtxo_pubkey()),
		Command::Balance => {
			info!("Onchain balance: {}", w.onchain_balance().await?);
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
			let addr = address.require_network(net).with_context(|| {
				format!("address is not valid for configured network {}", net)
			})?;
			w.send_onchain(addr, amount).await?;
		},
		Command::Send { destination, amount } => {
			if let Ok(pk) = PublicKey::from_str(&destination) {
				debug!("Sending to Ark public key {}", pk);
				w.send_ark_payment(pk, amount).await?;
			} else if let Ok(addr) = Address::from_str(&destination) {
				let addr = addr.require_network(net).with_context(|| {
					format!("address is not valid for configured network {}", net)
				})?;
				debug!("Sending to on-chain address {}", addr);
				w.send_ark_onchain_payment(addr, amount).await?;
			} else {
				bail!("Invalid destination");
			}
		},
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
	let cli = Cli::parse();
	let verbose = cli.verbose;

	if let Err(e) = inner_main(cli).await {
		eprintln!("An error occurred: {}", e);
		if verbose {
			// maybe hide second print behind a verbose flag
			eprintln!("");
			eprintln!("{:?}", e);
		}
		process::exit(1);
	}
}
