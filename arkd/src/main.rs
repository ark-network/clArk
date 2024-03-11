
#[macro_use] extern crate log;

use std::{fs, process};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use bitcoin::{Amount, Network};
use clap::Parser;

use arkd::{App, Config};
use arkd_rpc_client as rpc;

const RPC_ADDR: &str = "[::]:35035";

#[derive(Parser)]
#[command(author = "Steven Roose <steven@roose.io>", version, about)]
struct Cli {
	#[arg(long, global = true)]
	datadir: Option<PathBuf>,
	#[command(subcommand)]
	command: Command,
}

#[derive(clap::Args)]
struct CreateOpts {
	#[arg(long, default_value = "regtest")]
	network: Network,
	#[arg(long)]
	bitcoind_url: String,
	#[arg(long)]
	bitcoind_cookie: String,
}

#[derive(clap::Subcommand)]
enum Command {
	#[command()]
	Create(CreateOpts),
	#[command()]
	Start,
	#[command()]
	GetMnemonic,
	#[command()]
	DropOorConflicts,
	#[command()]
	Rpc {
		#[command(subcommand)]
		cmd: RpcCommand,
		#[arg(long, default_value = RPC_ADDR)]
		addr: String,
	},
}

#[derive(clap::Subcommand)]
enum RpcCommand {
	#[command()]
	Balance,
	#[command()]
	GetAddress,
	/// Stop arkd.
	#[command()]
	Stop,
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

async fn inner_main() -> anyhow::Result<()> {
	let cli = Cli::parse();

	if let Command::Rpc { cmd, addr } = cli.command {
		env_logger::builder()
			.filter_level(log::LevelFilter::Trace)
			.init();

		return run_rpc(&addr, cmd).await;
	}

	env_logger::builder()
		.filter_module("bitcoincore_rpc", log::LevelFilter::Warn)
		.filter_module("rustls", log::LevelFilter::Warn)
		.filter_level(log::LevelFilter::Trace)
		.init();

	match cli.command {
		Command::Rpc { .. } => unreachable!(),
		Command::Create(opts) => {
			let datadir = {
				let datadir = PathBuf::from(cli.datadir.context("need datadir")?);
				if !datadir.exists() {
					fs::create_dir_all(&datadir).context("failed to create datadir")?;
				}
				datadir.canonicalize().context("canonicalizing path")?
			};

			let cfg = Config {
				network: opts.network,
				public_rpc_address: RPC_ADDR.parse().unwrap(),
				round_interval: Duration::from_secs(10),
				round_submit_time: Duration::from_secs(2),
				round_sign_time: Duration::from_secs(2),
				nb_round_nonces: 100,
				vtxo_expiry_delta: 1 * 24 * 6,
				vtxo_exit_delta: 2 * 6,
				bitcoind_url: opts.bitcoind_url,
				bitcoind_cookie: opts.bitcoind_cookie,
				..Default::default()
			};

			App::create(&datadir, cfg)?;
		},
		Command::Start => {
			let (app, jh) = App::start(&cli.datadir.context("need datadir")?).context("starting server")?;
			info!("arkd onchain address: {}", app.onchain_address().await?);
			if let Err(e) = jh.await? {
				error!("Shutdown error from arkd: {:?}", e);
				process::exit(1);
			}
		},
		Command::GetMnemonic => {
			let (app, _jh) = App::start(&cli.datadir.context("need datadir")?).context("starting server")?;
			println!("{}", app.get_master_mnemonic()?);
		},
		Command::DropOorConflicts => {
			let (app, _jh) = App::start(&cli.datadir.context("need datadir")?).context("starting server")?;
			app.drop_all_oor_conflicts()?;
		},
	}

	Ok(())
}

async fn run_rpc(addr: &str, cmd: RpcCommand) -> anyhow::Result<()> {
	let asp_endpoint = tonic::transport::Uri::from_str(&format!("http://{}", addr))
		.context("invalid asp addr")?;
	let mut asp = rpc::AdminServiceClient::connect(asp_endpoint)
		.await.context("failed to connect to asp")?;

	match cmd {
		RpcCommand::Balance => {
			let res = asp.wallet_status(rpc::Empty {}).await?.into_inner();
			println!("{}", Amount::from_sat(res.balance));
		},
		RpcCommand::GetAddress => {
			let res = asp.wallet_status(rpc::Empty {}).await?.into_inner();
			println!("{}", res.address);
		},
		RpcCommand::Stop => unimplemented!(),
	}
	Ok(())
}
