
#[macro_use] extern crate log;

use std::{env, fs, process};
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use bitcoin::Amount;
use clap::Parser;

use arkd::{App, Config};
use arkd_rpc_client as rpc;

#[derive(Parser)]
#[command(author = "Steven Roose <steven@roose.io>", version, about)]
struct Cli {
	#[command(subcommand)]
	command: Option<Command>,
}

#[derive(clap::Subcommand)]
enum Command {
	#[command()]
	Balance,
	#[command()]
	GetAddress,
    /// Stop arkd.
	#[command()]
	Stop,
}

const RPC_ADDR: &str = "[::1]:35035";

#[tokio::main]
async fn main() {
	let cli = Cli::parse();

    if let Some(cmd) = cli.command {
        if let Err(e) = run_command(cmd).await {
            eprintln!("An error occurred: {}", e);
            // maybe hide second print behind a verbose flag
            eprintln!("");
            eprintln!("{:?}", e);
            process::exit(1);
        }
    } else {
        env_logger::builder()
            .filter_module("sled", log::LevelFilter::Warn)
            .filter_module("bitcoincore_rpc", log::LevelFilter::Warn)
            .filter_level(log::LevelFilter::Trace)
            .init();

        let cfg = Config {
            network: bitcoin::Network::Regtest,
            public_rpc_address: RPC_ADDR.parse().unwrap(),
            datadir: env::current_dir().unwrap().join("test/arkd/"),
            round_interval: Duration::from_secs(10),
            round_submit_time: Duration::from_secs(2),
            round_sign_time: Duration::from_secs(2),
            nb_round_nonces: 100,
            vtxo_expiry_delta: 1 * 24 * 6,
            vtxo_exit_delta: 2 * 6,
            ..Default::default()
        };
        fs::create_dir_all(&cfg.datadir).expect("failed to create datadir");

        let (app, jh) = App::start(cfg).unwrap();
        info!("arkd onchain address: {}", app.onchain_address().await.unwrap());
        if let Err(e) = jh.await.unwrap() {
            error!("Shutdown error from arkd: {:?}", e);
            process::exit(1);
        }
    }
}

async fn run_command(cmd: Command) -> anyhow::Result<()> {
	env_logger::builder()
		.target(env_logger::Target::Stderr)
		.filter_module("sled", log::LevelFilter::Warn)
		.filter_module("bitcoincore_rpc", log::LevelFilter::Debug)
		.filter_level(log::LevelFilter::Trace)
		.init();

    let asp_endpoint = tonic::transport::Uri::from_str(&format!("http://{}", RPC_ADDR))
        .context("invalid asp addr")?;
    let mut asp = rpc::AdminServiceClient::connect(asp_endpoint)
        .await.context("failed to connect to asp")?;

	match cmd {
		Command::Balance => {
            let res = asp.wallet_status(rpc::Empty {}).await?.into_inner();
            println!("{}", Amount::from_sat(res.balance));
        },
		Command::GetAddress => {
            let res = asp.wallet_status(rpc::Empty {}).await?.into_inner();
            println!("{}", res.address);
        },
		Command::Stop => unreachable!(),
	}
	Ok(())
}
