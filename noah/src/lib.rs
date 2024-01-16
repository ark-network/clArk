#![allow(unused)]

mod onchain;

use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{bail, Context};
use bitcoin::{Address, Amount, Network};

use arkd_rpc_client::ArkServiceClient;


pub struct Config {
	pub network: Network,
	pub datadir: PathBuf,
	pub asp_address: String,
}

pub struct Wallet {
	config: Config,
	onchain: onchain::Wallet,
	asp: ArkServiceClient<tonic::transport::Channel>,
}

impl Wallet {
	/// Create new wallet.
	pub async fn create(config: Config) -> anyhow::Result<Wallet> {
		// create dir if not exit, but check that it's empty
		fs::create_dir_all(&config.datadir).context("can't create dir")?;
		if fs::read_dir(&config.datadir).context("can't read dir")?.next().is_some() {
			bail!("dir is not empty");
		}

		// generate seed
		let mnemonic = bip39::Mnemonic::generate(12).expect("12 is valid");

		// write it to file
		fs::write(config.datadir.join("mnemonic"), mnemonic.to_string().as_bytes())
			.context("failed to write mnemonic")?;

		// from then on we can open the wallet
		Ok(Wallet::open(config).await.context("failed to open")?)
	}

	/// Open existing wallet.
	pub async fn open(config: Config) -> anyhow::Result<Wallet> {
		// read mnemonic file
		let mnemonic_path = config.datadir.join("mnemonic");
		let mnemonic_str = fs::read_to_string(&mnemonic_path)
			.with_context(|| format!("failed to read mnemonic file at {}", mnemonic_path.display()))?;
		let mnemonic = bip39::Mnemonic::from_str(&mnemonic_str).context("broken mnemonic")?;

		// create on-chain wallet
		let seed = mnemonic.to_seed("");
		let onchain = onchain::Wallet::create(config.network, seed, &config.datadir)
			.context("failed to create onchain wallet")?;

		let asp_endpoint = tonic::transport::Uri::from_str(&config.asp_address)
			.context("invalid asp addr")?;
		let asp = ArkServiceClient::connect(asp_endpoint)
			.await.context("failed to connect to asp")?;

		Ok(Wallet { config, onchain, asp })
	}

	pub fn get_new_onchain_address(&mut self) -> anyhow::Result<Address> {
		self.onchain.new_address()
	}

	pub fn onchain_balance(&mut self) -> anyhow::Result<Amount> {
		self.onchain.sync()
	}
}
