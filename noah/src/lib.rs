#![allow(unused)]

mod database;
mod onchain;


use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{bail, Context};
use bitcoin::{bip32, secp256k1};
use bitcoin::{Address, Amount, Network, OutPoint};
use bitcoin::secp256k1::PublicKey;

use arkd_rpc_client::ArkServiceClient;


lazy_static::lazy_static! {
	/// Global secp context.
	static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

pub struct Config {
	pub network: Network,
	pub datadir: PathBuf,
	pub asp_address: String,
}

pub struct Wallet {
	config: Config,
	db: database::Db,
	onchain: onchain::Wallet,
	asp: ArkServiceClient<tonic::transport::Channel>,
	vtxo_seed: bip32::ExtendedPrivKey,
	// ASP info
	asp_key: PublicKey,
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

		// open db
		let db = database::Db::open(&config.datadir.join("db")).context("failed to open db")?;

		let vtxo_seed = {
			let master = bip32::ExtendedPrivKey::new_master(config.network, &seed).unwrap();
			master.derive_priv(&SECP, &[350.into()]).unwrap()
		};

		let asp_endpoint = tonic::transport::Uri::from_str(&config.asp_address)
			.context("invalid asp addr")?;
		let mut asp = ArkServiceClient::connect(asp_endpoint)
			.await.context("failed to connect to asp")?;

		let ark_info = asp.get_ark_info(arkd_rpc_client::Empty{})
			.await.context("ark info request failed")?.into_inner();
		let asp_key = PublicKey::from_slice(&ark_info.pubkey).context("asp pubkey")?;

		Ok(Wallet { config, db, onchain, asp, vtxo_seed, asp_key })
	}

	pub fn get_new_onchain_address(&mut self) -> anyhow::Result<Address> {
		self.onchain.new_address()
	}

	pub fn onchain_balance(&mut self) -> anyhow::Result<Amount> {
		self.onchain.sync()
	}

	pub async fn onboard(&mut self, amount: Amount) -> anyhow::Result<()> {
		let key = self.vtxo_seed.derive_priv(&SECP, &[0.into()]).unwrap(); //TODO(stevenroose) fix
		let spec = ark::onboard::Spec {
			user_key: key.private_key.public_key(&SECP),
			asp_key: self.asp_key,
			expiry_delta: 14 * 144,
			exit_delta: 144,
			amount: amount,
		};
		let addr = Address::from_script(&ark::onboard::onboard_spk(&spec), self.config.network).unwrap();

		// We create the onboard tx template, but don't sign it yet.
		let onboard_tx = self.onchain.prepare_tx(addr, amount)?;
		let utxo = OutPoint::new(onboard_tx.unsigned_tx.txid(), 0);

		// We ask the ASP to cosign our onboard unlock tx.
		let (user_part, priv_user_part) = ark::onboard::new_user(spec, utxo);
		let asp_part = {
			let res = self.asp.request_onboard_cosign(arkd_rpc_client::OnboardCosignRequest {
				user_part: {
					let mut buf = Vec::new();
					ciborium::into_writer(&user_part, &mut buf).unwrap();
					buf
				},
			}).await.context("error requesting onboard cosign")?;
			ciborium::from_reader::<ark::onboard::AspPart, _>(&res.into_inner().asp_part[..])
				.context("invalid ASP part in response")?
		};

		// Store vtxo first before we actually make the on-chain tx.
		let vtxo = ark::onboard::finish(user_part, priv_user_part, asp_part, key.private_key); 
		self.db.store_vtxo(vtxo).context("db error storing vtxo")?;

		let tx = self.onchain.finish_tx(onboard_tx)?;
		self.onchain.broadcast_tx(&tx)?;

		Ok(())
	}
}
