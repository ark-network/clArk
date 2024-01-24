
use std::sync::Arc;

use bitcoin::Amount;
use bitcoin::secp256k1::PublicKey;
use tokio_stream::{Stream, StreamExt};
use tokio_stream::wrappers::BroadcastStream;

use ark::{musig, Destination, Vtxo, VtxoId};

use crate::App;
use crate::rpc;
use crate::round::{self, RoundEvent, RoundInput};

macro_rules! badarg {
	($($arg:tt)*) => {{
		tonic::Status::invalid_argument(format!($($arg)*))
	}};
}

macro_rules! internal {
	($($arg:tt)*) => {{
		tonic::Status::internal(format!($($arg)*))
	}};
}

macro_rules! not_found {
	($($arg:tt)*) => {{
		tonic::Status::not_found(format!($($arg)*))
	}};
}

/// Just a trait to easily convert some kind of errors to tonic things.
trait ToStatus<T> {
	fn to_status(self) -> Result<T, tonic::Status>;
}

impl<T> ToStatus<T> for anyhow::Result<T> {
	fn to_status(self) -> Result<T, tonic::Status> {
		self.map_err(|e| tonic::Status::internal(format!("internal error: {}", e)))
	}
}

#[tonic::async_trait]
impl rpc::ArkService for Arc<App> {
	async fn get_ark_info(
		&self,
		_req: tonic::Request<rpc::Empty>,
	) -> Result<tonic::Response<rpc::ArkInfo>, tonic::Status> {
		let ret = rpc::ArkInfo {
			pubkey: self.master_key.public_key().serialize().to_vec(),
			xonly_pubkey: self.master_key.public_key().x_only_public_key().0.serialize().to_vec(),
			nb_round_nonces: self.config.nb_round_nonces as u32,
		};
		Ok(tonic::Response::new(ret))
	}

	async fn request_onboard_cosign(
		&self,
		req: tonic::Request<rpc::OnboardCosignRequest>,
	) -> Result<tonic::Response<rpc::OnboardCosignResponse>, tonic::Status> {
		let req = req.into_inner();
		let user_part = ciborium::from_reader(&req.user_part[..])
			.map_err(|e| badarg!("invalid user part: {}", e))?;
		let asp_part = self.cosign_onboard(user_part);
		Ok(tonic::Response::new(rpc::OnboardCosignResponse {
			asp_part: {
				let mut buf = Vec::new();
				ciborium::into_writer(&asp_part, &mut buf).unwrap();
				buf
			},
		}))
	}

	async fn register_onboard_vtxo(
		&self,
		req: tonic::Request<rpc::RegisterOnboardVtxoRequest>,
	) -> Result<tonic::Response<rpc::Empty>, tonic::Status> {
		let vtxo = Vtxo::decode(&req.into_inner().vtxo).map_err(|e| badarg!("invalid vtxo: {}", e))?;
		//TODO(stevenroose) do sanity checks like to see if tx confirmed etc
		self.db.register_onboard_vtxo(vtxo).to_status()?;
		Ok(tonic::Response::new(rpc::Empty {}))
	}

	type SubscribeRoundsStream = Box<
		dyn Stream<Item = Result<rpc::RoundEvent, tonic::Status>> + Unpin + Send + 'static
	>;

	async fn subscribe_rounds(
		&self,
		_req: tonic::Request<rpc::Empty>,
	) -> Result<tonic::Response<Self::SubscribeRoundsStream>, tonic::Status> {
		let chan = self.round_event_tx.subscribe();
		let stream = BroadcastStream::new(chan);

		Ok(tonic::Response::new(Box::new(stream.map(|e| {
			let e = e.map_err(|e| internal!("broken stream: {}", e))?;
			Ok(rpc::RoundEvent {
				event: Some(match e {
					RoundEvent::Start { id } => {
						rpc::round_event::Event::Start(rpc::RoundStart {
							round_id: id,
						})
					},
					RoundEvent::Proposal {
						id, vtxos_spec, round_tx, vtxos_signers, vtxos_agg_nonces, forfeit_nonces,
					} => {
						rpc::round_event::Event::Proposal(rpc::RoundProposal {
							round_id: id,
							vtxos_spec: vtxos_spec.encode(),
							round_tx: bitcoin::consensus::serialize(&round_tx),
							vtxos_signers: vtxos_signers.into_iter().map(|k| k.serialize().to_vec()).collect(),
							vtxos_agg_nonces: vtxos_agg_nonces.into_iter().map(|n| n.serialize().to_vec()).collect(),
							forfeit_nonces: forfeit_nonces.into_iter().map(|(id, nonces)| {
								rpc::ForfeitNonces {
									input_vtxo_id: id.bytes().to_vec(),
									pub_nonces: nonces.into_iter().map(|n| n.serialize().to_vec()).collect(),
								}
							}).collect(),
						})
					},
					RoundEvent::Finished { id, vtxos, round_tx } => {
						rpc::round_event::Event::Finished(rpc::RoundFinished {
							round_id: id,
							signed_vtxos: vtxos.encode(),
							round_tx: bitcoin::consensus::serialize(&round_tx),
						})
					},
				})
			})
		}))))
	}

	async fn submit_payment(
		&self,
		req: tonic::Request<rpc::SubmitPaymentRequest>,
	) -> Result<tonic::Response<rpc::Empty>, tonic::Status> {
		let req = req.into_inner();

		let inputs =  req.input_vtxo_ids.into_iter().map(|id| {
			let id = VtxoId::from_slice(&id)
				.map_err(|e| badarg!("invalid vtxo id: {}", e))?;
			match self.db.get_vtxo(id) {
				Err(e) => Err(internal!("db error: {}", e)),
				Ok(None) => Err(not_found!("vtxo not found: {}", id)),
				Ok(Some(v)) => Ok(v)
			}
		}).collect::<Result<_, tonic::Status>>()?;

		let outputs = req.destinations.into_iter().map(|d| {
			Ok(Destination {
				amount: Amount::from_sat(d.amount),
				pubkey: PublicKey::from_slice(&d.public_key)
					.map_err(|e| badarg!("malformed pubkey {:?}: {}", d.public_key, e))?,
			})
		}).collect::<Result<_, tonic::Status>>()?;

		let cosign_pubkey = PublicKey::from_slice(&req.cosign_pubkey)
			.map_err(|e| badarg!("invalid cosign pubkey: {}", e))?;

		// Make sure we have at least enough nonces, but just drop
		// leftover if user provided too many.
		if req.public_nonces.len() < self.config.nb_round_nonces {
			return Err(badarg!(
				"need at least {} public nonces", self.config.nb_round_nonces,
			));
		}
		let public_nonces = req.public_nonces.into_iter()
		.take(self.config.nb_round_nonces)
		.map(|n| {
			musig::MusigPubNonce::from_slice(&n)
				.map_err(|e| badarg!("invalid public nonce: {}", e))
		}).collect::<Result<_, tonic::Status>>()?;

		let inp = RoundInput::RegisterPayment { inputs, outputs, cosign_pubkey, public_nonces };
		self.round_input_tx.send(inp).expect("input channel closed");
		Ok(tonic::Response::new(rpc::Empty {}))
	}

	async fn provide_signatures(
		&self,
		req: tonic::Request<rpc::RoundSignatures>,
	) -> Result<tonic::Response<rpc::Empty>, tonic::Status> {
		let req = req.into_inner();

		let forfeit = req.forfeit.into_iter().map(|forfeit| {
			let id = VtxoId::from_slice(&forfeit.input_vtxo_id)
				.map_err(|e| badarg!("invalid vtxo id: {}", e))?;
			let nonces = forfeit.pub_nonces.into_iter().map(|n| {
				musig::MusigPubNonce::from_slice(&n)
					.map_err(|e| badarg!("invalid forfeit nonce: {}", e))
			}).collect::<Result<_, tonic::Status>>()?;
			let signatures = forfeit.signatures.into_iter().map(|s| {
				musig::MusigPartialSignature::from_slice(&s)
					.map_err(|e| badarg!("invalid forfeit sig: {}", e))
			}).collect::<Result<_, tonic::Status>>()?;
			Ok((id, (nonces, signatures)))
		}).collect::<Result<_, tonic::Status>>()?;

		let vtxo = req.vtxo.ok_or_else(|| badarg!("vtxo signatures missing"))?;
		let inp = RoundInput::Signatures {
			vtxo_pubkey: PublicKey::from_slice(&vtxo.pubkey)
				.map_err(|e| badarg!("invalid pubkey: {}", e))?,
			vtxo_signatures: vtxo.signatures.into_iter().map(|s| {
				musig::MusigPartialSignature::from_slice(&s)
					.map_err(|e| badarg!("invalid signature: {}", e))
			}).collect::<Result<_, tonic::Status>>()?,
			forfeit: forfeit,
		};
		self.round_input_tx.send(inp).expect("input channel closed");
		Ok(tonic::Response::new(rpc::Empty {}))
	}
}

/// Run the public gRPC endpoint.
pub async fn run_public_rpc_server(app: Arc<App>) -> anyhow::Result<()> {
	let addr = app.config.public_rpc_address;
	let server = rpc::ArkServiceServer::new(app);
	tonic::transport::Server::builder()
		.add_service(server)
		.serve(addr)
		.await?;
	Ok(())
}
