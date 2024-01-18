
use std::sync::Arc;

use tokio_stream::{Stream, StreamExt};
use tokio_stream::wrappers::BroadcastStream;

use ark::Vtxo;

use crate::App;
use crate::rpc;
use crate::round::RoundEvent;

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
			pubkey: self.master_pubkey.serialize().to_vec(),
			xonly_pubkey: self.master_pubkey.x_only_public_key().0.serialize().to_vec(),
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
					RoundEvent::NewRound { id } => rpc::round_event::Event::NewRound(rpc::NewRoundEvent {
						round_id: id.to_le_bytes().to_vec(),
					}),
				})
			})
		}))))
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
