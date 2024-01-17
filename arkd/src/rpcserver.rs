
use std::sync::Arc;

use crate::App;
use crate::rpc;

impl App {
	pub async fn start_public_rpc_server(self: &Arc<Self>) {
		let addr = self.config.public_rpc_address;
		let server = rpc::ArkServiceServer::new(self.clone());
		//TODO(stevenroose) capture thread so we can cancel later
		let _ = tokio::spawn(async move {
			tonic::transport::Server::builder()
				.add_service(server)
				.serve(addr)
				.await
		});
	}
}

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
}

