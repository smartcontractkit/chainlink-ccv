//! gRPC transport for [`ccv_chainaccess::SourceReader`].
//!
//! Exposes any `SourceReader` implementation as a `ccv.chainaccess.v1.SourceReader`
//! gRPC service, making it a drop-in replacement for the in-process Go
//! `chainaccess.SourceReader`. Stateless by construction: the service holds only
//! the reader, and the reader holds no persistent state, so the server can be
//! shut down without notice (SIGKILL included) without getting into a bad state.

// Library code must never panic: all fallible operations return Status.
#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)
)]

use std::collections::HashMap;
use std::sync::Arc;

use tonic::{Request, Response, Status};

use ccv_chainaccess::{ChainAccessError, SourceReader};
use ccv_protocol::{BlockHeader, MessageSentEvent};

pub mod pb {
    tonic::include_proto!("ccv.chainaccess.v1");
}

/// gRPC service adapter over any [`SourceReader`].
pub struct SourceReaderService<R> {
    reader: Arc<R>,
}

impl<R> SourceReaderService<R> {
    pub fn new(reader: Arc<R>) -> Self {
        Self { reader }
    }

    /// Tonic service wiring.
    pub fn into_server(self) -> pb::source_reader_server::SourceReaderServer<Self>
    where
        R: SourceReader + 'static,
    {
        pb::source_reader_server::SourceReaderServer::new(self)
    }
}

impl<R> Clone for SourceReaderService<R> {
    fn clone(&self) -> Self {
        Self { reader: Arc::clone(&self.reader) }
    }
}

/// Maps domain errors onto gRPC status codes:
/// invalid input -> INVALID_ARGUMENT, missing data -> NOT_FOUND,
/// upstream RPC transport failure -> UNAVAILABLE, everything else -> INTERNAL.
fn to_status(err: ChainAccessError) -> Status {
    match err {
        ChainAccessError::InvalidInput(msg) => Status::invalid_argument(msg),
        ChainAccessError::NotFound(msg) => Status::not_found(msg),
        ChainAccessError::Rpc(err) => Status::unavailable(format!("upstream RPC error: {err}")),
        other => Status::internal(other.to_string()),
    }
}

fn to_pb_header(h: &BlockHeader) -> pb::BlockHeader {
    pb::BlockHeader {
        number: h.number,
        hash: h.hash.to_vec(),
        parent_hash: h.parent_hash.to_vec(),
        timestamp: h.timestamp,
    }
}

#[allow(clippy::result_large_err)] // tonic::Status is the natural error type here
fn to_pb_event(e: &MessageSentEvent) -> Result<pb::MessageSentEvent, Status> {
    let encoded_message = e
        .message
        .encode()
        .map_err(|err| Status::internal(format!("failed to encode message: {err}")))?;
    Ok(pb::MessageSentEvent {
        message_id: e.message_id.to_vec(),
        encoded_message,
        receipts: e
            .receipts
            .iter()
            .map(|r| pb::ReceiptWithBlob {
                issuer: r.issuer.clone(),
                blob: r.blob.clone(),
                extra_args: r.extra_args.clone(),
                dest_gas_limit: r.dest_gas_limit,
                dest_bytes_overhead: r.dest_bytes_overhead,
                fee_token_amount: r.fee_token_amount.to_be_bytes::<32>().to_vec(),
            })
            .collect(),
        block_number: e.block_number,
        tx_hash: e.tx_hash.to_vec(),
    })
}

#[tonic::async_trait]
impl<R> pb::source_reader_server::SourceReader for SourceReaderService<R>
where
    R: SourceReader + 'static,
{
    async fn fetch_message_sent_events(
        &self,
        request: Request<pb::FetchMessageSentEventsRequest>,
    ) -> Result<Response<pb::FetchMessageSentEventsResponse>, Status> {
        let req = request.into_inner();
        let events = self
            .reader
            .fetch_message_sent_events(req.from_block, req.to_block)
            .await
            .map_err(to_status)?;
        let events = events.iter().map(to_pb_event).collect::<Result<Vec<_>, _>>()?;
        Ok(Response::new(pb::FetchMessageSentEventsResponse { events }))
    }

    async fn get_blocks_headers(
        &self,
        request: Request<pb::GetBlocksHeadersRequest>,
    ) -> Result<Response<pb::GetBlocksHeadersResponse>, Status> {
        let headers: HashMap<u64, BlockHeader> =
            self.reader.get_blocks_headers(&request.into_inner().block_numbers).await.map_err(to_status)?;
        let headers = headers.into_iter().map(|(k, v)| (k, to_pb_header(&v))).collect();
        Ok(Response::new(pb::GetBlocksHeadersResponse { headers }))
    }

    async fn latest_and_finalized_block(
        &self,
        _request: Request<pb::LatestAndFinalizedBlockRequest>,
    ) -> Result<Response<pb::LatestAndFinalizedBlockResponse>, Status> {
        let (latest, finalized) = self.reader.latest_and_finalized_block().await.map_err(to_status)?;
        Ok(Response::new(pb::LatestAndFinalizedBlockResponse {
            latest: Some(to_pb_header(&latest)),
            finalized: Some(to_pb_header(&finalized)),
        }))
    }

    async fn latest_safe_block(
        &self,
        _request: Request<pb::LatestSafeBlockRequest>,
    ) -> Result<Response<pb::LatestSafeBlockResponse>, Status> {
        let safe = self.reader.latest_safe_block().await.map_err(to_status)?;
        Ok(Response::new(pb::LatestSafeBlockResponse { safe: safe.as_ref().map(to_pb_header) }))
    }

    async fn get_rmn_cursed_subjects(
        &self,
        _request: Request<pb::GetRmnCursedSubjectsRequest>,
    ) -> Result<Response<pb::GetRmnCursedSubjectsResponse>, Status> {
        let subjects = self.reader.get_rmn_cursed_subjects().await.map_err(to_status)?;
        Ok(Response::new(pb::GetRmnCursedSubjectsResponse {
            subjects: subjects.iter().map(|s| s.to_vec()).collect(),
        }))
    }
}

/// Server configuration. One process serves exactly one chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    /// JSON-RPC HTTP endpoint of the EVM node.
    pub rpc_url: String,
    /// OnRamp contract address (hex, 0x-prefixed).
    pub on_ramp_address: String,
    /// RMN Remote contract address (hex, 0x-prefixed).
    pub rmn_remote_address: String,
    /// CCIP chain selector of the chain this instance serves.
    pub chain_selector: u64,
    /// gRPC listen address, e.g. "0.0.0.0:50051".
    pub listen_addr: String,
}

impl ServerConfig {
    /// Builds a config from key/value pairs (used by [`ServerConfig::from_env`]).
    /// Missing or malformed entries are collected and returned as one error.
    pub fn from_pairs<K: AsRef<str>, V: AsRef<str>>(
        pairs: impl IntoIterator<Item = (K, V)>,
    ) -> Result<Self, ConfigError> {
        let mut map = HashMap::new();
        for (k, v) in pairs {
            map.insert(k.as_ref().to_string(), v.as_ref().to_string());
        }
        let get = |key: &str| map.get(key).map(String::as_str).unwrap_or("").trim().to_string();

        let mut errs = Vec::new();
        let rpc_url = get("CCV_EVM_RPC_URL");
        if rpc_url.is_empty() {
            errs.push("CCV_EVM_RPC_URL is not set".to_string());
        }
        let on_ramp_address = get("CCV_ON_RAMP_ADDRESS");
        if on_ramp_address.is_empty() {
            errs.push("CCV_ON_RAMP_ADDRESS is not set".to_string());
        }
        let rmn_remote_address = get("CCV_RMN_REMOTE_ADDRESS");
        if rmn_remote_address.is_empty() {
            errs.push("CCV_RMN_REMOTE_ADDRESS is not set".to_string());
        }
        let chain_selector = match get("CCV_CHAIN_SELECTOR").parse::<u64>() {
            Ok(0) => {
                errs.push("CCV_CHAIN_SELECTOR must be non-zero".to_string());
                0
            }
            Ok(v) => v,
            Err(_) => {
                errs.push("CCV_CHAIN_SELECTOR is not a valid u64".to_string());
                0
            }
        };
        let listen_addr = match get("CCV_LISTEN_ADDR").as_str() {
            "" => "0.0.0.0:50051".to_string(),
            v => v.to_string(),
        };

        if errs.is_empty() {
            Ok(Self { rpc_url, on_ramp_address, rmn_remote_address, chain_selector, listen_addr })
        } else {
            Err(ConfigError(errs))
        }
    }

    /// Builds a config from process environment variables.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_pairs(ENV_KEYS.iter().map(|&k| (k, std::env::var(k).unwrap_or_default())))
    }
}

const ENV_KEYS: [&str; 5] = [
    "CCV_EVM_RPC_URL",
    "CCV_ON_RAMP_ADDRESS",
    "CCV_RMN_REMOTE_ADDRESS",
    "CCV_CHAIN_SELECTOR",
    "CCV_LISTEN_ADDR",
];

/// Aggregated configuration errors.
#[derive(Debug, thiserror::Error)]
#[error("invalid server configuration: {}", .0.join("; "))]
pub struct ConfigError(Vec<String>);

impl ConfigError {
    /// The individual problems found.
    pub fn problems(&self) -> &[String] {
        &self.0
    }
}

/// Runs the gRPC server until `shutdown` resolves or the process is signalled.
///
/// The server is stateless: persistence lives above this interface (in the
/// verifier service), so an ungraceful shutdown cannot corrupt anything. The
/// `shutdown` future exists for cooperative shutdown (e.g. SIGTERM handling in
/// `main`); a hard kill is equally safe.
pub async fn serve<R, F>(reader: R, listen_addr: std::net::SocketAddr, shutdown: F) -> Result<(), tonic::transport::Error>
where
    R: SourceReader + 'static,
    F: std::future::Future<Output = ()> + Send,
{
    let service = SourceReaderService::new(Arc::new(reader));
    tonic::transport::Server::builder()
        .add_service(service.into_server())
        .serve_with_shutdown(listen_addr, shutdown)
        .await
}
