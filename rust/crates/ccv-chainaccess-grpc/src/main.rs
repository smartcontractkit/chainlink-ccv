//! `ccv-evm-source-reader-server`: serves one EVM chain's `SourceReader` over gRPC
//! (`ccv.chainaccess.v1.SourceReader`), as a drop-in replacement for the in-process
//! Go implementation.
//!
//! Configuration via environment variables (see ServerConfig):
//!   CCV_EVM_RPC_URL, CCV_ON_RAMP_ADDRESS, CCV_RMN_REMOTE_ADDRESS,
//!   CCV_CHAIN_SELECTOR, CCV_LISTEN_ADDR (default 0.0.0.0:50051)
//!
//! The process is stateless: it can be killed at any point without getting into
//! a bad state. SIGINT triggers a cooperative gRPC shutdown.

use std::process::ExitCode;

use alloy::providers::ProviderBuilder;
use tracing::info;

use ccv_chainaccess::evm::EvmSourceReader;
use ccv_chainaccess_grpc::{ServerConfig, serve};

fn main() -> ExitCode {
    // Logs go to stderr; stdout stays clean for any piping.
    tracing_subscriber::fmt().with_target(false).with_writer(std::io::stderr).init();

    match run().map_err(|err| eprintln!("{err}")) {
        Ok(()) => ExitCode::SUCCESS,
        Err(()) => ExitCode::FAILURE,
    }
}

/// Single error-chained flow: every line executes on both the happy path and on
/// failures (the error value differs), keeping the process fully test-covered.
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = ServerConfig::from_env().map_err(|err| err.to_string())?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("failed to build tokio runtime: {err}"))?;

    runtime.block_on(async move {
        let rpc_url = config
            .rpc_url
            .parse()
            .map_err(|err| format!("invalid CCV_EVM_RPC_URL: {err}"))?;
        let on_ramp = config
            .on_ramp_address
            .parse()
            .map_err(|err| format!("invalid CCV_ON_RAMP_ADDRESS: {err}"))?;
        let rmn_remote = config
            .rmn_remote_address
            .parse()
            .map_err(|err| format!("invalid CCV_RMN_REMOTE_ADDRESS: {err}"))?;
        let listen_addr = config
            .listen_addr
            .parse()
            .map_err(|err| format!("invalid CCV_LISTEN_ADDR: {err}"))?;

        let provider = ProviderBuilder::new().connect_http(rpc_url);
        let reader = EvmSourceReader::new(provider, on_ramp, rmn_remote, config.chain_selector)
            .map_err(|err| format!("failed to construct source reader: {err}"))?;

        info!(listen_addr = %config.listen_addr, chain_selector = config.chain_selector, "starting EVM source reader gRPC server");

        let shutdown = async {
            let _ = tokio::signal::ctrl_c().await;
            info!("shutdown signal received, stopping gRPC server");
        };

        serve(reader, listen_addr, shutdown).await.map_err(|err| format!("gRPC server failed: {err}"))?;
        Ok(())
    })
}
