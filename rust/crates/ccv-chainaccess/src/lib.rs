//! Chain-agnostic read access to CCIP source chains.
//!
//! Rust port of the Go `pkg/chainaccess` interfaces (`SourceReader`, `HeadTracker`,
//! `RMNCurseReader`) plus the EVM implementation from
//! `integration/pkg/accessors/evm`, backed by Alloy.
//!
//! Differences from the Go signatures, by design:
//! - Block numbers are `u64` in and out. The Go interface takes `*big.Int` inputs
//!   while producing `uint64` outputs; the `big.Int` inputs were a geth passthrough,
//!   and both non-EVM implementations (Solana, Canton) immediately convert to `u64`.
//! - `toBlock == nil` ("query up to latest") is expressed as `Option<u64>::None`.
//! - `context.Context` is replaced by ordinary future cancellation.
//!
//! # Layering contract
//!
//! Implementations are stateless and hold no persistent state: durability
//! (processed-block checkpoints, task queues) lives strictly **above** this
//! interface, in the verifier service. Because there is no state, any
//! implementation can be shut down without notice (SIGKILL included) and cannot
//! end up in a bad state.
//!
//! Each implementation supports exactly one chain family (see
//! [`evm::EvmSourceReader`] for the EVM family and its called-out exceptions).

// Library code must never panic: all fallible operations return ChainAccessError
// (or ProtocolError). The lints below make that enforceable in non-test code.
#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)
)]

pub mod evm;

use std::collections::HashMap;

use alloy::primitives::FixedBytes;
use async_trait::async_trait;

use ccv_protocol::{BlockHeader, MessageSentEvent};

/// Errors returned by chain access implementations.
#[derive(Debug, thiserror::Error)]
pub enum ChainAccessError {
    #[error("RPC error: {0}")]
    Rpc(#[from] alloy::transports::RpcError<alloy::transports::TransportErrorKind>),
    #[error("contract call error: {0}")]
    Contract(#[from] alloy::contract::Error),
    #[error(transparent)]
    Protocol(#[from] ccv_protocol::ProtocolError),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("not found: {0}")]
    NotFound(String),
}

/// Access to the latest blockchain head information, taking finality
/// tags / finality depth into consideration. Mirrors `chainaccess.HeadTracker`.
#[async_trait]
pub trait HeadTracker: Send + Sync {
    /// Returns the latest and finalized block headers.
    async fn latest_and_finalized_block(&self) -> Result<(BlockHeader, BlockHeader), ChainAccessError>;

    /// Returns the latest block that is considered safe. On Ethereum this is the
    /// `safe` head — a checkpoint more recent than `finalized` but less final than
    /// `finalized`. Returns `None` without an error when the chain does not
    /// support the safe tag.
    async fn latest_safe_block(&self) -> Result<Option<BlockHeader>, ChainAccessError>;
}

/// Read-only access to RMN Remote curse state. Mirrors `chainaccess.RMNCurseReader`.
#[async_trait]
pub trait RmnCurseReader: Send + Sync {
    /// Queries the configured RMN Remote contract for cursed subjects
    /// (the global curse constant or chain selectors, as bytes16).
    async fn get_rmn_cursed_subjects(&self) -> Result<Vec<FixedBytes<16>>, ChainAccessError>;
}

/// Reads CCIP message events from source chains. Mirrors `chainaccess.SourceReader`.
///
/// All implementations must be safe for concurrent calls (satisfied by the
/// `Send + Sync` supertrait bounds).
#[async_trait]
pub trait SourceReader: HeadTracker + RmnCurseReader {
    /// Returns MessageSentEvents in the given block range, `[from_block, to_block]`.
    /// `to_block == None` queries up to the latest block.
    async fn fetch_message_sent_events(
        &self,
        from_block: u64,
        to_block: Option<u64>,
    ) -> Result<Vec<MessageSentEvent>, ChainAccessError>;

    /// Returns the full block headers for a batch of block numbers.
    ///
    /// If a block is not found or the RPC call fails for a specific block, it is
    /// omitted from the result. Callers should check that all requested blocks are
    /// present in the returned map.
    async fn get_blocks_headers(&self, block_numbers: &[u64]) -> Result<HashMap<u64, BlockHeader>, ChainAccessError>;
}
