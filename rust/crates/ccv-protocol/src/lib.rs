//! Chain-agnostic CCV protocol types and the canonical CCIP v1.7 message encoding.
//!
//! Rust port of the Go `protocol` package in this repository. Byte-level
//! compatibility with the Go implementation is enforced by golden-vector tests
//! generated from the Go code (see the `tests` modules).

pub mod message;
pub mod receipt;
pub mod types;

pub use message::{Message, TokenTransfer};
pub use receipt::{compute_ccv_and_executor_hash, parse_receipt_structure, validate_ccv_and_executor_hash, ReceiptStructure};
pub use types::{
    BlockHeader, ChainSelector, Finality, MessageSentEvent, ReceiptWithBlob, SequenceNumber, UnknownAddress,
    MAX_CCVS_PER_MESSAGE, MESSAGE_VERSION, MIN_SIZE_REQUIRED_MSG_FIELDS, MIN_SIZE_REQUIRED_MSG_TOKEN_FIELDS,
};

use alloy_primitives::B256;

/// Errors returned by message/token-transfer decoding and receipt validation.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("data too short: need at least {needed} bytes, got {got}")]
    DataTooShort { needed: usize, got: usize },
    #[error("unexpected end of data while reading {0}")]
    UnexpectedEof(&'static str),
    #[error("trailing bytes after decoding")]
    TrailingBytes,
    #[error("no receipt blobs to extract CCV and executor addresses from")]
    NoReceipts,
    #[error(
        "invalid receipt structure: insufficient receipts (got {got}, need at least {needed} for tokens + executor + network fee)"
    )]
    InsufficientReceipts { got: usize, needed: usize },
    #[error(
        "unexpected receipt count: got {got}, expected {expected} (CCVs={ccvs} + Tokens={tokens} + Executor=1 + Network fee=1)"
    )]
    UnexpectedReceiptCount { got: usize, expected: usize, ccvs: usize, tokens: usize },
    #[error("too many CCV addresses: {0} (max {MAX_CCVS_PER_MESSAGE})")]
    TooManyCcvs(usize),
    #[error("executor address length cannot be 0")]
    EmptyExecutorAddress,
    #[error("CCV address at index {index} has different length: got {got}, expected {expected}")]
    CcvAddressLengthMismatch { index: usize, got: usize, expected: usize },
    #[error("ccvAndExecutorHash mismatch: expected {expected}, got {got}")]
    CcvAndExecutorHashMismatch { expected: B256, got: B256 },
}
