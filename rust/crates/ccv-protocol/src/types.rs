use alloy_primitives::{B256, U256};

use crate::Message;

/// Chain selector as defined by CCIP.
pub type ChainSelector = u64;
/// Per-(source, dest) lane message sequence number.
pub type SequenceNumber = u64;
/// Requested finality depth/tag for a message.
pub type Finality = u32;

/// Address on an arbitrary chain (20 bytes for EVM, up to 255 bytes otherwise).
pub type UnknownAddress = Vec<u8>;

/// Current message format version (CCIP v1.7).
pub const MESSAGE_VERSION: u8 = 1;
/// Minimum size for the required fields in a canonical [`Message`] encoding.
pub const MIN_SIZE_REQUIRED_MSG_FIELDS: usize = 79;
/// Minimum size for the required fields in a canonical [`crate::TokenTransfer`] encoding.
pub const MIN_SIZE_REQUIRED_MSG_TOKEN_FIELDS: usize = 39;
/// Maximum number of CCV addresses per message (limited by uint8).
pub const MAX_CCVS_PER_MESSAGE: usize = 255;

/// Blockchain block header metadata.
///
/// `Number` is critical: it is used when querying for MessageSent events.
/// Hash/ParentHash are only used for reorg detection and finality violation detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockHeader {
    /// Block number of this block.
    pub number: u64,
    /// Block hash of this block.
    pub hash: B256,
    /// Block hash of the parent block.
    pub parent_hash: B256,
    /// Unix timestamp (seconds) of when the block was minted.
    pub timestamp: u64,
}

/// A CCIPMessageSent event from the blockchain.
///
/// Protocol-level representation of the OnRamp CCIPMessageSent event,
/// decoupled from chain-specific implementations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageSentEvent {
    /// Unique identifier for the message.
    pub message_id: B256,
    /// The decoded CCIP message.
    pub message: Message,
    /// Verifier receipts + executor receipt, in the original order emitted on-chain.
    pub receipts: Vec<ReceiptWithBlob>,
    /// Block number where the event occurred.
    pub block_number: u64,
    /// Transaction hash of the event.
    pub tx_hash: B256,
}

/// Chain-agnostic receipt with blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptWithBlob {
    pub issuer: UnknownAddress,
    pub blob: Vec<u8>,
    pub extra_args: Vec<u8>,
    pub dest_gas_limit: u64,
    pub dest_bytes_overhead: u32,
    pub fee_token_amount: U256,
}
