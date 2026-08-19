//! EVM implementation of [`SourceReader`] using Alloy.
//!
//! Behavioral port of the Go implementation in
//! `integration/pkg/accessors/evm/evm_source_reader.go`:
//! - same `eth_getLogs` filter (OnRamp address + CCIPMessageSent topic0)
//! - same per-event validation pipeline, including the critical-invariant hook
//!   and the skip-on-violation semantics
//! - same header/head/safe-block lookups
//! - same RMN Remote `getCursedSubjects()` call

// The sol!-generated event type mirrors the on-chain event's 8 fields.
#![allow(clippy::too_many_arguments)]

use std::collections::HashMap;
use std::sync::Arc;

use alloy::eips::BlockNumberOrTag;
use alloy::primitives::{Address, B256, FixedBytes};
use alloy::providers::Provider;
use alloy::rpc::types::{Block, Filter, Log};
use alloy::sol;
use alloy::sol_types::SolEvent;
use async_trait::async_trait;
use tracing::{debug, error, warn};

use ccv_protocol::{
    BlockHeader, Message, MessageSentEvent, ReceiptWithBlob, validate_ccv_and_executor_hash,
};

use crate::{ChainAccessError, HeadTracker, RmnCurseReader, SourceReader};

sol! {
    /// Subset of the OnRamp contract: the CCIPMessageSent event and its Receipt struct.
    /// Event layout must match the Go bindings
    /// (chainlink-ccip/chains/evm/gobindings/generated/latest/onramp) byte for byte.
    #[sol(rpc)]
    interface OnRamp {
        struct Receipt {
            address issuer;
            uint32 destGasLimit;
            uint32 destBytesOverhead;
            uint256 feeTokenAmount;
            bytes extraArgs;
        }

        event CCIPMessageSent(
            uint64 indexed destChainSelector,
            address indexed sender,
            bytes32 indexed messageId,
            address feeToken,
            uint256 tokenAmountBeforeTokenPoolFees,
            bytes encodedMessage,
            Receipt[] receipts,
            bytes[] verifierBlobs
        );
    }

    /// Subset of RMN Remote (chainlink-ccip v1_6_0 bindings).
    #[sol(rpc)]
    interface RMNRemote {
        function getCursedSubjects() external view returns (bytes16[] subjects);
    }
}

/// Minimum receipts: 1 CCV + executor + network fee.
const MIN_RECEIPTS: usize = 3;

/// Why an event log was skipped. Mirrors every `continue` path in the Go
/// implementation (`evm_source_reader.go`); [`SkipReason::fires_critical_invariant`]
/// records whether the Go code invokes its `onCriticalInvariant` hook for the path.
///
/// Exposed (rather than kept internal) so differential tests can compare skip
/// causes against the Go implementation event by event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// Topics/ABI decoding failed (includes fewer than 4 topics).
    MalformedEvent,
    /// Fewer than 3 receipts (1 CCV + executor + network fee).
    InsufficientReceipts,
    /// Canonical message decoding failed.
    UndecodableMessage,
    /// `ccvAndExecutorHash` is zero in the decoded message.
    ZeroCcvAndExecutorHash,
    /// Message `onRampAddress` != configured OnRamp address.
    OnRampAddressMismatch,
    /// Message `sender` != the event's sender topic.
    SenderMismatch,
    /// Recomputed message ID != the event's messageId topic.
    MessageIdMismatch,
    /// Message `destChainSelector` != the event's destChainSelector topic.
    DestChainSelectorMismatch,
    /// Receipt-derived `ccvAndExecutorHash` != the hash embedded in the message.
    CcvAndExecutorHashValidation,
}

impl SkipReason {
    /// Whether the Go implementation fires its `onCriticalInvariant` hook on this path.
    /// Every path does except [`SkipReason::CcvAndExecutorHashValidation`].
    pub fn fires_critical_invariant(self) -> bool {
        !matches!(self, SkipReason::CcvAndExecutorHashValidation)
    }

    /// Stable machine-readable code, kept in sync with the Go differential harness
    /// (`rust/differential-go/main.go`).
    pub fn code(self) -> &'static str {
        match self {
            SkipReason::MalformedEvent => "malformed_event",
            SkipReason::InsufficientReceipts => "insufficient_receipts",
            SkipReason::UndecodableMessage => "undecodable_message",
            SkipReason::ZeroCcvAndExecutorHash => "zero_hash",
            SkipReason::OnRampAddressMismatch => "onramp_mismatch",
            SkipReason::SenderMismatch => "sender_mismatch",
            SkipReason::MessageIdMismatch => "id_mismatch",
            SkipReason::DestChainSelectorMismatch => "dest_mismatch",
            SkipReason::CcvAndExecutorHashValidation => "hash_validation",
        }
    }
}

/// EVM [`SourceReader`] backed by an Alloy [`Provider`].
///
/// Stateless: every method hits the RPC endpoint, like the Go implementation.
/// Cheap to clone if `P` is (e.g. `RootProvider`/`DynProvider` are `Arc` internally),
/// and safe for concurrent use.
///
/// # Chain family support
///
/// This implementation covers the **EVM chain family**: any chain exposing the
/// standard `eth_*` JSON-RPC API (`eth_getLogs`, `eth_getBlockByNumber` with the
/// `latest`/`safe`/`finalized` tags, `eth_call`). One instance serves exactly one
/// chain; deploy one instance per chain. The event format is the CCIP v2 OnRamp
/// `CCIPMessageSent` (identical across EVM chains).
///
/// Explicitly called-out exceptions within the family:
/// - Chains without the `safe` tag (e.g. BSC): [`HeadTracker::latest_safe_block`]
///   returns `Ok(None)`. This is a supported configuration, matching the Go behavior.
/// - Chains without the `finalized` tag are **not** supported:
///   [`HeadTracker::latest_and_finalized_block`] fails. Such chains need a
///   finality-depth shim above this layer.
pub struct EvmSourceReader<P> {
    provider: P,
    on_ramp_address: Address,
    rmn_remote_address: Address,
    chain_selector: u64,
    /// Invoked on every critical-invariant violation (malformed events, message
    /// fields disagreeing with the on-chain event, ...). Mirrors the Go
    /// `onCriticalInvariant` callback; violations are also logged and the offending
    /// event is skipped.
    on_critical_invariant: Arc<dyn Fn() + Send + Sync>,
}

impl<P: Provider> EvmSourceReader<P> {
    /// Creates a new reader, validating the same inputs as the Go constructor.
    pub fn new(
        provider: P,
        on_ramp_address: Address,
        rmn_remote_address: Address,
        chain_selector: u64,
    ) -> Result<Self, ChainAccessError> {
        if on_ramp_address.is_zero() {
            return Err(ChainAccessError::InvalidInput("onRampAddress is not set".into()));
        }
        if rmn_remote_address.is_zero() {
            return Err(ChainAccessError::InvalidInput("rmnRemoteAddress is not set".into()));
        }
        if chain_selector == 0 {
            return Err(ChainAccessError::InvalidInput("chainSelector is not set".into()));
        }
        Ok(Self {
            provider,
            on_ramp_address,
            rmn_remote_address,
            chain_selector,
            on_critical_invariant: Arc::new(|| {}),
        })
    }

    /// Installs the critical-invariant hook (default: no-op).
    pub fn with_critical_invariant_hook(mut self, hook: impl Fn() + Send + Sync + 'static) -> Self {
        self.on_critical_invariant = Arc::new(hook);
        self
    }

    fn critical_invariant(&self) {
        (self.on_critical_invariant)()
    }

    /// Decodes a raw log into the CCIPMessageSent event with go-ethereum-exact
    /// semantics (the Go implementation decodes via geth):
    ///
    /// - topics: masked reads (destChainSelector u64 from the last 8 bytes of
    ///   topic1, sender from the last 20 bytes of topic2, messageId = topic3) —
    ///   no range checks, identical to the Go code.
    /// - body: bounds-checked ABI decode (offsets, length prefixes), tolerant of
    ///   trailing garbage — identical to geth's `abi.Unpack`.
    /// - uint32 fields (receipt destGasLimit/destBytesOverhead): geth
    ///   range-checks the raw words while Alloy's lenient sequence decode masks
    ///   them, so the raw receipt-head words are checked explicitly for parity.
    ///
    /// The only intentional divergence: topic0 is verified against the event
    /// signature. The Go inner loop never observes a wrong topic0 (the
    /// eth_getLogs filter pins it), so this only hardens direct `check_log` calls.
    fn decode_event(&self, log: &Log) -> Result<OnRamp::CCIPMessageSent, SkipReason> {
        // Go: len(log.Topics) < 4 -> invariant + skip. The slice pattern subsumes
        // the arity check: fewer than 4 topics is malformed.
        let [topic0, topic1, topic2, topic3, ..] = log.inner.data.topics() else {
            return Err(SkipReason::MalformedEvent);
        };

        if *topic0 != OnRamp::CCIPMessageSent::SIGNATURE_HASH {
            return Err(SkipReason::MalformedEvent);
        }

        // Masked topic reads, identical to the Go code (topics are always 32 bytes):
        // destChainSelector = last 8 bytes of topic1, sender = last 20 bytes of topic2.
        let t1: [u8; 32] = (*topic1).into();
        let dest_chain_selector = t1.iter().skip(24).fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
        let t2: [u8; 32] = (*topic2).into();
        let sender = Address::from_slice(t2.split_at(12).1);
        let message_id = *topic3;

        let data: &[u8] = &log.inner.data.data;
        let (fee_token, token_amount, encoded_message, receipts, verifier_blobs) =
            <OnRamp::CCIPMessageSent as SolEvent>::abi_decode_data(data)
                .map_err(|_| SkipReason::MalformedEvent)?;

        if receipts_have_uint32_overflow(data)? {
            return Err(SkipReason::MalformedEvent);
        }

        Ok(OnRamp::CCIPMessageSent {
            destChainSelector: dest_chain_selector,
            sender,
            messageId: message_id,
            feeToken: fee_token,
            tokenAmountBeforeTokenPoolFees: token_amount,
            encodedMessage: encoded_message,
            receipts,
            verifierBlobs: verifier_blobs,
        })
    }

    /// Applies the Go per-event validation pipeline to a single log. Public so
    /// callers (and the differential tests) can validate individual logs against
    /// the Go implementation's skip semantics.
    ///
    /// Returns `Err(reason)` when the event must be skipped (every skip mirrors a
    /// Go `continue` path, including whether the critical-invariant hook fires).
    ///
    /// Note: unlike the Go inner loop, this also validates the topic0 signature
    /// (`MalformedEvent` on mismatch). This is unreachable through
    /// `fetch_message_sent_events`, where the RPC filter already pins topic0 —
    /// it only hardens direct calls with arbitrary logs.
    pub fn check_log(&self, log: &Log) -> Result<MessageSentEvent, SkipReason> {
        let event = match self.decode_event(log) {
            Ok(event) => event,
            Err(reason) => {
                if reason.fires_critical_invariant() {
                    self.critical_invariant();
                }
                error!(
                    chain_selector = self.chain_selector,
                    reason = reason.code(),
                    block_number = log.block_number.unwrap_or_default(),
                    tx_hash = ?log.transaction_hash.unwrap_or_default(),
                    "CCIPMessageSent event failed topic/ABI validation",
                );
                return Err(reason);
            }
        };

        debug!(
            chain_selector = self.chain_selector,
            block_number = log.block_number.unwrap_or_default(),
            tx_hash = ?log.transaction_hash.unwrap_or_default(),
            "Found CCIPMessageSent event",
        );

        if event.receipts.len() < MIN_RECEIPTS {
            self.critical_invariant();
            error!(
                message_id = ?event.messageId,
                count = event.receipts.len(),
                "Insufficient receipts. Expected at least 3 (1 CCV + executor + network fees)",
            );
            return Err(SkipReason::InsufficientReceipts);
        }

        let message = match Message::decode(&event.encodedMessage) {
            Ok(m) => m,
            Err(err) => {
                self.critical_invariant();
                error!(message_id = ?event.messageId, error = %err, "Failed to decode message");
                return Err(SkipReason::UndecodableMessage);
            }
        };

        if message.ccv_and_executor_hash == B256::ZERO {
            self.critical_invariant();
            error!(
                message_id = ?event.messageId,
                block_number = log.block_number.unwrap_or_default(),
                "ccvAndExecutorHash is zero in decoded message",
            );
            return Err(SkipReason::ZeroCcvAndExecutorHash);
        }

        // The on-chain event emits 20-byte EVM addresses; the canonical message
        // stores them left-padded to 32 bytes (Go: expectedSourceAddressBytes).
        if message.on_ramp_address != left_pad_32(&self.on_ramp_address) {
            self.critical_invariant();
            error!(
                message_id = ?event.messageId,
                "onRampAddress must match the value configured — critical invariant violated; escalate immediately",
            );
            return Err(SkipReason::OnRampAddressMismatch);
        }

        if message.sender != left_pad_32(&event.sender) {
            self.critical_invariant();
            error!(
                message_id = ?event.messageId,
                "sender must match the value emitted from the on-chain event. This should never happen.",
            );
            return Err(SkipReason::SenderMismatch);
        }

        // Go uses MustMessageID (zero on encode error), so an encode failure lands
        // on the same mismatch path as a wrong ID.
        let computed_id = message.message_id().unwrap_or_default();
        if computed_id != event.messageId {
            self.critical_invariant();
            error!(
                message_id = ?event.messageId,
                computed = ?computed_id,
                "computed messageID must match the value emitted from the on-chain event — critical invariant violated",
            );
            return Err(SkipReason::MessageIdMismatch);
        }

        if message.dest_chain_selector != event.destChainSelector {
            self.critical_invariant();
            error!(
                message_id = ?event.messageId,
                "destination chain selector must match the value emitted from the on-chain event. This should never happen",
            );
            return Err(SkipReason::DestChainSelectorMismatch);
        }

        // Pair each receipt with its verifier blob: only CCV receipts
        // (the first len(verifierBlobs)) have blobs.
        let receipts: Vec<ReceiptWithBlob> = event
            .receipts
            .iter()
            .enumerate()
            .map(|(i, r)| ReceiptWithBlob {
                issuer: r.issuer.to_vec(),
                blob: event.verifierBlobs.get(i).map(|b| b.to_vec()).unwrap_or_default(),
                extra_args: r.extraArgs.to_vec(),
                dest_gas_limit: u64::from(r.destGasLimit),
                dest_bytes_overhead: r.destBytesOverhead,
                fee_token_amount: r.feeTokenAmount,
            })
            .collect();

        // Note: like the Go code, this failure logs but does NOT fire the
        // critical-invariant hook (see SkipReason::fires_critical_invariant).
        if let Err(err) = validate_ccv_and_executor_hash(&message, &receipts) {
            error!(
                message_id = ?event.messageId,
                block_number = log.block_number.unwrap_or_default(),
                error = %err,
                "ccvAndExecutorHash validation failed",
            );
            return Err(SkipReason::CcvAndExecutorHashValidation);
        }

        Ok(MessageSentEvent {
            message_id: event.messageId,
            message,
            receipts,
            block_number: log.block_number.unwrap_or_default(),
            tx_hash: log.transaction_hash.unwrap_or_default(),
        })
    }
}

#[async_trait]
impl<P: Provider> SourceReader for EvmSourceReader<P> {
    async fn fetch_message_sent_events(
        &self,
        from_block: u64,
        to_block: Option<u64>,
    ) -> Result<Vec<MessageSentEvent>, ChainAccessError> {
        let filter = Filter::new()
            .address(self.on_ramp_address)
            .event_signature(OnRamp::CCIPMessageSent::SIGNATURE_HASH)
            .from_block(BlockNumberOrTag::Number(from_block))
            // Go passes a nil ToBlock to geth, which the node treats as "latest".
            .to_block(to_block.map_or(BlockNumberOrTag::Latest, BlockNumberOrTag::Number));

        let logs = self.provider.get_logs(&filter).await.inspect_err(|err| {
            warn!(error = %err, "Failed to filter logs");
        })?;

        Ok(logs.iter().filter_map(|log| self.check_log(log).ok()).collect())
    }

    async fn get_blocks_headers(
        &self,
        block_numbers: &[u64],
    ) -> Result<HashMap<u64, BlockHeader>, ChainAccessError> {
        // TODO: batch requests for efficiency (mirrors Go ticket CCIP-7766).
        let mut headers = HashMap::with_capacity(block_numbers.len());
        for &number in block_numbers {
            match self
                .provider
                .get_block_by_number(BlockNumberOrTag::Number(number))
                .await
            {
                Ok(Some(block)) => {
                    headers.insert(number, header_from_block(&block));
                }
                Ok(None) => {
                    warn!(block_number = number, "Block not found, omitting from result");
                }
                Err(err) => {
                    warn!(block_number = number, error = %err, "Failed to get block header");
                }
            }
        }
        Ok(headers)
    }
}

#[async_trait]
impl<P: Provider> HeadTracker for EvmSourceReader<P> {
    async fn latest_and_finalized_block(&self) -> Result<(BlockHeader, BlockHeader), ChainAccessError> {
        let latest = self
            .provider
            .get_block_by_number(BlockNumberOrTag::Latest)
            .await?;
        let finalized = self
            .provider
            .get_block_by_number(BlockNumberOrTag::Finalized)
            .await?;

        match (latest, finalized) {
            (Some(latest), Some(finalized)) => Ok((header_from_block(&latest), header_from_block(&finalized))),
            _ => Err(ChainAccessError::NotFound("received nil head from tracker".into())),
        }
    }

    async fn latest_safe_block(&self) -> Result<Option<BlockHeader>, ChainAccessError> {
        match self
            .provider
            .get_block_by_number(BlockNumberOrTag::Safe)
            .await
        {
            Ok(Some(block)) => Ok(Some(header_from_block(&block))),
            // Chain does not support the safe tag: Go returns nil without an error.
            Ok(None) => Ok(None),
            Err(err) => {
                debug!(error = %err, "safe block tag unsupported or unavailable");
                Ok(None)
            }
        }
    }
}

#[async_trait]
impl<P: Provider> RmnCurseReader for EvmSourceReader<P> {
    async fn get_rmn_cursed_subjects(&self) -> Result<Vec<FixedBytes<16>>, ChainAccessError> {
        let rmn_remote = RMNRemote::new(self.rmn_remote_address, &self.provider);
        let subjects = rmn_remote.getCursedSubjects().call().await?;
        Ok(subjects)
    }
}

fn header_from_block(block: &Block) -> BlockHeader {
    BlockHeader {
        number: block.header.number,
        hash: block.header.hash,
        parent_hash: block.header.parent_hash,
        timestamp: block.header.timestamp,
    }
}

/// Left-pads a 20-byte EVM address to 32 bytes, matching how addresses appear
/// in the canonical message encoding (Go: common.LeftPadBytes).
fn left_pad_32(address: &Address) -> Vec<u8> {
    let mut out = vec![0u8; 12];
    out.extend_from_slice(address.as_slice());
    out
}

/// Replicates go-ethereum's uint32 range checks on the raw ABI words of every
/// receipt's `destGasLimit` and `destBytesOverhead` fields. geth rejects a
/// receipt whose uint32 word has any of the top 28 bytes set; Alloy's lenient
/// sequence decode masks those bits instead, so without this check the two
/// implementations disagree on corrupted data.
///
/// Must only be called after a successful bounds-checked decode of `data`
/// (which guarantees the offsets walked here are in range); all accessors stay
/// checked regardless.
fn receipts_have_uint32_overflow(data: &[u8]) -> Result<bool, SkipReason> {
    let word = |pos: usize| -> Result<&[u8], SkipReason> {
        data.get(pos..pos.saturating_add(32)).ok_or(SkipReason::MalformedEvent)
    };
    // Reads a 32-byte word as a usize offset/length. Nonzero bytes above the low
    // 8 are unreachable after a successful decode; rejected defensively.
    let usize_at = |pos: usize| -> Result<usize, SkipReason> {
        let w = word(pos)?;
        if w.iter().take(24).any(|&b| b != 0) {
            return Err(SkipReason::MalformedEvent);
        }
        let tail = w.get(24..32).ok_or(SkipReason::MalformedEvent)?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(tail);
        Ok(u64::from_be_bytes(arr) as usize)
    };

    // Event data head: word0 feeToken, word1 tokenAmount, word2 encodedMessage
    // offset, word3 receipts offset, word4 verifierBlobs offset.
    let receipts_area = usize_at(96)?;
    let count = usize_at(receipts_area)?;
    let elems_base = receipts_area.checked_add(32).ok_or(SkipReason::MalformedEvent)?;

    for i in 0..count {
        let offset_word_pos = elems_base
            .checked_add(i.checked_mul(32).ok_or(SkipReason::MalformedEvent)?)
            .ok_or(SkipReason::MalformedEvent)?;
        let elem_offset = usize_at(offset_word_pos)?;
        let head = elems_base.checked_add(elem_offset).ok_or(SkipReason::MalformedEvent)?;
        // Receipt tuple head: word0 issuer, word1 destGasLimit, word2
        // destBytesOverhead, word3 feeTokenAmount, word4 extraArgs offset.
        for field_word in [1usize, 2usize] {
            let pos = head.checked_add(field_word * 32).ok_or(SkipReason::MalformedEvent)?;
            if word(pos)?.iter().take(28).any(|&b| b != 0) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Bytes, LogData, U256, address, b256, hex as alloy_hex};
    use alloy::providers::ProviderBuilder;
    use alloy::providers::mock::Asserter;
    use ccv_protocol::{MESSAGE_VERSION, TokenTransfer};
    use hex_literal::hex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const CHAIN_SELECTOR: u64 = 16015286601757825753;
    const DEST_CHAIN_SELECTOR: u64 = 5009297550715157269;

    // Golden values produced by the Go protocol package.
    const ENCODED_MESSAGE_NO_TOKEN: &[u8] = &hex!(
        "01de41ba4fc9d91ad945849994fc9c7b15000000000000002a0007a12000030d4000000001"
        "13a7b9b0c5f3ba0823991a0f2fccdb822f02084cde959b3b1a33f5b19ce7b4cf"
        "20000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "20000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        "20000000000000000000000000cccccccccccccccccccccccccccccccccccccccc"
        "20000000000000000000000000dddddddddddddddddddddddddddddddddddddddd"
        "0003010203" "0000" "000a" "68656c6c6f2063636970"
    );
    const MESSAGE_ID_NO_TOKEN: B256 = b256!("8527b04a622efd89664aeaa2269dcdf2f4f46898e2776aa144f874bace7be211");

    const ON_RAMP: Address = address!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    const SENDER: Address = address!("cccccccccccccccccccccccccccccccccccccccc");
    const RMN_REMOTE: Address = address!("9999999999999999999999999999999999999999");

    fn receipt(issuer_byte: u8) -> OnRamp::Receipt {
        OnRamp::Receipt {
            issuer: Address::from([issuer_byte; 20]),
            destGasLimit: 100_000,
            destBytesOverhead: 32,
            feeTokenAmount: U256::from(1u64),
            extraArgs: Bytes::from(vec![0x01, 0x02]),
        }
    }

    /// A fully valid CCIPMessageSent event whose embedded message is the Go
    /// golden encoding (2 CCVs 0x11/0x22, executor 0x33, network fee 0x44).
    fn valid_event() -> OnRamp::CCIPMessageSent {
        OnRamp::CCIPMessageSent {
            destChainSelector: DEST_CHAIN_SELECTOR,
            sender: SENDER,
            messageId: MESSAGE_ID_NO_TOKEN,
            feeToken: Address::ZERO,
            tokenAmountBeforeTokenPoolFees: U256::ZERO,
            encodedMessage: Bytes::from(ENCODED_MESSAGE_NO_TOKEN.to_vec()),
            receipts: vec![receipt(0x11), receipt(0x22), receipt(0x33), receipt(0x44)],
            verifierBlobs: vec![Bytes::from(vec![0xb1; 4]), Bytes::from(vec![0xb2; 4])],
        }
    }

    fn log_for(event: &OnRamp::CCIPMessageSent, block_number: u64) -> Log {
        let topics = event.encode_topics().into_iter().map(|t| t.0).collect::<Vec<B256>>();
        let mut log = Log {
            inner: alloy::primitives::Log::new_unchecked(ON_RAMP, topics, event.encode_data().into()),
            block_hash: None,
            block_number: None,
            block_timestamp: None,
            transaction_hash: None,
            transaction_index: None,
            log_index: None,
            removed: false,
        };
        log.block_number = Some(block_number);
        log.transaction_hash = Some(b256!("deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead"));
        log.block_timestamp = Some(1_700_000_000);
        log
    }

    /// Enables tracing (with discarded output) so that log statements in library
    /// code actually evaluate their fields under coverage instrumentation.
    fn init_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_writer(std::io::sink)
            .with_max_level(tracing::Level::TRACE)
            .try_init();
    }

    fn reader_with_logs(logs: Vec<Log>) -> (EvmSourceReader<impl Provider>, Arc<AtomicUsize>) {
        init_tracing();
        let asserter = Asserter::new();
        asserter.push_success(&logs);
        let provider = ProviderBuilder::new().connect_mocked_client(asserter);
        let violations = Arc::new(AtomicUsize::new(0));
        let counter = violations.clone();
        let reader = EvmSourceReader::new(provider, ON_RAMP, RMN_REMOTE, CHAIN_SELECTOR)
            .unwrap()
            .with_critical_invariant_hook(move || {
                counter.fetch_add(1, Ordering::SeqCst);
            });
        (reader, violations)
    }

    #[tokio::test]
    async fn parses_valid_event_end_to_end() {
        let (reader, violations) = reader_with_logs(vec![log_for(&valid_event(), 123)]);
        let events = reader.fetch_message_sent_events(100, Some(200)).await.unwrap();

        assert_eq!(events.len(), 1);
        let evt = &events[0];
        assert_eq!(evt.message_id, MESSAGE_ID_NO_TOKEN);
        assert_eq!(evt.block_number, 123);
        assert_eq!(
            alloy_hex::encode(evt.tx_hash),
            "deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead"
        );
        assert_eq!(evt.receipts.len(), 4);
        // Verifier blobs pair with the first two (CCV) receipts only.
        assert_eq!(evt.receipts[0].blob, vec![0xb1; 4]);
        assert_eq!(evt.receipts[1].blob, vec![0xb2; 4]);
        assert_eq!(evt.receipts[2].blob, Vec::<u8>::new());
        assert_eq!(evt.receipts[3].blob, Vec::<u8>::new());
        // Message round-trips against the Go golden encoding.
        assert_eq!(evt.message.encode().unwrap(), ENCODED_MESSAGE_NO_TOKEN);
        assert_eq!(evt.message.version, MESSAGE_VERSION);
        assert_eq!(evt.message.dest_chain_selector, DEST_CHAIN_SELECTOR);
        assert!(evt.message.token_transfer.is_none());
        assert_eq!(violations.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn skips_event_with_too_few_receipts() {
        let mut event = valid_event();
        event.receipts.truncate(2);
        let (reader, violations) = reader_with_logs(vec![log_for(&event, 1)]);
        let events = reader.fetch_message_sent_events(0, None).await.unwrap();
        assert!(events.is_empty());
        assert_eq!(violations.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn skips_event_with_wrong_sender_and_fires_invariant() {
        let mut event = valid_event();
        event.sender = Address::from([0xef; 20]);
        let (reader, violations) = reader_with_logs(vec![log_for(&event, 1)]);
        let events = reader.fetch_message_sent_events(0, None).await.unwrap();
        assert!(events.is_empty());
        assert_eq!(violations.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn skips_event_with_bad_ccv_hash_without_firing_invariant() {
        // Executor receipt replaced by 0x55 -> ccvAndExecutorHash mismatch.
        // The Go code logs the error but does not call onCriticalInvariant here.
        let mut event = valid_event();
        event.receipts[2] = receipt(0x55);
        let (reader, violations) = reader_with_logs(vec![log_for(&event, 1)]);
        let events = reader.fetch_message_sent_events(0, None).await.unwrap();
        assert!(events.is_empty());
        assert_eq!(violations.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn skips_event_with_undecodable_message() {
        let mut event = valid_event();
        event.encodedMessage = Bytes::from(vec![0x01, 0x02, 0x03]);
        let (reader, violations) = reader_with_logs(vec![log_for(&event, 1)]);
        let events = reader.fetch_message_sent_events(0, None).await.unwrap();
        assert!(events.is_empty());
        assert_eq!(violations.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn skips_log_with_wrong_topic0() {
        let mut log = log_for(&valid_event(), 7);
        log.inner.data.topics_mut()[0] = B256::ZERO;
        let (reader, violations) = reader_with_logs(vec![log]);
        let events = reader.fetch_message_sent_events(0, None).await.unwrap();
        assert!(events.is_empty());
        assert_eq!(violations.load(Ordering::SeqCst), 1);
    }

    // Golden message WITH token transfer, encoded by the Go protocol package.
    const ENCODED_MESSAGE_WITH_TOKEN: &[u8] = &hex!(
        "01de41ba4fc9d91ad945849994fc9c7b15000000000000002a0007a12000030d4000000001"
        "13a7b9b0c5f3ba0823991a0f2fccdb822f02084cde959b3b1a33f5b19ce7b4cf"
        "20000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "20000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        "20000000000000000000000000cccccccccccccccccccccccccccccccccccccccc"
        "20000000000000000000000000dddddddddddddddddddddddddddddddddddddddd"
        "0003010203"
        "0087"
        "010000000000000000000000000000000000000000000000000de0b6b3a7640000"
        "14" "4444444444444444444444444444444444444444"
        "14" "5555555555555555555555555555555555555555"
        "20" "6666666666666666666666666666666666666666666666666666666666666666"
        "14" "7777777777777777777777777777777777777777"
        "0004" "deadbeef"
        "000a" "68656c6c6f2063636970"
    );
    const MESSAGE_ID_WITH_TOKEN: B256 =
        b256!("969d89ef12e60be7faff8b1b72c6b9a95faac24cb82c77cdf009e5a580500557");

    /// Valid event carrying the golden message WITH a token transfer: receipts
    /// gain a token receipt at index len-3: [CCV0, CCV1, Token, Executor, NetworkFee].
    fn valid_event_with_token() -> OnRamp::CCIPMessageSent {
        OnRamp::CCIPMessageSent {
            destChainSelector: DEST_CHAIN_SELECTOR,
            sender: SENDER,
            messageId: MESSAGE_ID_WITH_TOKEN,
            feeToken: Address::ZERO,
            tokenAmountBeforeTokenPoolFees: U256::ZERO,
            encodedMessage: Bytes::from(ENCODED_MESSAGE_WITH_TOKEN.to_vec()),
            receipts: vec![receipt(0x11), receipt(0x22), receipt(0x99), receipt(0x33), receipt(0x44)],
            verifierBlobs: vec![Bytes::from(vec![0xb1; 4]), Bytes::from(vec![0xb2; 4])],
        }
    }

    #[tokio::test]
    async fn parses_event_with_token_transfer() {
        let event = valid_event_with_token();
        let (reader, violations) = reader_with_logs(vec![log_for(&event, 50)]);
        let events = reader.fetch_message_sent_events(0, None).await.unwrap();

        assert_eq!(events.len(), 1);
        let evt = &events[0];
        assert_eq!(evt.message_id, MESSAGE_ID_WITH_TOKEN);
        assert_eq!(evt.receipts.len(), 5);
        let tt: &TokenTransfer = evt.message.token_transfer.as_ref().expect("token transfer");
        assert_eq!(tt.amount, U256::from(1_000_000_000_000_000_000u64));
        assert_eq!(tt.dest_token_address, vec![0x66; 32]);
        assert_eq!(violations.load(Ordering::SeqCst), 0);
    }

    /// Minimal eth_getBlockByNumber response JSON that Alloy can deserialize.
    fn block_json(n: u64) -> serde_json::Value {
        serde_json::json!({
            "number": format!("0x{n:x}"),
            "hash": format!("0x{n:064x}"),
            "parentHash": format!("0x{:064x}", n.saturating_sub(1)),
            "timestamp": "0x65f1e200",
            "nonce": "0x0000000000000000",
            "sha3Uncles": format!("0x{:064x}", 0),
            "logsBloom": format!("0x{:0512x}", 0),
            "transactionsRoot": format!("0x{:064x}", 0),
            "stateRoot": format!("0x{:064x}", 0),
            "receiptsRoot": format!("0x{:064x}", 0),
            "miner": "0x0000000000000000000000000000000000000000",
            "difficulty": "0x0",
            "extraData": "0x",
            "gasLimit": "0x1c9c380",
            "gasUsed": "0x0",
            "baseFeePerGas": "0x3b9aca00",
            "mixHash": format!("0x{:064x}", 0),
            "transactions": [],
            "uncles": [],
        })
    }

    fn reader_with_mocked_rpc() -> (EvmSourceReader<impl Provider>, Asserter) {
        init_tracing();
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
        let reader = EvmSourceReader::new(provider, ON_RAMP, RMN_REMOTE, CHAIN_SELECTOR).unwrap();
        (reader, asserter)
    }

    #[tokio::test]
    async fn fetch_propagates_rpc_error() {
        let (reader, asserter) = reader_with_mocked_rpc();
        asserter.push_failure_msg("node is down");
        let err = reader.fetch_message_sent_events(1, Some(2)).await.unwrap_err();
        assert!(matches!(err, ChainAccessError::Rpc(_)));
    }

    #[tokio::test]
    async fn get_blocks_headers_omits_missing_and_failed_blocks() {
        let (reader, asserter) = reader_with_mocked_rpc();
        asserter.push_success(&block_json(10)); // block 10: ok
        asserter.push_success(&serde_json::Value::Null); // block 11: not found
        asserter.push_failure_msg("boom"); // block 12: RPC error
        asserter.push_success(&block_json(13)); // block 13: ok

        let headers = reader.get_blocks_headers(&[10, 11, 12, 13]).await.unwrap();
        assert_eq!(headers.len(), 2);
        let h10 = headers.get(&10).unwrap();
        assert_eq!(h10.number, 10);
        assert_eq!(h10.parent_hash, b256!("0000000000000000000000000000000000000000000000000000000000000009"));
        assert_eq!(h10.timestamp, 0x65f1e200);
        assert!(!headers.contains_key(&11));
        assert!(!headers.contains_key(&12));
        assert!(headers.contains_key(&13));
    }

    #[tokio::test]
    async fn latest_and_finalized_block_returns_both_heads() {
        let (reader, asserter) = reader_with_mocked_rpc();
        asserter.push_success(&block_json(100));
        asserter.push_success(&block_json(90));
        let (latest, finalized) = reader.latest_and_finalized_block().await.unwrap();
        assert_eq!(latest.number, 100);
        assert_eq!(finalized.number, 90);
    }

    #[tokio::test]
    async fn latest_and_finalized_block_errors_on_nil_head() {
        let (reader, asserter) = reader_with_mocked_rpc();
        asserter.push_success(&block_json(100));
        asserter.push_success(&serde_json::Value::Null);
        let err = reader.latest_and_finalized_block().await.unwrap_err();
        assert!(matches!(err, ChainAccessError::NotFound(_)));

        let (reader, asserter) = reader_with_mocked_rpc();
        asserter.push_failure_msg("boom");
        let err = reader.latest_and_finalized_block().await.unwrap_err();
        assert!(matches!(err, ChainAccessError::Rpc(_)));
    }

    #[tokio::test]
    async fn latest_safe_block_variants() {
        // Chain supports the tag.
        let (reader, asserter) = reader_with_mocked_rpc();
        asserter.push_success(&block_json(77));
        assert_eq!(reader.latest_safe_block().await.unwrap().map(|h| h.number), Some(77));

        // Tag unsupported by the chain: error mapped to None (Go-compatible).
        let (reader, asserter) = reader_with_mocked_rpc();
        asserter.push_failure_msg("invalid tag");
        assert_eq!(reader.latest_safe_block().await.unwrap(), None);

        // No safe block known yet: null mapped to None.
        let (reader, asserter) = reader_with_mocked_rpc();
        asserter.push_success(&serde_json::Value::Null);
        assert_eq!(reader.latest_safe_block().await.unwrap(), None);
    }

    #[tokio::test]
    async fn get_rmn_cursed_subjects_decodes_response() {
        let subject1 = [0x01u8; 16];
        let subject2 = [0x02u8; 16];
        // ABI-encoded bytes16[2]: offset, length, two right-zero-padded elements.
        let mut encoded = format!("{:064x}", 0x20) + &format!("{:064x}", 2);
        for s in [&subject1, &subject2] {
            encoded.push_str(&alloy_hex::encode(s));
            encoded.push_str(&"00".repeat(16));
        }
        let (reader, asserter) = reader_with_mocked_rpc();
        asserter.push_success(&format!("0x{encoded}"));

        let subjects = reader.get_rmn_cursed_subjects().await.unwrap();
        assert_eq!(subjects, vec![FixedBytes::<16>::from(subject1), FixedBytes::<16>::from(subject2)]);

        let (reader, asserter) = reader_with_mocked_rpc();
        asserter.push_failure_msg("revert");
        let err = reader.get_rmn_cursed_subjects().await.unwrap_err();
        assert!(matches!(err, ChainAccessError::Contract(_)));
    }

    #[tokio::test]
    async fn skip_reasons_match_go_semantics() {
        // Zero ccvAndExecutorHash: decoded message with zeroed hash field.
        let mut encoded = ENCODED_MESSAGE_NO_TOKEN.to_vec();
        // hash occupies bytes 37..69 (after version 1 + 3*8 selectors/seq + 3*4 gas/finality).
        for b in encoded.iter_mut().take(69).skip(37) {
            *b = 0;
        }
        let mut event = valid_event();
        event.encodedMessage = Bytes::from(encoded);
        event.messageId = B256::ZERO;
        let (reader, violations) = reader_with_logs(vec![log_for(&event, 1)]);
        let err = reader.check_log(&log_for(&event, 1)).unwrap_err();
        assert_eq!(err, SkipReason::ZeroCcvAndExecutorHash);
        assert!(err.fires_critical_invariant());
        assert_eq!(violations.load(Ordering::SeqCst), 1); // direct process_log call fired the hook
        let events = reader.fetch_message_sent_events(0, None).await.unwrap();
        assert!(events.is_empty());
        assert_eq!(violations.load(Ordering::SeqCst), 2); // and again via fetch

        // onRamp mismatch: reader configured with a different OnRamp address than
        // the address embedded (left-padded) in the golden message.
        let other_ramp = Address::from([0x42; 20]);
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(asserter);
        let reader2 = EvmSourceReader::new(provider, other_ramp, RMN_REMOTE, CHAIN_SELECTOR).unwrap();
        let err = reader2.check_log(&log_for(&valid_event(), 1)).unwrap_err();
        assert_eq!(err, SkipReason::OnRampAddressMismatch);

        // MessageId mismatch: corrupt the embedded ccv hash so recompute != topic.
        let mut encoded = ENCODED_MESSAGE_NO_TOKEN.to_vec();
        for b in encoded.iter_mut().take(69).skip(37) {
            *b = 0xab;
        }
        let mut event = valid_event();
        event.encodedMessage = Bytes::from(encoded);
        let (reader, _) = reader_with_logs(vec![log_for(&event, 1)]);
        let err = reader.check_log(&log_for(&event, 1)).unwrap_err();
        assert_eq!(err, SkipReason::MessageIdMismatch);

        // DestChainSelector mismatch.
        let mut event = valid_event();
        event.destChainSelector = 999;
        let (reader, _) = reader_with_logs(vec![log_for(&event, 1)]);
        let err = reader.check_log(&log_for(&event, 1)).unwrap_err();
        assert_eq!(err, SkipReason::DestChainSelectorMismatch);

        // Insufficient receipts.
        let mut event = valid_event();
        event.receipts.truncate(2);
        let (reader, _) = reader_with_logs(vec![log_for(&event, 1)]);
        let err = reader.check_log(&log_for(&event, 1)).unwrap_err();
        assert_eq!(err, SkipReason::InsufficientReceipts);

        // Malformed event (only 3 topics).
        let mut log = log_for(&valid_event(), 1);
        log.inner.data = LogData::new_unchecked(
            log.inner.data.topics().to_vec().into_iter().take(3).collect(),
            log.inner.data.data.clone(),
        );
        let (reader, _) = reader_with_logs(vec![log.clone()]);
        let err = reader.check_log(&log).unwrap_err();
        assert_eq!(err, SkipReason::MalformedEvent);

        // Undecodable message.
        let mut event = valid_event();
        event.encodedMessage = Bytes::from(vec![0x01, 0x02, 0x03]);
        let (reader, _) = reader_with_logs(vec![log_for(&event, 1)]);
        let err = reader.check_log(&log_for(&event, 1)).unwrap_err();
        assert_eq!(err, SkipReason::UndecodableMessage);

        // ccvAndExecutorHash validation failure does NOT fire the hook.
        let mut event = valid_event();
        event.receipts[2] = receipt(0x55);
        let (reader, violations) = reader_with_logs(vec![log_for(&event, 1)]);
        let err = reader.check_log(&log_for(&event, 1)).unwrap_err();
        assert_eq!(err, SkipReason::CcvAndExecutorHashValidation);
        assert!(!err.fires_critical_invariant());
        let events = reader.fetch_message_sent_events(0, None).await.unwrap();
        assert!(events.is_empty());
        assert_eq!(violations.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn constructor_validates_inputs() {
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(asserter);
        assert!(EvmSourceReader::new(provider, Address::ZERO, RMN_REMOTE, CHAIN_SELECTOR).is_err());

        let asserter = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(asserter);
        assert!(EvmSourceReader::new(provider, ON_RAMP, Address::ZERO, CHAIN_SELECTOR).is_err());

        let asserter = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(asserter);
        assert!(EvmSourceReader::new(provider, ON_RAMP, RMN_REMOTE, 0).is_err());
    }

    #[test]
    fn skip_reason_codes_and_hooks_are_stable() {
        let all = [
            (SkipReason::MalformedEvent, "malformed_event", true),
            (SkipReason::InsufficientReceipts, "insufficient_receipts", true),
            (SkipReason::UndecodableMessage, "undecodable_message", true),
            (SkipReason::ZeroCcvAndExecutorHash, "zero_hash", true),
            (SkipReason::OnRampAddressMismatch, "onramp_mismatch", true),
            (SkipReason::SenderMismatch, "sender_mismatch", true),
            (SkipReason::MessageIdMismatch, "id_mismatch", true),
            (SkipReason::DestChainSelectorMismatch, "dest_mismatch", true),
            (SkipReason::CcvAndExecutorHashValidation, "hash_validation", false),
        ];
        for (reason, code, fires) in all {
            assert_eq!(reason.code(), code);
            assert_eq!(reason.fires_critical_invariant(), fires);
        }
    }

    /// Builds a minimal ABI event-data buffer with one receipt whose
    /// destGasLimit/destBytesOverhead words carry the given top bytes.
    fn abi_data_with_receipt(gas_limit_word_top: u8, overhead_word_top: u8) -> Vec<u8> {
        let word = |top: u8, low: u64| {
            let mut w = [0u8; 32];
            w[0] = top;
            w[24..].copy_from_slice(&low.to_be_bytes());
            w
        };
        let mut data = Vec::new();
        for w in [word(0, 0), word(0, 0), word(0, 0xa0), word(0, 0xa0), word(0, 0x120)] {
            data.extend_from_slice(&w); // event head: 5 words
        }
        data.extend_from_slice(&word(0, 1)); // receipts: 1 element
        data.extend_from_slice(&word(0, 0x20)); // element offset 32: head follows the offset table
        // receipt head: issuer, destGasLimit, destBytesOverhead, feeTokenAmount, extraArgs offset
        data.extend_from_slice(&word(0, 0)); // issuer (masked address)
        data.extend_from_slice(&word(gas_limit_word_top, 100_000));
        data.extend_from_slice(&word(overhead_word_top, 32));
        data.extend_from_slice(&word(0, 1)); // feeTokenAmount
        data.extend_from_slice(&word(0, 0xa0)); // extraArgs offset (relative to head)
        data.extend_from_slice(&word(0, 0)); // extraArgs: empty
        data.extend_from_slice(&word(0, 0)); // encodedMessage: empty (unused by the walk)
        data.extend_from_slice(&word(0, 0)); // verifierBlobs: empty
        data
    }

    #[test]
    fn uint32_overflow_walk_matches_geth_range_checks() {
        // Clean buffer: no overflow.
        assert!(!receipts_have_uint32_overflow(&abi_data_with_receipt(0, 0)).unwrap());
        // High bit set in destGasLimit: geth would reject.
        assert!(receipts_have_uint32_overflow(&abi_data_with_receipt(1, 0)).unwrap());
        // High bit set in destBytesOverhead: geth would reject.
        assert!(receipts_have_uint32_overflow(&abi_data_with_receipt(0, 1)).unwrap());

        // Defensive paths on malformed layouts.
        let mut bad = abi_data_with_receipt(0, 0);
        bad.truncate(100); // head cut short: receipts offset word out of range
        assert!(receipts_have_uint32_overflow(&bad).is_err());

        let mut bad = abi_data_with_receipt(0, 0);
        bad[96] = 1; // receipts offset word with high bits set
        assert!(receipts_have_uint32_overflow(&bad).is_err());

        let mut bad = abi_data_with_receipt(0, 0);
        bad[160] = 0xff; // absurd receipt count: element offset word out of range
        assert!(receipts_have_uint32_overflow(&bad).is_err());

        let mut bad = abi_data_with_receipt(0, 0);
        bad[192] = 1; // element offset word with high bits set
        assert!(receipts_have_uint32_overflow(&bad).is_err());
    }

    #[tokio::test]
    async fn dirty_uint32_word_is_malformed_like_geth() {
        // Flip the top byte of the first receipt's destGasLimit word in otherwise
        // valid event data: geth rejects, and so must we. Positions are derived
        // from the data's own offsets, not hardcoded.
        let mut data = valid_event().encode_data().to_vec();
        let word_as_usize = |pos: usize| -> usize {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&data[pos + 24..pos + 32]);
            u64::from_be_bytes(arr) as usize
        };
        let receipts_area = word_as_usize(96); // head word 3: receipts offset
        let head0 = receipts_area + 32 + word_as_usize(receipts_area + 32); // first element offset
        let dest_gas_limit_word = head0 + 32; // receipt head word 1
        assert!(!receipts_have_uint32_overflow(&data).unwrap());
        data[dest_gas_limit_word] = 0x01;
        let event = valid_event();
        let topics = event.encode_topics().into_iter().map(|t| t.0).collect::<Vec<B256>>();
        let mut log = log_for(&event, 1);
        log.inner.data = LogData::new_unchecked(topics, Bytes::from(data));

        let (reader, violations) = reader_with_logs(vec![log.clone()]);
        let err = reader.check_log(&log).unwrap_err();
        assert_eq!(err, SkipReason::MalformedEvent);
        assert_eq!(violations.load(Ordering::SeqCst), 1);
        let events = reader.fetch_message_sent_events(0, None).await.unwrap();
        assert!(events.is_empty());
        assert_eq!(violations.load(Ordering::SeqCst), 2);
    }
}

