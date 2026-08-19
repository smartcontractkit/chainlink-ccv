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

/// EVM [`SourceReader`] backed by an Alloy [`Provider`].
///
/// Stateless: every method hits the RPC endpoint, like the Go implementation.
/// Cheap to clone if `P` is (e.g. `RootProvider`/`DynProvider` are `Arc` internally),
/// and safe for concurrent use.
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

    /// Applies the Go per-event validation pipeline. Returns `None` when the event
    /// must be skipped (all skips mirror the Go `continue` paths).
    fn process_log(&self, log: &Log) -> Option<MessageSentEvent> {
        // Topic arity + ABI decoding in one step. The Go code checks
        // len(topics) >= 4 explicitly, then ABI-unpacks the data; both failure
        // modes land here.
        let event = match log.log_decode::<OnRamp::CCIPMessageSent>() {
            Ok(decoded) => decoded.inner.data.clone(),
            Err(err) => {
                self.critical_invariant();
                error!(
                    chain_selector = self.chain_selector,
                    error = %err,
                    block_number = log.block_number.unwrap_or_default(),
                    tx_hash = ?log.transaction_hash.unwrap_or_default(),
                    "CCIPMessageSent event failed topic/ABI validation",
                );
                return None;
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
            return None;
        }

        let message = match Message::decode(&event.encodedMessage) {
            Ok(m) => m,
            Err(err) => {
                self.critical_invariant();
                error!(message_id = ?event.messageId, error = %err, "Failed to decode message");
                return None;
            }
        };

        if message.ccv_and_executor_hash == B256::ZERO {
            self.critical_invariant();
            error!(
                message_id = ?event.messageId,
                block_number = log.block_number.unwrap_or_default(),
                "ccvAndExecutorHash is zero in decoded message",
            );
            return None;
        }

        // The on-chain event emits 20-byte EVM addresses; the canonical message
        // stores them left-padded to 32 bytes (Go: expectedSourceAddressBytes).
        if message.on_ramp_address != left_pad_32(&self.on_ramp_address) {
            self.critical_invariant();
            error!(
                message_id = ?event.messageId,
                "onRampAddress must match the value configured — critical invariant violated; escalate immediately",
            );
            return None;
        }

        if message.sender != left_pad_32(&event.sender) {
            self.critical_invariant();
            error!(
                message_id = ?event.messageId,
                "sender must match the value emitted from the on-chain event. This should never happen.",
            );
            return None;
        }

        if message.message_id() != event.messageId {
            self.critical_invariant();
            error!(
                message_id = ?event.messageId,
                computed = ?message.message_id(),
                "computed messageID must match the value emitted from the on-chain event — critical invariant violated",
            );
            return None;
        }

        if message.dest_chain_selector != event.destChainSelector {
            self.critical_invariant();
            error!(
                message_id = ?event.messageId,
                "destination chain selector must match the value emitted from the on-chain event. This should never happen",
            );
            return None;
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
        // critical-invariant hook.
        if let Err(err) = validate_ccv_and_executor_hash(&message, &receipts) {
            error!(
                message_id = ?event.messageId,
                block_number = log.block_number.unwrap_or_default(),
                error = %err,
                "ccvAndExecutorHash validation failed",
            );
            return None;
        }

        Some(MessageSentEvent {
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

        Ok(logs.iter().filter_map(|log| self.process_log(log)).collect())
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
    let mut out = vec![0u8; 32];
    out[12..].copy_from_slice(address.as_slice());
    out
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
    const CCV_HASH: B256 = b256!("13a7b9b0c5f3ba0823991a0f2fccdb822f02084cde959b3b1a33f5b19ce7b4cf");
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

    fn reader_with_logs(logs: Vec<Log>) -> (EvmSourceReader<impl Provider>, Arc<AtomicUsize>) {
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
        assert_eq!(evt.message.encode(), ENCODED_MESSAGE_NO_TOKEN);
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
}

