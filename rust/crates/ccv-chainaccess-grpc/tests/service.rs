//! Tests for the gRPC SourceReader service: handler mapping, error-to-Status
//! mapping, and a full over-the-wire roundtrip against a real socket.

use std::sync::Arc;

use alloy::primitives::{Address, B256, Bytes, U256, address, b256, hex as alloy_hex};
use alloy::providers::mock::Asserter;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::Log;
use alloy::sol_types::SolEvent;
use hex_literal::hex;
use tonic::Code;

use ccv_chainaccess::evm::{EvmSourceReader, OnRamp};
use ccv_chainaccess::ChainAccessError;
use ccv_chainaccess_grpc::pb::source_reader_server::SourceReader as _;
use ccv_chainaccess_grpc::{SourceReaderService, pb};

const CHAIN_SELECTOR: u64 = 16015286601757825753;
const DEST_CHAIN_SELECTOR: u64 = 5009297550715157269;

// Golden message (no token transfer), produced by the Go protocol package.
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

fn valid_log(block_number: u64) -> Log {
    let event = valid_event();
    let topics = event.encode_topics().into_iter().map(|t| t.0).collect::<Vec<B256>>();
    Log {
        inner: alloy::primitives::Log::new_unchecked(ON_RAMP, topics, event.encode_data().into()),
        block_hash: None,
        block_number: Some(block_number),
        block_timestamp: Some(1_700_000_000),
        transaction_hash: Some(b256!("deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead")),
        transaction_index: Some(0),
        log_index: Some(0),
        removed: false,
    }
}

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

type MockReader = EvmSourceReader<alloy::providers::DynProvider>;

fn service_with(asserter: &Asserter) -> SourceReaderService<MockReader> {
    let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone()).erased();
    let reader = EvmSourceReader::new(provider, ON_RAMP, RMN_REMOTE, CHAIN_SELECTOR).unwrap();
    SourceReaderService::new(Arc::new(reader))
}

#[tokio::test]
async fn fetch_message_sent_events_maps_events() {
    let asserter = Asserter::new();
    asserter.push_success(&vec![valid_log(123)]);
    let svc = service_with(&asserter);

    let resp = svc
        .fetch_message_sent_events(tonic::Request::new(pb::FetchMessageSentEventsRequest {
            from_block: 100,
            to_block: Some(200),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(resp.events.len(), 1);
    let evt = &resp.events[0];
    assert_eq!(evt.message_id, MESSAGE_ID_NO_TOKEN.to_vec());
    assert_eq!(evt.encoded_message, ENCODED_MESSAGE_NO_TOKEN);
    assert_eq!(evt.block_number, 123);
    assert_eq!(alloy_hex::encode(&evt.tx_hash), "deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead");
    assert_eq!(evt.receipts.len(), 4);
    assert_eq!(evt.receipts[0].issuer, vec![0x11; 20]);
    assert_eq!(evt.receipts[0].blob, vec![0xb1; 4]);
    assert_eq!(evt.receipts[2].blob, Vec::<u8>::new());
    assert_eq!(evt.receipts[0].fee_token_amount.len(), 32);
    assert_eq!(evt.receipts[0].dest_gas_limit, 100_000);
    assert_eq!(evt.receipts[0].dest_bytes_overhead, 32);

    // The wire encoding must decode back to the identical protocol message.
    let msg = ccv_protocol::Message::decode(&evt.encoded_message).unwrap();
    assert_eq!(msg.message_id().unwrap(), MESSAGE_ID_NO_TOKEN);
}

#[tokio::test]
async fn fetch_message_sent_events_maps_rpc_failure_to_unavailable() {
    let asserter = Asserter::new();
    asserter.push_failure_msg("node is down");
    let svc = service_with(&asserter);

    let status = svc
        .fetch_message_sent_events(tonic::Request::new(pb::FetchMessageSentEventsRequest {
            from_block: 0,
            to_block: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::Unavailable);
}

#[tokio::test]
async fn get_blocks_headers_roundtrip() {
    let asserter = Asserter::new();
    asserter.push_success(&block_json(10));
    asserter.push_success(&serde_json::Value::Null); // 11 omitted
    let svc = service_with(&asserter);

    let resp = svc
        .get_blocks_headers(tonic::Request::new(pb::GetBlocksHeadersRequest { block_numbers: vec![10, 11] }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.headers.len(), 1);
    let h = resp.headers.get(&10).unwrap();
    assert_eq!(h.number, 10);
    assert_eq!(h.hash.len(), 32);
    assert_eq!(h.parent_hash.len(), 32);
    assert_eq!(h.timestamp, 0x65f1e200);
}

#[tokio::test]
async fn latest_and_finalized_block_maps_heads() {
    let asserter = Asserter::new();
    asserter.push_success(&block_json(100));
    asserter.push_success(&block_json(90));
    let svc = service_with(&asserter);

    let resp = svc
        .latest_and_finalized_block(tonic::Request::new(pb::LatestAndFinalizedBlockRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.latest.unwrap().number, 100);
    assert_eq!(resp.finalized.unwrap().number, 90);
}

#[tokio::test]
async fn latest_and_finalized_block_nil_head_is_not_found() {
    let asserter = Asserter::new();
    asserter.push_success(&block_json(100));
    asserter.push_success(&serde_json::Value::Null);
    let svc = service_with(&asserter);

    let status = svc
        .latest_and_finalized_block(tonic::Request::new(pb::LatestAndFinalizedBlockRequest {}))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::NotFound);
}

#[tokio::test]
async fn latest_safe_block_supported_and_unsupported() {
    let asserter = Asserter::new();
    asserter.push_success(&block_json(77));
    let svc = service_with(&asserter);
    let resp = svc
        .latest_safe_block(tonic::Request::new(pb::LatestSafeBlockRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.safe.unwrap().number, 77);

    let asserter = Asserter::new();
    asserter.push_failure_msg("invalid tag");
    let svc = service_with(&asserter);
    let resp = svc
        .latest_safe_block(tonic::Request::new(pb::LatestSafeBlockRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert!(resp.safe.is_none());
}

#[tokio::test]
async fn get_rmn_cursed_subjects_maps_subjects() {
    let subject1 = [0x01u8; 16];
    let mut encoded = format!("{:064x}", 0x20) + &format!("{:064x}", 1);
    encoded.push_str(&alloy_hex::encode(subject1));
    encoded.push_str(&"00".repeat(16));

    let asserter = Asserter::new();
    asserter.push_success(&format!("0x{encoded}"));
    let svc = service_with(&asserter);

    let resp = svc
        .get_rmn_cursed_subjects(tonic::Request::new(pb::GetRmnCursedSubjectsRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.subjects, vec![subject1.to_vec()]);
}

#[test]
fn server_config_parsing() {
    use ccv_chainaccess_grpc::ServerConfig;

    // Happy path, including the default listen address.
    let cfg = ServerConfig::from_pairs([
        ("CCV_EVM_RPC_URL", "http://localhost:8545"),
        ("CCV_ON_RAMP_ADDRESS", "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ("CCV_RMN_REMOTE_ADDRESS", "0x9999999999999999999999999999999999999999"),
        ("CCV_CHAIN_SELECTOR", "16015286601757825753"),
    ])
    .unwrap();
    assert_eq!(cfg.chain_selector, 16015286601757825753);
    assert_eq!(cfg.listen_addr, "0.0.0.0:50051");

    // All problems are aggregated into one error.
    let err = ServerConfig::from_pairs([("CCV_CHAIN_SELECTOR", "not-a-number")]).unwrap_err();
    let problems = err.problems();
    assert_eq!(problems.len(), 4, "expected 4 problems, got {problems:?}");

    // Zero chain selector rejected.
    let err = ServerConfig::from_pairs([
        ("CCV_EVM_RPC_URL", "http://localhost:8545"),
        ("CCV_ON_RAMP_ADDRESS", "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ("CCV_RMN_REMOTE_ADDRESS", "0x9999999999999999999999999999999999999999"),
        ("CCV_CHAIN_SELECTOR", "0"),
    ])
    .unwrap_err();
    assert_eq!(err.problems().len(), 1);
}

#[tokio::test]
async fn over_the_wire_roundtrip() {
    let asserter = Asserter::new();
    asserter.push_success(&vec![valid_log(55)]);
    let svc = service_with(&asserter);
    let _cloned = svc.clone(); // Clone impl is required by tonic's connection model

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc.into_server())
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), async move {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });

    let mut client = pb::source_reader_client::SourceReaderClient::connect(format!("http://{addr}")).await.unwrap();
    let resp = client
        .fetch_message_sent_events(pb::FetchMessageSentEventsRequest { from_block: 1, to_block: Some(100) })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.events.len(), 1);
    assert_eq!(resp.events[0].block_number, 55);

    shutdown_tx.send(()).unwrap();
    server.await.unwrap();
}

/// A reader that fails every method with the configured error, to exercise the
/// domain-error -> gRPC-Status mapping of every service method.
struct ErrReader(fn() -> ChainAccessError);

#[async_trait::async_trait]
impl ccv_chainaccess::HeadTracker for ErrReader {
    async fn latest_and_finalized_block(&self) -> Result<(ccv_protocol::BlockHeader, ccv_protocol::BlockHeader), ChainAccessError> {
        Err((self.0)())
    }
    async fn latest_safe_block(&self) -> Result<Option<ccv_protocol::BlockHeader>, ChainAccessError> {
        Err((self.0)())
    }
}

#[async_trait::async_trait]
impl ccv_chainaccess::RmnCurseReader for ErrReader {
    async fn get_rmn_cursed_subjects(&self) -> Result<Vec<alloy::primitives::FixedBytes<16>>, ChainAccessError> {
        Err((self.0)())
    }
}

#[async_trait::async_trait]
impl ccv_chainaccess::SourceReader for ErrReader {
    async fn fetch_message_sent_events(
        &self,
        _from_block: u64,
        _to_block: Option<u64>,
    ) -> Result<Vec<ccv_protocol::MessageSentEvent>, ChainAccessError> {
        Err((self.0)())
    }
    async fn get_blocks_headers(
        &self,
        _block_numbers: &[u64],
    ) -> Result<std::collections::HashMap<u64, ccv_protocol::BlockHeader>, ChainAccessError> {
        Err((self.0)())
    }
}

#[tokio::test]
async fn error_status_mapping_for_every_method() {
    use ccv_chainaccess::ChainAccessError as E;

    let cases: [(fn() -> E, Code); 3] = [
        (|| E::InvalidInput("bad".into()), Code::InvalidArgument),
        (|| E::NotFound("gone".into()), Code::NotFound),
        (|| E::Protocol(ccv_protocol::ProtocolError::TrailingBytes), Code::Internal),
    ];

    for (err, code) in cases {
        let svc = SourceReaderService::new(Arc::new(ErrReader(err)));
        let status = svc
            .fetch_message_sent_events(tonic::Request::new(pb::FetchMessageSentEventsRequest {
                from_block: 0,
                to_block: None,
            }))
            .await
            .unwrap_err();
        assert_eq!(status.code(), code);
        let status = svc
            .get_blocks_headers(tonic::Request::new(pb::GetBlocksHeadersRequest { block_numbers: vec![1] }))
            .await
            .unwrap_err();
        assert_eq!(status.code(), code);
        let status = svc
            .latest_and_finalized_block(tonic::Request::new(pb::LatestAndFinalizedBlockRequest {}))
            .await
            .unwrap_err();
        assert_eq!(status.code(), code);
        let status = svc
            .latest_safe_block(tonic::Request::new(pb::LatestSafeBlockRequest {}))
            .await
            .unwrap_err();
        assert_eq!(status.code(), code);
        let status = svc
            .get_rmn_cursed_subjects(tonic::Request::new(pb::GetRmnCursedSubjectsRequest {}))
            .await
            .unwrap_err();
        assert_eq!(status.code(), code);
    }
}

#[tokio::test]
async fn serve_over_real_socket_until_shutdown() {
    let asserter = Asserter::new();
    asserter.push_success(&block_json(42)); // latest
    asserter.push_success(&block_json(40)); // finalized
    let provider = ProviderBuilder::new().connect_mocked_client(asserter).erased();
    let reader = EvmSourceReader::new(provider, ON_RAMP, RMN_REMOTE, CHAIN_SELECTOR).unwrap();

    // Reserve a free port, release it, then hand it to serve().
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        ccv_chainaccess_grpc::serve(reader, addr, async move {
            let _ = shutdown_rx.await;
        })
        .await
        .unwrap();
    });

    // Retry connect briefly: the server binds asynchronously.
    let mut client = None;
    for _ in 0..50 {
        match pb::source_reader_client::SourceReaderClient::connect(format!("http://{addr}")).await {
            Ok(c) => {
                client = Some(c);
                break;
            }
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
        }
    }
    let mut client = client.expect("server should accept connections");

    let resp = client
        .latest_and_finalized_block(pb::LatestAndFinalizedBlockRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.latest.unwrap().number, 42);

    shutdown_tx.send(()).unwrap();
    server.await.unwrap();
}

#[test]
fn server_config_from_env() {
    // No other test in this binary reads these variables, so mutating them here
    // cannot race with anything.
    std::env::set_var("CCV_EVM_RPC_URL", "http://localhost:8545");
    std::env::set_var("CCV_ON_RAMP_ADDRESS", "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    std::env::set_var("CCV_RMN_REMOTE_ADDRESS", "0x9999999999999999999999999999999999999999");
    std::env::set_var("CCV_CHAIN_SELECTOR", "123");
    std::env::set_var("CCV_LISTEN_ADDR", "127.0.0.1:9999");
    let cfg = ccv_chainaccess_grpc::ServerConfig::from_env().unwrap();
    assert_eq!(cfg.chain_selector, 123);
    assert_eq!(cfg.listen_addr, "127.0.0.1:9999");
    std::env::remove_var("CCV_EVM_RPC_URL");
    std::env::remove_var("CCV_ON_RAMP_ADDRESS");
    std::env::remove_var("CCV_RMN_REMOTE_ADDRESS");
    std::env::remove_var("CCV_CHAIN_SELECTOR");
    std::env::remove_var("CCV_LISTEN_ADDR");
    let err = ccv_chainaccess_grpc::ServerConfig::from_env().unwrap_err();
    assert!(err.to_string().contains("CCV_EVM_RPC_URL"));
}
