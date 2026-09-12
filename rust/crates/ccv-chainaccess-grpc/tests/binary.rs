//! End-to-end tests for the `ccv-chainaccess-grpc` server binary: boots the real
//! process against a stub JSON-RPC endpoint, serves gRPC requests over a real
//! socket, then shuts the process down gracefully via SIGINT.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use ccv_chainaccess_grpc::pb;
use ccv_chainaccess_grpc::pb::source_reader_client::SourceReaderClient;

const BIN: &str = env!("CARGO_BIN_EXE_ccv-chainaccess-grpc");

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn block_json(tag: &str) -> serde_json::Value {
    let n: u64 = match tag {
        "finalized" => 40,
        "safe" => 39,
        _ => 42,
    };
    common::block_json(n)
}

fn handle_rpc(mut stream: TcpStream) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut content_length = 0usize;
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    loop {
        line.clear();
        if reader.read_line(&mut line).is_err() {
            return;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some(v) = trimmed.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; content_length];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    let body: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(_) => return,
    };
    let id = body["id"].clone();
    let result = match body["method"].as_str().unwrap_or("") {
        "eth_getBlockByNumber" => block_json(body["params"][0].as_str().unwrap_or("latest")),
        // ABI-encoded empty bytes16[]: offset word (0x20) + zero-length word.
        "eth_call" => serde_json::json!(format!("0x{:0>62}20{:0>64}", "", "")),
        _ => serde_json::json!([]),
    };
    let resp = serde_json::json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string();
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
        resp.len(),
        resp
    );
    let _ = stream.flush();
}

fn spawn_rpc_stub(port: u16) {
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().map_while(Result::ok) {
            std::thread::spawn(move || handle_rpc(stream));
        }
    });
}

fn spawn_server(rpc_port: u16, grpc_port: u16) -> Child {
    Command::new(BIN)
        .env("CCV_EVM_RPC_URL", format!("http://127.0.0.1:{rpc_port}"))
        .env("CCV_ON_RAMP_ADDRESS", "0x181Ac7dC295f1C8C87342d07CFaBA90bC477DB5d")
        .env("CCV_RMN_REMOTE_ADDRESS", "0xF094E1dB26Ce8C76C9fF0bD0566Bb8EEfF1b76dd")
        .env("CCV_CHAIN_SELECTOR", "16015286601757825753")
        .env("CCV_LISTEN_ADDR", format!("127.0.0.1:{grpc_port}"))
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn server binary")
}

async fn connect_ready(grpc_port: u16) -> SourceReaderClient<tonic::transport::Channel> {
    for _ in 0..100 {
        if let Ok(client) = SourceReaderClient::connect(format!("http://127.0.0.1:{grpc_port}")).await {
            return client;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("server did not start listening");
}

fn sigint(child: &Child) {
    let _ = Command::new("kill").arg("-INT").arg(child.id().to_string()).status();
}

#[tokio::test]
async fn binary_serves_and_shuts_down_gracefully() {
    let rpc_port = free_port();
    let grpc_port = free_port();
    spawn_rpc_stub(rpc_port);
    let mut child = spawn_server(rpc_port, grpc_port);

    let mut client = connect_ready(grpc_port).await;
    let resp = client
        .latest_and_finalized_block(pb::LatestAndFinalizedBlockRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.latest.unwrap().number, 42);
    assert_eq!(resp.finalized.unwrap().number, 40);

    let resp = client
        .latest_safe_block(pb::LatestSafeBlockRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.safe.unwrap().number, 39);

    let resp = client
        .get_rmn_cursed_subjects(pb::GetRmnCursedSubjectsRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.subjects.len(), 0);

    let resp = client
        .fetch_message_sent_events(pb::FetchMessageSentEventsRequest {
            from_block: 1,
            to_block: Some(10),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.events.len(), 0);

    // Cooperative shutdown: SIGINT -> graceful gRPC stop -> clean exit.
    // tonic waits for open connections, so the client must be dropped first, and
    // the wait loop must yield to the async runtime (the dropped client's h2
    // teardown runs on it) — a blocking sleep here would deadlock the shutdown.
    drop(client);
    sigint(&child);
    for _ in 0..100 {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "graceful shutdown should exit 0, got {status}");
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let _ = child.kill();
    panic!("server did not exit within 5s of SIGINT");
}

#[test]
fn binary_fails_fast_without_config() {
    let status = Command::new(BIN)
        .env_remove("CCV_EVM_RPC_URL")
        .env_remove("CCV_ON_RAMP_ADDRESS")
        .env_remove("CCV_RMN_REMOTE_ADDRESS")
        .env_remove("CCV_CHAIN_SELECTOR")
        .env_remove("CCV_LISTEN_ADDR")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!status.success());
}

#[test]
fn binary_fails_fast_on_bad_rpc_url() {
    let status = Command::new(BIN)
        .env("CCV_EVM_RPC_URL", "not a url")
        .env("CCV_ON_RAMP_ADDRESS", "0x181Ac7dC295f1C8C87342d07CFaBA90bC477DB5d")
        .env("CCV_RMN_REMOTE_ADDRESS", "0xF094E1dB26Ce8C76C9fF0bD0566Bb8EEfF1b76dd")
        .env("CCV_CHAIN_SELECTOR", "16015286601757825753")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!status.success());
}

/// Every misconfiguration value must exit non-zero before serving.
#[test]
fn binary_fails_fast_on_each_bad_value() {
    let good: [(&str, &str); 5] = [
        ("CCV_EVM_RPC_URL", "http://127.0.0.1:1"),
        ("CCV_ON_RAMP_ADDRESS", "0x181Ac7dC295f1C8C87342d07CFaBA90bC477DB5d"),
        ("CCV_RMN_REMOTE_ADDRESS", "0xF094E1dB26Ce8C76C9fF0bD0566Bb8EEfF1b76dd"),
        ("CCV_CHAIN_SELECTOR", "16015286601757825753"),
        ("CCV_LISTEN_ADDR", "127.0.0.1:18787"),
    ];
    let bad_cases: Vec<(&str, &str)> = vec![
        ("CCV_ON_RAMP_ADDRESS", "not an address"),
        ("CCV_RMN_REMOTE_ADDRESS", "0x1234"),
        ("CCV_LISTEN_ADDR", "999.999.999.999:99999"),
        // Well-formed but the zero address: rejected at reader construction.
        ("CCV_ON_RAMP_ADDRESS", "0x0000000000000000000000000000000000000000"),
        ("CCV_CHAIN_SELECTOR", "0"),
    ];
    for (key, bad) in bad_cases {
        let mut cmd = Command::new(BIN);
        for (k, v) in good {
            cmd.env(k, v);
        }
        cmd.env(key, bad);
        let status = cmd.stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap();
        assert!(!status.success(), "expected failure for {key}={bad}");
    }
}

/// If the listen port is taken, serve() fails and the process exits non-zero.
#[tokio::test]
async fn binary_fails_when_listen_port_is_taken() {
    let rpc_port = free_port();
    let grpc_port = free_port();
    spawn_rpc_stub(rpc_port);
    let _holder = TcpListener::bind(("127.0.0.1", grpc_port)).unwrap();
    let mut child = spawn_server(rpc_port, grpc_port);
    for _ in 0..100 {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success());
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let _ = child.kill();
    panic!("server should have exited when its listen port is taken");
}
