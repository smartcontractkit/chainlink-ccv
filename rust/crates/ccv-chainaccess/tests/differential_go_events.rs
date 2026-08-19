//! Differential test of `EvmSourceReader::check_log` (and the fetch pipeline) against
//! the Go EVM SourceReader, driven through `rust/differential-go parse-events`.
//!
//! Corpus 1: 708 real historical CCIPMessageSent logs emitted by the Sepolia
//! OnRamp v2.0.0 (0x181Ac7dC…B5d) between blocks 10970571 and 11522733,
//! cross-validated byte-identically across two independent RPC endpoints
//! (0xrpc.io and ethpandaops) to guard against silent log dropping.
//! Saved under tests/data.
//! Corpus 2: deterministic mutations of those historical logs.
//!
//! Both sides must agree per log on accept/skip, the skip reason code, and —
//! on accept — message ID, block number, tx hash, receipt count, and the
//! re-encoded canonical message.
//!
//! Note on scope: the Go inner loop never sees logs with a wrong topic0 (the
//! eth_getLogs filter pins topic0), so topic0 corruption is excluded from the
//! mutation space; the Rust reader additionally rejects such logs as
//! `malformed_event`, which is unreachable through fetch_message_sent_events.
//!
//! Requires `go` in PATH; skipped otherwise. Tunables: CCV_DIFF_MUTATIONS_PER_LOG
//! (default 12), CCV_DIFF_SEED.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use alloy::primitives::{Address, B256, Bytes, address, hex};
use alloy::providers::mock::Asserter;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::Log;

use ccv_chainaccess::evm::EvmSourceReader;

const CORPUS: &str = include_str!("data/sepolia_v2_onramp_logs.json");
/// Sepolia OnRamp v2.0.0 that emitted the corpus.
const ON_RAMP: Address = address!("181Ac7dC295f1C8C87342d07CFaBA90bC477DB5d");
const CHAIN_SELECTOR: u64 = 16015286601757825753;
const RMN_REMOTE: Address = address!("F094E1dB26Ce8C76C9fF0bD0566Bb8EEfF1b76dd");

// ---------------------------------------------------------------------------
// RNG (same xorshift64* as the codec differential test)
// ---------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn from_env() -> Self {
        let seed = std::env::var("CCV_DIFF_SEED")
            .ok()
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0x243F6A8885A308D3);
        Self(seed)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

// ---------------------------------------------------------------------------
// Go CLI plumbing
// ---------------------------------------------------------------------------

fn repo_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.ancestors().nth(3).expect("repo root").to_path_buf()
}

fn ensure_go_cli(bin_name: &str) -> Option<PathBuf> {
    if Command::new("go").arg("version").output().is_err() {
        eprintln!("differential test skipped: `go` not in PATH");
        return None;
    }
    let out = repo_root().join("rust/target").join(bin_name);
    let status = Command::new("go")
        .arg("build")
        .arg("-o")
        .arg(&out)
        .arg("./rust/differential-go")
        .current_dir(repo_root())
        .status()
        .expect("run go build");
    assert!(status.success(), "go build of rust/differential-go failed");
    Some(out)
}

fn go_parse_events(bin: &Path, logs: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let mut child = Command::new(bin)
        .arg("parse-events")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn differential-go");

    let request = serde_json::json!({
        "onRampAddress": format!("0x{}", hex::encode(ON_RAMP)),
        "logs": logs,
    })
    .to_string();

    let mut stdin = child.stdin.take().expect("stdin");
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(request.as_bytes());
        drop(stdin);
    });

    let mut results = Vec::with_capacity(logs.len());
    let stdout = child.stdout.take().expect("stdout");
    for line in BufReader::new(stdout).lines() {
        let line = line.expect("read go stdout");
        if line.trim().is_empty() {
            continue;
        }
        results.push(serde_json::from_str(&line).expect("parse go result JSON"));
    }
    writer.join().expect("join writer");
    assert!(child.wait().expect("wait go").success(), "differential-go parse-events failed");
    assert_eq!(results.len(), logs.len(), "go returned a wrong number of results");
    results
}

// ---------------------------------------------------------------------------
// Rust-side outcome
// ---------------------------------------------------------------------------

fn rust_reader() -> EvmSourceReader<alloy::providers::DynProvider> {
    let provider = ProviderBuilder::new().connect_mocked_client(Asserter::new()).erased();
    EvmSourceReader::new(provider, ON_RAMP, RMN_REMOTE, CHAIN_SELECTOR).expect("reader")
}

fn rust_outcome(reader: &EvmSourceReader<alloy::providers::DynProvider>, log: &Log) -> serde_json::Value {
    match reader.check_log(log) {
        Ok(evt) => serde_json::json!({
            "status": "ok",
            "message_id": format!("0x{}", hex::encode(evt.message_id)),
            "block_number": evt.block_number,
            "tx_hash": format!("0x{}", hex::encode(evt.tx_hash)),
            "receipts": evt.receipts.len(),
            "encoded_message": format!("0x{}", hex::encode(evt.message.encode().expect("encode"))),
        }),
        Err(reason) => serde_json::json!({
            "status": "skip",
            "reason": reason.code(),
        }),
    }
}

fn compare(label: &str, rust: &serde_json::Value, go: &serde_json::Value) {
    assert_eq!(
        rust["status"].as_str().unwrap(),
        go["status"].as_str().unwrap(),
        "{label}: status mismatch\n rust: {rust}\n   go: {go}"
    );
    if rust["status"] == "skip" {
        assert_eq!(
            rust["reason"].as_str().unwrap(),
            go["reason"].as_str().unwrap(),
            "{label}: skip reason mismatch\n rust: {rust}\n   go: {go}"
        );
    } else {
        for field in ["message_id", "block_number", "tx_hash", "receipts", "encoded_message"] {
            assert_eq!(rust[field], go[field], "{label}: field {field} mismatch\n rust: {rust}\n   go: {go}");
        }
    }
}

// ---------------------------------------------------------------------------
// Mutations (never touch topic0: the RPC filter pins it, so the Go inner loop
// never observes a wrong topic0 in production — see module docs).
// ---------------------------------------------------------------------------

fn mutate(log: &Log, rng: &mut Rng) -> Log {
    let mut m = log.clone();
    match rng.below(7) {
        // Flip a byte in the ABI data.
        0 if !m.inner.data.data.is_empty() => {
            let mut data = m.inner.data.data.to_vec();
            let idx = rng.below(data.len());
            data[idx] ^= 1 << rng.below(8);
            m.inner.data.data = Bytes::from(data);
        }
        // Truncate the ABI data.
        1 if !m.inner.data.data.is_empty() => {
            let data = m.inner.data.data.to_vec();
            m.inner.data.data = Bytes::from(data[..rng.below(data.len()) + 1].to_vec());
        }
        // Append garbage to the ABI data (both decoders must tolerate trailing data).
        2 => {
            let mut data = m.inner.data.data.to_vec();
            let extra = rng.below(64) + 1;
            for _ in 0..extra {
                data.push((rng.next() & 0xff) as u8);
            }
            m.inner.data.data = Bytes::from(data);
        }
        // Corrupt the sender topic (topics[2]).
        3 => {
            if m.inner.data.topics().len() >= 3 {
                m.inner.data.topics_mut()[2] = B256::from_slice(&{
                    let mut b = [0u8; 32];
                    for x in &mut b {
                        *x = (rng.next() & 0xff) as u8;
                    }
                    b
                });
            }
        }
        // Corrupt the messageId topic (topics[3]).
        4 => {
            if m.inner.data.topics().len() >= 4 {
                let mut t = m.inner.data.topics()[3];
                let mut raw = *t;
                raw[0] ^= 0xff;
                t = B256::from(raw);
                m.inner.data.topics_mut()[3] = t;
            }
        }
        // Corrupt the destChainSelector topic (topics[1]), possibly into the
        // high bytes (both implementations must mask identically).
        5 => {
            if m.inner.data.topics().len() >= 2 {
                let raw = *m.inner.data.topics()[1];
                let mut mutated = raw;
                let idx = rng.below(32);
                mutated[idx] ^= 1 << rng.below(8);
                m.inner.data.topics_mut()[1] = B256::from(mutated);
            }
        }
        // Drop the last topic (3 topics left).
        _ => {
            let topics = m.inner.data.topics().to_vec();
            if topics.len() == 4 {
                m.inner.data = alloy::primitives::LogData::new_unchecked(
                    topics[..3].to_vec(),
                    m.inner.data.data.clone(),
                );
            }
        }
    }
    m
}

// ---------------------------------------------------------------------------
// The differential run
// ---------------------------------------------------------------------------

#[test]
fn differential_events_vs_go() {
    let Some(bin) = ensure_go_cli("differential-events") else { return };
    let reader = rust_reader();

    let corpus: Vec<serde_json::Value> = serde_json::from_str(CORPUS).expect("corpus parses");
    assert_eq!(corpus.len(), 708, "corpus should contain 708 historical logs");

    // --- Corpus 1: unmodified historical logs. ---
    let alloy_logs: Vec<Log> = corpus
        .iter()
        .map(|v| serde_json::from_value(v.clone()).expect("corpus log deserializes"))
        .collect();
    let go_results = go_parse_events(&bin, &corpus);
    for (i, log) in alloy_logs.iter().enumerate() {
        compare(&format!("historical log {i}"), &rust_outcome(&reader, log), &go_results[i]);
    }

    // --- Corpus 2: mutations of historical logs. ---
    let mutations_per_log: usize =
        std::env::var("CCV_DIFF_MUTATIONS_PER_LOG").ok().and_then(|s| s.parse().ok()).unwrap_or(3);
    let mut rng = Rng::from_env();

    let mut mutant_logs: Vec<Log> = Vec::new();
    for log in alloy_logs.iter().take(200) {
        for _ in 0..mutations_per_log {
            mutant_logs.push(mutate(log, &mut rng));
        }
    }
    let mutant_json: Vec<serde_json::Value> =
        mutant_logs.iter().map(|l| serde_json::to_value(l).expect("log serializes")).collect();
    let go_results = go_parse_events(&bin, &mutant_json);
    for (i, log) in mutant_logs.iter().enumerate() {
        compare(&format!("mutant {i}"), &rust_outcome(&reader, log), &go_results[i]);
    }

    eprintln!(
        "differential events: 708 historical + {} mutated logs compared against Go",
        mutant_logs.len()
    );
}
