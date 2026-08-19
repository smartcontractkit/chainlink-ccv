//! Differential fuzz test: this crate's canonical message codec vs the Go
//! `protocol` package (ground truth), driven through `rust/differential-go`.
//!
//! For every generated or mutated input, both sides must agree on
//! accept/reject, on the error *class* on reject, and on the re-encoded bytes
//! and message ID on accept.
//!
//! Requires `go` in PATH; skipped otherwise (with a notice on stderr).
//! Tunables: CCV_DIFF_ITERS (default 300), CCV_DIFF_SEED (default fixed).

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use alloy_primitives::{B256, U256, hex};

use ccv_protocol::{Message, ProtocolError, TokenTransfer};

// ---------------------------------------------------------------------------
// Deterministic RNG (xorshift64*), dependency-free so fuzz runs are reproducible.
// ---------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn from_env() -> Self {
        let seed = std::env::var("CCV_DIFF_SEED")
            .ok()
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0x9E3779B97F4A7C15);
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

    fn coin(&mut self) -> bool {
        self.next() & 1 == 1
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next() & 0xff) as u8).collect()
    }

    fn u64(&mut self) -> u64 {
        self.next()
    }

    fn u32(&mut self) -> u32 {
        (self.next() >> 32) as u32
    }
}

// ---------------------------------------------------------------------------
// Go CLI plumbing
// ---------------------------------------------------------------------------

fn repo_root() -> PathBuf {
    // crates/ccv-protocol -> crates -> rust -> repo root
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
    if !status.success() {
        panic!("go build of rust/differential-go failed");
    }
    Some(out)
}

/// Feeds hex-encoded inputs to `differential-go message-codec` and returns one
/// JSON result per input.
fn go_codec_batch(bin: &Path, inputs: &[Vec<u8>]) -> Vec<serde_json::Value> {
    let mut child = Command::new(bin)
        .arg("message-codec")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn differential-go");

    let mut payload = String::new();
    for data in inputs {
        payload.push_str(&hex::encode(data));
        payload.push('\n');
    }
    let mut stdin = child.stdin.take().expect("stdin");
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(payload.as_bytes());
        drop(stdin); // close stdin so the Go side sees EOF
    });

    let mut results = Vec::with_capacity(inputs.len());
    let stdout = child.stdout.take().expect("stdout");
    for line in BufReader::new(stdout).lines() {
        let line = line.expect("read go stdout");
        if line.trim().is_empty() {
            continue;
        }
        results.push(serde_json::from_str(&line).expect("parse go result JSON"));
    }
    writer.join().expect("join writer");
    assert!(child.wait().expect("wait go").success(), "differential-go failed");
    assert_eq!(results.len(), inputs.len(), "go returned a wrong number of results");
    results
}

// ---------------------------------------------------------------------------
// Random message generation (valid encodings only)
// ---------------------------------------------------------------------------

fn random_varbytes(rng: &mut Rng, max: usize) -> Vec<u8> {
    // Bias toward boundary lengths: 0, 1, max-1, max, and everything between.
    let len = match rng.below(6) {
        0 => 0,
        1 => 1,
        2 => max.saturating_sub(1),
        3 => max,
        _ => rng.below(max + 1),
    };
    rng.bytes(len)
}

fn random_address(rng: &mut Rng) -> Vec<u8> {
    match rng.below(4) {
        0 => rng.bytes(20), // EVM-sized
        1 => rng.bytes(32), // left-padded EVM / non-EVM
        _ => random_varbytes(rng, 255),
    }
}

fn random_token_transfer(rng: &mut Rng) -> TokenTransfer {
    TokenTransfer {
        version: if rng.coin() { 1 } else { (rng.next() & 0xff) as u8 },
        amount: U256::ZERO,
        source_pool_address: random_address(rng),
        source_token_address: random_address(rng),
        dest_token_address: random_address(rng),
        token_receiver: random_address(rng),
        extra_data: random_varbytes(rng, 1024),
    }
}

fn random_message(rng: &mut Rng) -> Message {
    Message {
        version: if rng.coin() { 1 } else { (rng.next() & 0xff) as u8 },
        source_chain_selector: rng.u64(),
        dest_chain_selector: rng.u64(),
        sequence_number: rng.u64(),
        execution_gas_limit: rng.u32(),
        ccip_receive_gas_limit: rng.u32(),
        finality: rng.u32(),
        ccv_and_executor_hash: B256::from_slice(&rng.bytes(32)),
        on_ramp_address: random_address(rng),
        off_ramp_address: random_address(rng),
        sender: random_address(rng),
        receiver: random_address(rng),
        dest_blob: random_varbytes(rng, 512),
        token_transfer: if rng.coin() { Some(random_token_transfer(rng)) } else { None },
        data: random_varbytes(rng, 1024),
    }
}

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------

fn rust_class(err: &ProtocolError) -> &'static str {
    match err {
        ProtocolError::DataTooShort { .. } => "too_short",
        ProtocolError::TrailingBytes => "trailing",
        ProtocolError::UnexpectedEof(_) => "eof",
        _ => "other",
    }
}

fn compare_case(label: &str, input: &[u8], go: &serde_json::Value) {
    let go_ok = go["ok"].as_bool().expect("go ok field");
    match Message::decode(input) {
        Ok(msg) => {
            assert!(go_ok, "{label}: Go rejected input Rust accepted: {}", hex::encode(input));
            let reencoded = msg.encode().expect("re-encode decoded message");
            assert_eq!(
                go["encoded"].as_str().expect("go encoded"),
                hex::encode(&reencoded),
                "{label}: re-encode mismatch"
            );
            assert_eq!(
                go["id"].as_str().expect("go id"),
                format!("0x{}", hex::encode(msg.message_id().expect("id"))),
                "{label}: message id mismatch"
            );
        }
        Err(err) => {
            assert!(!go_ok, "{label}: Go accepted input Rust rejected ({err}): {}", hex::encode(input));
            assert_eq!(
                go["class"].as_str().expect("go class"),
                rust_class(&err),
                "{label}: error class mismatch (rust: {err})"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The differential fuzz run
// ---------------------------------------------------------------------------

#[test]
fn differential_message_codec_vs_go() {
    let Some(bin) = ensure_go_cli("differential-codec") else { return };
    let iters = std::env::var("CCV_DIFF_ITERS").ok().and_then(|s| s.parse().ok()).unwrap_or(300);
    let mut rng = Rng::from_env();

    let mut labels: Vec<String> = Vec::new();
    let mut inputs: Vec<Vec<u8>> = Vec::new();

    for i in 0..iters {
        // Case 1: random valid message.
        let valid = random_message(&mut rng).encode().expect("encode valid message");
        labels.push(format!("iter {i} valid"));
        inputs.push(valid.clone());

        // Case 2: mutations of the valid encoding.
        for m in 0..3 {
            let mut mutated = valid.clone();
            match rng.below(4) {
                0 if !mutated.is_empty() => {
                    mutated.truncate(rng.below(mutated.len()) + 1);
                }
                1 if !mutated.is_empty() => {
                    let idx = rng.below(mutated.len());
                    mutated[idx] ^= 1 << rng.below(8);
                }
                2 => {
                    let n = rng.below(33) + 1;
                    mutated.extend_from_slice(&rng.bytes(n));
                }
                _ => {
                    // Scribble on a random length prefix region (first 80 bytes).
                    if !mutated.is_empty() {
                        let idx = rng.below(mutated.len().min(80));
                        mutated[idx] = (rng.next() & 0xff) as u8;
                    }
                }
            }
            labels.push(format!("iter {i} mutation {m}"));
            inputs.push(mutated);
        }

        // Case 3: pure garbage.
        labels.push(format!("iter {i} garbage"));
        let n = rng.below(150);
        inputs.push(rng.bytes(n));
    }

    let results = go_codec_batch(&bin, &inputs);
    for ((label, input), go) in labels.iter().zip(inputs.iter()).zip(results.iter()) {
        compare_case(label, input, go);
    }
    eprintln!("differential codec fuzz: {} cases compared against Go", inputs.len());
}
