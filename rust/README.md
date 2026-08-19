# CCV Chain Access — Rust

Rust implementation of the Go `pkg/chainaccess` `SourceReader` interface for the
**EVM chain family**, exposed over gRPC as a drop-in replacement for the in-process
Go implementation (`integration/pkg/accessors/evm`).

```
rust/
├── crates/
│   ├── ccv-protocol/          # chain-agnostic types + canonical CCIP v1.7 message codec
│   ├── ccv-chainaccess/       # SourceReader/HeadTracker/RMNCurseReader traits + EVM impl (Alloy)
│   └── ccv-chainaccess-grpc/  # gRPC service + server binary (drop-in replacement)
├── proto/ccv/chainaccess/v1/  # the wire contract (ccv.chainaccess.v1.SourceReader)
├── grpc-client-go/            # Go client: chainaccess.SourceReader over gRPC
├── differential-go/           # Go ground-truth CLI used by the differential tests
└── scripts/fetch_logs.py      # historical-log corpus fetcher
```

Properties claimed (and how to validate each below):

1. **Behavioral parity with the Go EVM SourceReader** — golden vectors + differential testing.
2. **No panics** — all fallible operations return errors; enforced by lint gates.
3. **Stateless; survives no-notice shutdown** — no persistent state anywhere in the stack.
4. **One chain family per implementation** — this one covers any EVM chain exposing the
   standard `eth_*` JSON-RPC API. Exceptions called out: chains without the `safe`
   tag get `None` from `latest_safe_block` (supported); chains without the
   `finalized` tag are not supported.
5. **100% line coverage** of all functions (llvm-cov).
6. **Backtested against historical logs** — 708 real `CCIPMessageSent` events from
   Sepolia's OnRamp v2.0.0.

## Prerequisites

- Rust (the repo pins Alloy to 1.6.3, the newest line supporting rustc 1.90; on
  rustc ≥ 1.91 the pins in `rust/Cargo.toml`/`Cargo.lock` can be relaxed).
- Go (only for the differential tests — they drive the Go implementation as ground
  truth). Without `go` in PATH those two tests skip themselves.
- protoc (only if you regenerate the gRPC code after editing the `.proto`).
- For coverage measurement: `rustup component add llvm-tools-preview && cargo install cargo-llvm-cov`.

## Validate the claims

| Claim | Command | Expected |
|---|---|---|
| Everything builds & all tests pass | `cargo test --workspace` | 53 passed, 0 failed |
| No panics in library code | `cargo clippy --workspace --all-targets` | 0 warnings; `unwrap`/`expect`/`panic`/indexing are `deny` in non-test code |
| Line coverage 100% | `cargo llvm-cov --workspace --summary-only` | no zero-count lines in the lcov export |
| Go builds/vets (client + harness) | `go build ./rust/... && go vet ./rust/...` (from repo root) | clean |
| Historical backtest | see "Backtest" below | exactly 708 events on Sepolia |
| Differential vs Go | see "Differential tests" below | all cases agree |

For the coverage claim, inspect the line-level export rather than the summary table
(the table's region-based aggregation shows a residual artifact; the lcov export is
authoritative for line coverage):

```bash
cargo llvm-cov --workspace --lcov --output-path /tmp/cov.lcov
grep -c '^DA:.*,0$' /tmp/cov.lcov   # -> 0
```

## Backtest (any EVM chain)

`crates/ccv-chainaccess/examples/backtest.rs` runs the reader over a historical
block range against a live RPC: it scans for events, verifies every event block's
header is fetchable, and exercises the head tracker and RMN curse reader.

```bash
cargo run -p ccv-chainaccess --example backtest -- \
  <rpc_url> <on_ramp_address> <rmn_remote_address> <chain_selector> <from_block> <to_block> [chunk_size]
```

Sepolia reference run (must print `total events ... : 708`):

```bash
cargo run -p ccv-chainaccess --example backtest -- \
  https://rpc.sepolia.ethpandaops.io \
  0x181Ac7dC295f1C8C87342d07CFaBA90bC477DB5d \
  0xF094E1dB26Ce8C76C9fF0bD0566Bb8EEfF1b76dd \
  16015286601757825753 10970571 11522733 5000
```

Notes:

- `chunk_size` must stay under the endpoint's `eth_getLogs` block-range limit
  (the error tells you the limit; 5000 is safe for most public endpoints).
- **Beware flaky endpoints**: during development, a public RPC silently dropped
  logs, returning three different partial counts for identical queries. If a count
  matters, validate it against a second endpoint (see `--compare` below).

## Differential tests

Two suites run the Go implementation (via `differential-go`) and this code over the
same inputs and require identical outcomes:

```bash
# Message codec fuzz: random valid messages, mutations, garbage — both sides must
# agree on accept/reject, error class, re-encoded bytes, and message ID.
cargo test -p ccv-protocol --test differential_go

# Event pipeline: 708 historical Sepolia logs + deterministic mutations — both
# sides must agree on accept/skip, the skip-reason code, and all output fields.
cargo test -p ccv-chainaccess --test differential_go_events
```

Tunables (deterministic by default, seeded):

| Env var | Default | Meaning |
|---|---|---|
| `CCV_DIFF_ITERS` | 300 | codec fuzz iterations (5 cases each) |
| `CCV_DIFF_SEED` | fixed | RNG seed (hex ok) |
| `CCV_DIFF_MUTATIONS_PER_LOG` | 3 | mutants per historical log (first 200 logs) |

Example longer run: `CCV_DIFF_ITERS=10000 cargo test -p ccv-protocol --test differential_go`

### Against another EVM chain

1. Fetch a corpus of historical `CCIPMessageSent` logs for that chain's OnRamp:

   ```bash
   python3 rust/scripts/fetch_logs.py \
     --rpc <rpc_url> --address <on_ramp_address> \
     --from-block <N> --to-block <M> --chunk 5000 \
     --out my_chain_logs.json
   ```

   OnRamp/RMN Remote addresses and chain selectors for CCV deployments are in
   `build/devenv/env-*.toml` in this repo (the v2.0.0 `OnRamp` entries).

2. Validate the corpus against a second endpoint (guards against silent log
   dropping):

   ```bash
   python3 rust/scripts/fetch_logs.py --rpc <another_rpc> ...same args... --out my_chain_logs_b.json
   python3 rust/scripts/fetch_logs.py --compare my_chain_logs.json my_chain_logs_b.json
   ```

3. Run the differential test against it:

   ```bash
   CCV_DIFF_CORPUS=my_chain_logs.json \
   CCV_DIFF_ONRAMP=<on_ramp_address> \
   CCV_DIFF_CHAIN_SELECTOR=<selector> \
   CCV_DIFF_RMN=<rmn_remote_address> \
     cargo test -p ccv-chainaccess --test differential_go_events
   ```

   The mutation corpus (byte flips, truncations, trailing garbage, corrupted
   topics) is generated from your logs, so the differential coverage follows the
   chain automatically.

## Run the gRPC server

```bash
CCV_EVM_RPC_URL=<rpc_url> \
CCV_ON_RAMP_ADDRESS=<0x...> \
CCV_RMN_REMOTE_ADDRESS=<0x...> \
CCV_CHAIN_SELECTOR=<u64> \
CCV_LISTEN_ADDR=0.0.0.0:50051 \
  cargo run -p ccv-chainaccess-grpc
```

The server holds no state; SIGINT drains gracefully, SIGKILL is safe. On the Go
side, swap the in-process reader for the gRPC client:

```go
import (
    "google.golang.org/grpc"
    grpcclient "github.com/smartcontractkit/chainlink-ccv/rust/grpc-client-go"
)

conn, _ := grpc.NewClient(addr, grpc.WithTransportCredentials(...))
var reader chainaccess.SourceReader = grpcclient.New(conn)
```

## Regenerating gRPC code

```bash
# Rust (tonic) — happens automatically on cargo build via build.rs
# Go client:
cd rust && protoc -I proto \
  --go_out=grpc-client-go/pb --go_opt=paths=source_relative \
  --go-grpc_out=grpc-client-go/pb --go-grpc_opt=paths=source_relative \
  proto/ccv/chainaccess/v1/source_reader.proto
```
