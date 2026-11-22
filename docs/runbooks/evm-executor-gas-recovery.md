# EVM executor gas recovery

Use this runbook for under-gassed Solana-to-Sepolia messages and messages queued behind their rejected transactions. It distinguishes the config-only stopgap available on `v0.22.1` from the permanent behavior in the next executor release.

## Incident mechanics

Sepolia's active calldata floor is:

```text
15,000 + 64 × len(calldata)
```

For example, 10,372 bytes require 678,808 gas, so a 574,980-gas transaction has a 103,828-gas deficit. Zero bytes cost 64 like every other byte; do not use the older mixed zero/nonzero formula or `eth_estimateGas` as an exact floor.

Glamsterdam activated before the standalone cutover. CL nodes' TXM v1 discarded deterministic fatal first broadcasts and reused their nonces, so other messages continued. Standalone TXM v2 was built with a nil error handler, retaining the rejected head transaction. After ten failed attempts, a five-transaction in-flight cap stopped later work and each executor's next turn fanned the same rejection across the pool.

The Arbitrum lane was already migrated: its 934,856-gas example decomposes into 400,000 base + 400,000 receiver + 85,000 verification + `64 × 779` bytes. Solana's configuration was not equivalently migrated.

## Path 1: config-only stopgap for the current deployment

Use this path on `v0.22.1`, before the fixed release is available.

### 1. Set Sepolia gas and purge configuration

Apply through the normal executor configuration pipeline, not an ad-hoc ConfigMap or JD edit:

```toml
[EVM.GasEstimator]
LimitMultiplier = '2'
EstimateLimit = false

[EVM.Transactions.AutoPurge]
Enabled = true
Threshold = 50
```

`LimitMultiplier = 2` covers the observed under-gassing and also applies with estimation disabled and on fee bumps. It increases the up-front balance each transaction requires; validate transmitter balances before rollout. Keep `EstimateLimit = false`: if an RPC estimate exceeds the multiplied cap, attempt creation fails before its attempt counter advances and AutoPurge cannot fire.

AutoPurge treats a never-broadcast transaction with ten attempts as stuck and replaces it with an empty transaction at the same nonce. Sepolia's 200,000 `LimitTransfer` covers that empty transaction. At a 12-second TXM tick this takes about two minutes and is independent of `Threshold`; the positive 50-block threshold is required for transactions that did broadcast successfully.

### 2. Expand the rediscovery window temporarily

Set `startup_lookback_window = "8h0m0s"` for the recovery restart. The default one-hour window would skip messages already dropped from a wedged TXM queue. `max_retry_duration` is eight hours, so older messages are expired and must be handled through the manual-execution path instead of automatic rediscovery.

Restore `startup_lookback_window = "1h0m0s"` after the backlog clears.

### 3. Restart with verification gates

Set the target context and record the current errors:

```bash
CTX=griddle-platform-ccip-prod-teamccipadmin
NS=chainlink-ccv-testnet
kubectl --context "$CTX" -n "$NS" logs deploy/executor-evm-0 -c executor-evm-0 --since=15m \
  | grep -E 'intrinsic gas too low|floor data gas|Reached transaction limit|LocalNonce'
```

Restart one affected executor:

```bash
kubectl --context "$CTX" -n "$NS" rollout restart deploy/executor-evm-0
kubectl --context "$CTX" -n "$NS" rollout status deploy/executor-evm-0 --timeout=10m
```

The restart clears in-memory TXM entries. Rejected transactions never reached the mempool, so there is no nonce orphan to recover. The coordinator re-reads awaiting messages, but the multiplied gas limit prevents another identical rejection.

Allow 90 seconds for orphan recovery plus several leader-election and TXM cycles. Continue to waves of at most two executors only when:

- New attempts use the multiplied gas limit.
- No new `intrinsic gas too low` or `insufficient gas for floor data gas cost` error appears.
- The pending nonce advances and transactions confirm.
- AutoPurge clears any remaining rejected heads rather than repeatedly broadcasting them.
- Previously queued small messages begin executing.

```bash
kubectl --context "$CTX" -n "$NS" rollout restart deploy/executor-evm-1 deploy/executor-evm-2
kubectl --context "$CTX" -n "$NS" rollout status deploy/executor-evm-1 --timeout=10m
kubectl --context "$CTX" -n "$NS" rollout status deploy/executor-evm-2 --timeout=10m
```

Repeat for the remaining affected deployments, then roll the rest in the same controlled waves. Keep the expanded lookback until every executor has restarted.

## Path 2: fixed release behavior

The next executor release adds deterministic first-broadcast recovery: `intrinsic gas too low` and `insufficient gas for floor data gas cost` are marked fatal on the first broadcast, the rejected transaction is discarded, and the next transaction immediately reuses its nonce. Later attempts are not rewound because that could collide with subsequent in-flight nonces. AutoPurge remains the backstop for later attempts, mempool-stuck transactions, and unmatched errors such as the per-transaction gas cap.

Each discard increments `executor_txm_discarded_transactions_total{chainID}` and logs the CCIP message IDs from TXM metadata. Use both to verify recovery and build alerts.

Deploy it with the same expanded lookback and canary/wave procedure. Keep `LimitMultiplier = 2` on testnet while the backlog drains: it is a separate testnet-only top-up, and removing it before the Solana migration would leave stale messages unexecuted or requiring manual execution. Do not carry that multiplier into mainnet configuration before product decides.

A restart alone is not the fix: without the handler or the multiplier, rediscovery simply creates the same under-gassed transaction and wedges the key again.

## Full Solana Glamsterdam migration

Do not change only the per-byte value. Use the normal reviewed Solana administration path and migrate every corresponding field:

- Router `base_execution_gas_cost`: EVM reference 200,000 → 400,000.
- Fee Quoter `dest_gas_per_payload_byte_base`: 20 → 64.
- Fee Quoter `default_tx_gas_limit`: EVM reference 200,000 → 400,000.
- Fee Quoter `default_token_dest_gas_overhead`: EVM reference 90,000 → 270,000.
- Committee Verifier `gas_for_verification`: EVM reference 75,000 → 85,000.
- Token-pool and per-token gas overrides, including legacy `DestGasOverhead` and USDC/Lombard-specific values. Review actual current values instead of applying EVM literals blindly.

Changing only the per-byte field can move failures from RPC rejection to on-chain revert. Audit other non-EVM sources sending to Sepolia for the same gap. The release and multiplier can recover already-verified messages, but full source migration is required for correct pricing and execution of new messages.

The Sepolia destination PDA and account can be inspected without signing:

```bash
NO_DNA=1 solana find-program-derived-address \
  FeeQPGkKDeRV1MgoYfMH6L8o3KeuYjwUZrgn4LRKfjHi \
  string:dest_chain_v2 u64le:16015286601757825753
NO_DNA=1 solana account J9HrUpKLDC2RH3oJoESFFM1jXJFhT4dU2mUY1vsqRBpM -u devnet --output json
```

Validate account owner, chain selector, and all decoded configuration fields after the migration.

## Verification and stop conditions

Useful incident checks include:

- `0xbd285f7fba23af53bd57ef9df6b3124420db800a69590c9fd97fb4cf2d34e1a3` executes after being queued. Its manual estimate was 270,615 gas and its automatic message limit was 947,656 gas.
- No executor repeats a rejected transaction thousands of times or reports `Reached transaction limit` with a stuck pending nonce.
- `Discarded transaction rejected on its first broadcast` logs include the expected CCIP message IDs, and `executor_txm_discarded_transactions_total` increases only for deterministic first-broadcast rejections.

Query message status rather than treating TXM submission as execution proof. If the public indexer endpoint is unavailable, use a read-only port-forward:

```bash
kubectl --context "$CTX" -n "$NS" port-forward deploy/chainlink-ccv-indexer-1 18100:8100
curl -sS 'http://127.0.0.1:18100/v1/messages?destChainSelectors=16015286601757825753&sourceChainSelectors=3478487238524512106&limit=100'
```

Stop the rollout if deterministic rejections are not discarded, the multiplier is absent, or new RPC errors appear. Keep a working canary running and investigate; do not roll back to `v0.22.1` without a mitigation, because that recreates the rejected transactions and nonce blockage.

Messages older than the eight-hour retry window require the reviewed manual-execution path. Do not repeatedly restart or manually replace nonces to make them disappear from TXM logs.
