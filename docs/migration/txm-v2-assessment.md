# TXM v2 assessment for standalone EVM executors

## Context

CL-mode production executors use the database-backed TXM v1. Standalone uses chainlink-evm's TXM
v2. Cutover gives the standalone executor a fresh transmitter, so no v1 nonce or pending-transaction
state is transferred; this decision is about operation after cutover, not live state migration.

## Advantages

- TXM v2 fits the standalone boundary. It provides nonce management, gas estimation, fee bumping,
  retries, signing, and multi-node broadcast without importing the Chainlink node's EVM database
  schemas and lifecycle.
- It reuses chainlink-evm's production client, estimator, head notifications, and TXM components
  instead of maintaining a CCV-specific transaction sender.
- Standalone detects nonce gaps after a restart, waits 90 seconds for old transactions to confirm,
  and then submits fee-bumped replacements so the executor can re-drive the original messages.

## Disadvantages, gaps, and risks

- Unlike v1, v2 stores transactions, attempts, and receipts in memory. A restart loses the original
  payload. Recovery can only infer missing nonces and replace them with empty transactions; this can
  delay later transactions, cost additional gas, and is skipped if the startup nonce reads fail.
- CCV currently mirrors the upstream v2 builder so it can retain the in-memory store for recovery.
  That local assembly can drift when chainlink-evm changes.
- The standalone path does not support forwarders or dual broadcast, and it leaves `AutoPurge`
  disabled. These are gaps wherever the production node relies on those features.
- Node-config conversion preserves RPC nodes, finality, and an explicit v2 block time, but not the
  v1 `GasEstimator`, `NodePool`, `HeadTracker`, or other `Transactions` tuning. Send-only nodes are
  dropped. If no v2 block time is present, standalone uses 2 seconds, which can retry and bump too
  aggressively on slower chains.
- V2 is not the current production baseline for this fleet, so it has less directly comparable
  operating history than v1.

## Recommendation

Proceed with TXM v2 for standalone rather than porting v1. The fresh transmitter avoids translating
v1 nonce and pending-transaction records into v2, while porting v1 would couple standalone to
Chainlink node database schemas and their migrations.

Make production cutover conditional on three checks: set and review `txm_block_time` and effective
gas/TXM/node settings per chain; confirm forwarders, dual broadcast, send-only capacity, and
`AutoPurge` are not required or provide equivalents; and pass a canary restart with transactions in
flight on representative chains. Track a durable v2 store and removal of the local builder copy as
follow-up work. Until then, in-memory restart recovery is an accepted residual risk and rollout
should remain staged and monitored.
