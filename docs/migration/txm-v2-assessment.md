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
  dropped. If no v2 block time is present, standalone uses a curated per-chain default for chains
  whose real block interval exceeds the 2s validation floor (Ethereum, Rootstock, Gnosis, and
  similar), and 2 seconds otherwise — acceptable for fast chains, which the floor already serves.
- V2 is not the current production baseline for this fleet, so it has less directly comparable
  operating history than v1.

## Recommendation

Proceed with TXM v2 for standalone rather than porting v1. The fresh transmitter avoids translating
v1 nonce and pending-transaction records into v2, while porting v1 would couple standalone to
Chainlink node database schemas and their migrations.

Make production cutover conditional on three checks: review `txm_block_time` per chain in the
pre-cutover diff (an operator-set value always wins; `txm_block_time_source` says whether a curated
chain default or the generic 2s fallback produced the reported value) along with the effective
gas/TXM/node settings; confirm forwarders, dual broadcast, send-only capacity, and
`AutoPurge` are not required or provide equivalents; and pass a canary restart with transactions in
flight on representative chains. Track a durable v2 store and removal of the local builder copy as
follow-up work. Until then, in-memory restart recovery is an accepted residual risk and rollout
should remain staged and monitored.
