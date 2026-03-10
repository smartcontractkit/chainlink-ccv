# Smoke test failure reference

This doc summarizes common failure patterns and custom error selectors seen when running `ccv test smoke`.

---

## 1. Execution timeout: "failed to wait for exec event: context deadline exceeded"

**Failing tests:** e.g. `custom_executor`, `receiver_w/_secondary_verifier_required`, `max_data_size`, and other `extra_args_v3_messaging` cases.

**What happens:** The message is sent (CCIPMessageSent), verifier results appear in the aggregator and indexer, but the test never sees `ExecutionStateChanged` on the destination chain before the context deadline.

**Likely causes:**
- **Executor not executing:** The executor may not be picking up the message or may be failing before submitting the execution tx (e.g. indexer unreachable, or `GetCCVSForMessage` reverting with `0x97a63cd9` so the executor cannot resolve CCV quorum).
- **Execution reverted on-chain:** The execution tx is submitted but reverts (e.g. receiver revert, gas, or CCV check).
- **Indexer / coordinator delay:** Verifier results or execution state are visible only after the test timeout.

**What to check:** Executor logs (whether it processes the message and submits a tx), destination chain for reverted execution txs, and indexer/aggregator latency.

---

## 2. Fee quote revert: "send message: failed to get fee" with `0xbf16aab6`

**Failing tests:** Most `extra_args_v3_token_transfer` cases (all except the ones using the **secondary** committee verifier token pool).

**Error:** `execution reverted: custom error 0xbf16aab6: 000000000000000000000000<address>`. The argument is a 20-byte address (token or pool).

**Where it happens:** `Router.GetFee()` (or the FeeQuoter path it uses) is called to get the fee for the token transfer; the contract reverts with this selector.

**Likely meaning:** The fee path does not support this token/pool for the requested lane (e.g. "TokenNotSupported" or "PoolNotFound" for that address). In your runs, the **secondary** pool qualifier works; **default** and other qualifiers do not, which suggests fee configuration or pool registration differs by qualifier.

**What to check:** FeeQuoter and router configuration for the token/pool addresses and destination chain; ensure every token combination used by the test has a valid fee path and pool registration.

---

## 3. Fee / finality revert: `0x98d50fd7` (no args)

**Seen in:** Token transfer when using an unsupported finality config (e.g. Lombard with custom finality), or fee quote for the secondary-only pool in some flows.

**Likely meaning:** Contract rejects the request (e.g. "UnsupportedFinality" or similar). One test expects this revert and passes when it occurs.

---

## 4. USDC send revert: `0xa9902c7e` with destination chain selector

**Failing tests:** All `TestE2ESmoke_TokenVerification/USDC_v3_token_transfer/*` (except where skipped).

**Error:** `execution reverted: custom error 0xa9902c7e: 0000...00b356733e229244f2`. The argument is the **destination chain selector** (uint256).

**Meaning:** The USDC token pool (or router) on the source chain is reverting with "destination chain not allowed": the destination chain is not in the pool’s allowlist.

**What to check:** Ensure `ConfigureTokensForTransfers` runs before `ConnectContractsWithSelectors` and that the CCTP/USDC configuration (e.g. `configureUSDCForTransfer`) actually adds the destination chain to the USDC pool’s allowlist for every lane used by the test.

---

## 5. Lombard send revert: `0xbce7b6cd` with (uint256, address)

**Failing tests:** `Lombard_transfer_to_EOA_receiver_with_chain_finality`, `Lombard_transfer_to_contract_receiver_with_chain_finality`.

**Error:** `custom error 0xbce7b6cd` with two 32-byte args (e.g. zero and the Lombard token address).

**Meaning:** The Lombard token pool or router is rejecting the send (e.g. "token not allowed for chain" or "lane not configured").

**What to check:** Lombard lane configuration: that the Lombard pool has the destination chain and token correctly configured via `configureLombardForTransfer` (and any token transfer config that applies to Lombard).

---

## 6. GetCCVSForMessage revert: `0x97a63cd9` (executor path)

**Seen in:** Executor logs when it calls the destination chain to get CCV requirements for a message. Error data is `(address, uint256, uint256)` (e.g. receiver/verifier, required, actual).

**Effect:** The executor cannot resolve verifier quorum and may not submit an execution tx, which can lead to tests failing with "failed to wait for exec event: context deadline exceeded".

**What to check:** That the message’s receiver contract is deployed on the destination chain and implements `get_ccvs` (or the interface used by the OffRamp) without reverting; that the receiver and token in the message match a valid receiver configuration.

---

## Summary table

| Selector    | Context              | Typical meaning                          |
|------------|----------------------|------------------------------------------|
| `0xa9902c7e` | USDC send            | Destination chain not in pool allowlist  |
| `0xbce7b6cd` | Lombard send         | Token/lane not allowed or not configured |
| `0xbf16aab6` | GetFee / token transfer | Token or pool not supported for fee      |
| `0x97a63cd9` | GetCCVSForMessage   | Receiver CCV requirements not resolvable |
| `0x98d50fd7` | Fee / finality      | Unsupported finality or invalid request  |
