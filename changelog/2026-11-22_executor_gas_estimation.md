# Executor gas estimation and deterministic rejection recovery

## Executive Summary

- EVM execution now estimates the complete OffRamp transaction with the selected transmitter before creating a TXM transaction.
- The gas limit is the larger of the message-derived limit and the RPC estimate with a 15% buffer, covering stale source-chain calldata prices and current destination rules.
- Estimation failures return a retryable error before TXM assigns a nonce, preventing invalid attempts from blocking later messages.
- Deterministic first-broadcast gas rejections are discarded and their nonces reused, matching TXM v1 behavior and preventing a rejected message from holding the queue.
- Standalone and legacy executor construction enable the estimator; existing constructor calls remain source-compatible.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `contracttransmitter.GasEstimator` | added | `GasEstimator` | `integration/pkg/contracttransmitter/txm_evm_contract_transmitter.go:36` | [#gas-estimation](#gas-estimation) |
| `contracttransmitter.WithGasEstimator` | added | `WithGasEstimator\(` | `integration/pkg/contracttransmitter/txm_evm_contract_transmitter.go:44` | [#construction](#construction) |
| `contracttransmitter.NewEVMContractTransmitterFromTxm` | behavior-changed | `NewEVMContractTransmitterFromTxm\(` | `integration/pkg/contracttransmitter/txm_evm_contract_transmitter.go:68` | [#construction](#construction) |
| `contracttransmitter.TXMEVMContractTransmitter.ConvertAndWriteMessageToChain` | behavior-changed | `ConvertAndWriteMessageToChain\(` | `integration/pkg/contracttransmitter/txm_evm_contract_transmitter.go:94` | [#gas-estimation](#gas-estimation) |
| `evm.deterministicTxErrorHandler.HandleError` | added | `deterministicTxErrorHandler` | `integration/pkg/accessors/evm/txm_error_handler.go:16` | [#deterministic-rejection-handling](#deterministic-rejection-handling) |

## Breaking Changes

*No breaking changes.* `NewEVMContractTransmitterFromTxm` gains an optional variadic `TransmitterOption`; existing calls compile unchanged. Callers that do not supply `WithGasEstimator` fail closed during message processing rather than submitting an unestimated transaction.

## Gas estimation

`TXMEVMContractTransmitter` ABI-packs the report and selects the round-robin sender as before. It then calls `eth_estimateGas` with that sender, the OffRamp address, and the exact execute payload.

The submitted gas limit is:

```text
messageLimit = ExecutionGasLimit + EIP150ForwardingBuffer(CcipReceiveGasLimit)
submissionLimit = max(messageLimit, estimatedGas * 1.15)
```

The message limit remains a floor, so the existing EIP-150 compensation is preserved when the RPC estimate is lower. The buffer is applied by `chainlink-framework/chains/fees.ApplyMultiplier`, including overflow checks.

A missing estimator, a zero estimate, an estimation RPC error, or buffer overflow returns an error before `TxmClient.CreateTransaction`. The executor's existing `ErrExecutionContended` path schedules a retry. These errors are not counted as unrecoverable message failures; a TXM creation error is no longer counted as unrecoverable either.

## Construction

Both production construction paths supply their existing chain client through `WithGasEstimator`:

- Standalone: `integration/pkg/accessors/evm/standalone_chain.go:363`
- Legacy: `integration/pkg/constructors/executor.go:122`

Estimation happens at message-processing time. Constructors and `Start` perform no additional network I/O.

## Deterministic rejection handling

`newTxmV2` now installs `deterministicTxErrorHandler` instead of a nil error handler. On the first broadcast only, it handles both `intrinsic gas too low` and `insufficient gas for floor data gas cost`, including RPC suffixes with actual and required gas.

The handler calls `MarkTxFatal`, rewinds the just-assigned nonce, and lets the next transaction reuse it. Later attempts are deliberately ineligible: rewinding then could collide with transactions already assigned subsequent nonces. This mirrors TXM v1's fatal first-broadcast behavior rather than relying on AutoPurge's ten-attempt delay.

## Recovery

The release does not update source-chain fee-quoter configuration. It allows already-verified messages carrying stale gas limits to be resubmitted with current destination-chain estimates.

See `docs/runbooks/evm-executor-gas-recovery.md` for the config-only stopgap and release recovery paths, the eight-hour lookback, and the full Solana Glamsterdam migration required for sustainable source-side pricing and execution.

## Verification

`integration/pkg/contracttransmitter/txm_evm_contract_transmitter_test.go` covers:

- Raising a stale 574,980-gas message limit from a 678,808-gas RPC estimate to 780,629 gas.
- Sender, OffRamp, and payload propagation into the estimator.
- Preserving the message limit when it exceeds the estimate.
- Zero estimates, estimator absence, buffer overflow, and RPC failure.
- No `CreateTransaction` call after estimation failure.

`integration/pkg/accessors/evm/txm_error_handler_test.go` additionally covers both rejection strings, nonce reuse by the next transaction, and preservation of later-attempt and unrelated transactions.

## References

- Prior TXM recovery change: `2026-11-06_standalone_txm_v2_recovery.md`
- TXM v2 assessment: `docs/migration/txm-v2-assessment.md`
