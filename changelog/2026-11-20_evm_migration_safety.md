# EVM standalone migration safety follow-ups

## Executive Summary

- Standalone EVM verifier/executor JD startup now requires an exact bootstrap/EVM chain inventory, and `inspect-config --bootstrap-config` provides an offline pre-shutdown gate.
- Conversion reports redacted before/after broadcast-endpoint counts and explicit operator decisions for `SendOnly`, `HTTPURLExtraWrite`, and `KeySpecific`.
- Standalone verifier `initial_start_blocks` covers long new-verifier-ID handoffs without changing checkpointed restart or disabled-chain behavior.
- Mantle conversion emits `gas_estimator_limit_multiplier = 1`; the shared builder rejects unsafe effective values before TXM construction.
- CCV now ships a balance dashboard, reviewed funding thresholds, and an assigned-inventory generator for low/absent/stale `node_balance` alerts.
- CCV runbooks document NOP-controlled external-wallet funding and legacy panic/crash-loop containment without manual TXM database edits.

## AI Adapter Index

| Symbol | Kind | Search | Location |
|---|---|---|---|
| `bootstrap.WithDeclaredChainInventoryChecker` | added | `WithDeclaredChainInventoryChecker` | `bootstrap/bootstrap.go` |
| `evmconfig.ReconcileChainInventory` | added | `ReconcileChainInventory` | `integration/pkg/accessors/evmconfig/inventory.go` |
| `evmconfig.BroadcastEndpointSummary` | added | `BroadcastEndpointSummary` | `integration/pkg/accessors/evmconfig/broadcast.go` |
| `commit.Config.InitialStartBlocks` | added | `initial_start_blocks` | `verifier/pkg/commit/config.go` |
| `sourcereader.Service.initializeStartBlock` | behavior-changed | `configured initial start block` | `verifier/pkg/sourcereader/service.go` |
| `evmconfig.ChainConfig.GasEstimatorLimitMultiplier` | added | `gas_estimator_limit_multiplier` | `integration/pkg/accessors/evmconfig/config.go` |
| CCV executor balance observability package | added | `CCVExecutorBalanceLow` | `deployment/observability/evm-executor-balance` |

## Behavior Changes

### Exact standalone chain inventory

The two standalone EVM JD binaries opt into exact inventory validation. Empty, missing, extra, duplicate, non-EVM, unknown, and unservable declarations fail before JD registration. Local mode and other bootstrap consumers retain their previous coverage-only behavior.

`ccv migrate inspect-config --config <evm.toml> --bootstrap-config <bootstrap.toml>` prints `chain_inventory` and exits nonzero on a mismatch. It reads no secrets and performs no network, database, or JD calls.

### Conversion and Mantle safety

The report's `broadcast_endpoints` compares legacy and standalone write endpoints without exposing URLs, and `conversion_review_required` identifies reports needing a decision. Mantle mainnet/Sepolia conversion emits a CCV-owned multiplier override of `1`. Standalone hand edits, custom defaults, or other paths that produce another effective Mantle value fail the shared builder used by preflight and runtime construction.

Non-Mantle multipliers remain unchanged. The real dependency estimator regression uses explicit fee limit 694,835 and verifies that the resulting limit remains 694,835 rather than 15,981,205,000.

### Migration-safe first start

`initial_start_blocks` maps canonical chain selectors to the first finalized height to scan when the new verifier ID has no chain-status row. Existing rows still resume at checkpoint plus one and retain `disabled`; the override never rewrites them. A first start above the finalized head is rejected, and ordinary finality/reorg handling remains active.

The committee verifier exposes `validate-config` for stopped-service structural validation. CL mode rejects `initial_start_blocks` rather than silently ignoring it.

### CCV-owned operations assets

The observability package generates three rules per assigned public account/chain pair and fails closed when no approved threshold exists. Its tests include a synthetic 51-chain inventory and histogram-independent queries. Live Prometheus load validation remains an operator gate.

No generic CCV funding helper is added. The supported affected-chain path is an NOP-controlled external wallet. Legacy Mode/Henesys crash causation remains unconfirmed without stack traces.

## Compatibility & Requirements

- These changes target **v0.22.1 (unreleased)**; verify the published release before naming it as the minimum fixed version. v0.22.0 still requires the manual Mantle workaround and coordinated 500-block handoff safeguards.
- Existing standalone JD deployments with incomplete chain declarations must reconcile them before upgrade. Valid local/no-chain consumers are unchanged.
- The new EVM multiplier field is operator-local and does not add a credential or JD secret.
- No upstream Chainlink, chainlink-evm, chainlink-framework, or vm-alerts change is required.
