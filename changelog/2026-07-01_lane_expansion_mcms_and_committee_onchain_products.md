# Lane expansion MCMS + committee-verifier onchain products (finality & allowlist)

## Executive Summary

- Adds two committee-verifier onchain products — `SetAllowedFinalityConfig` and `UpdateSenderAllowlist` — as single-entry, onchain-only changesets, plus the adapter methods that back them.
- Adds MCMS timelock-proposal support to the `LaneExpansion` and `PromoteLaneRouter` changesets: onchain lane writes can now be packaged into a timelock proposal instead of only deployer-key execution.
- Reworks lane configuration so remote-chain ramps are resolved via the *remote* chain's own adapter (family-correct encoding), which required two new methods on `LaneConfigAdapter`.
- Breaking for anyone implementing `CommitteeVerifierOnchainAdapter` or `LaneConfigAdapter` outside this repo (non-EVM families): both interfaces gained methods. The EVM implementations are provided here.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `adapters.CommitteeVerifierOnchainAdapter.SetAllowedFinalityConfig` | added | `\bSetAllowedFinalityConfig\b` | `deployment/adapters/committee_verifier_onchain.go:36` | [#committeeverifieronchainadapter-new-methods](#committeeverifieronchainadapter-new-methods) |
| `adapters.CommitteeVerifierOnchainAdapter.ApplyAllowlistUpdates` | added | `\bApplyAllowlistUpdates\b` | `deployment/adapters/committee_verifier_onchain.go:51` | [#committeeverifieronchainadapter-new-methods](#committeeverifieronchainadapter-new-methods) |
| `adapters.LaneConfigAdapter.GetOnRampAddress` | added | `\bGetOnRampAddress\b` | `deployment/adapters/lane_config.go:90` | [#laneconfigadapter-new-methods](#laneconfigadapter-new-methods) |
| `adapters.LaneConfigAdapter.GetOffRampAddress` | added | `\bGetOffRampAddress\b` | `deployment/adapters/lane_config.go:97` | [#laneconfigadapter-new-methods](#laneconfigadapter-new-methods) |
| `adapters.RemoteLaneConfig` (fields) | signature-changed | `\bRemoteLaneConfig\b` | `deployment/adapters/lane_config.go:43` | [#remotelaneconfig-new-fields](#remotelaneconfig-new-fields) |
| `changesets.LaneExpansionInput.MCMS` | added | `LaneExpansionInput{` | `deployment/changesets/lane_expansion.go:84` | [#mcms-on-lane-changesets](#mcms-on-lane-changesets) |
| `changesets.PromoteLaneRouterInput.MCMS` | added | `PromoteLaneRouterInput{` | `deployment/changesets/promote_lane_router.go:41` | [#mcms-on-lane-changesets](#mcms-on-lane-changesets) |
| `changesets.LaneChainOverrides.InboundSigners` / `.InboundThreshold` | added | `\bLaneChainOverrides\b` | `deployment/changesets/lane_expansion.go:49` | [#inbound-signers-on-lane-overrides](#inbound-signers-on-lane-overrides) |
| `changesets.SetAllowedFinalityConfig` | added | `\bSetAllowedFinalityConfig\(` | `deployment/changesets/set_allowed_finality_config.go:51` | [#new-changeset-setallowedfinalityconfig](#new-changeset-setallowedfinalityconfig) |
| `changesets.UpdateSenderAllowlist` | added | `\bUpdateSenderAllowlist\(` | `deployment/changesets/update_sender_allowlist.go:45` | [#new-changeset-updatesenderallowlist](#new-changeset-updatesenderallowlist) |

Rows not listed are unchanged. `SetAllowedFinalityConfigInput` and `UpdateSenderAllowlistInput` are the inputs to the two new changesets and are covered in their sections.

## Breaking Changes

### `CommitteeVerifierOnchainAdapter` new methods

- **What changed:** `deployment/adapters/committee_verifier_onchain.go` — the `CommitteeVerifierOnchainAdapter` interface gained two methods.
- **Before:** interface had `ApplySignatureConfigs` (and the scan method) only.
- **After:** implementers must also provide:

```go
SetAllowedFinalityConfig(
    ctx context.Context,
    env deployment.Environment,
    chainSelector uint64,
    qualifier string,
    waitForFinality bool,
    waitForSafe bool,
    blockDepth uint16,
) error

ApplyAllowlistUpdates(
    ctx context.Context,
    env deployment.Environment,
    chainSelector uint64,
    qualifier string,
    destChainSelector uint64,
    allowlistEnabled bool,
    addedSenders []string,
    removedSenders []string,
) error
```

- **Why:** back the two new onchain changesets (`SetAllowedFinalityConfig`, `UpdateSenderAllowlist`). Finality is passed as primitives (not a chain-family finality encoding) and senders as family-native strings so the `deployment` package stays chain-agnostic; the adapter encodes them for its family and, in deployer-key mode, submits the tx and blocks until mined.
- **Who is affected:** any non-EVM implementation of `CommitteeVerifierOnchainAdapter`. The EVM implementation is added in this PR (`integration/evm/adapters/ccv_committee_verifier_onchain.go`).

### `LaneConfigAdapter` new methods

- **What changed:** `deployment/adapters/lane_config.go` — the `LaneConfigAdapter` interface gained two methods.
- **Before:** interface exposed `ConfigureLane()` only.
- **After:** implementers must also provide:

```go
GetOnRampAddress(ds datastore.DataStore, chainSelector uint64) ([]byte, error)
GetOffRampAddress(ds datastore.DataStore, chainSelector uint64) ([]byte, error)
```

- **Why:** the lane changeset now resolves a *remote* chain's ramps by calling these on the remote chain's adapter, so the address bytes are encoded for the remote family. Return value is the family's native byte encoding (20 bytes for EVM).
- **Who is affected:** any non-EVM implementation of `LaneConfigAdapter`. EVM is implemented here (`integration/evm/adapters/lane_config_adapter.go`), delegating to the EVM chain-family adapter's `GetOnRampAddress` / `GetOffRampAddress`.

If you maintain no out-of-repo adapter implementations, there are no breaking changes for you.

## Migration Guide

For downstream adapter implementers only:

1. Add `SetAllowedFinalityConfig` and `ApplyAllowlistUpdates` to your `CommitteeVerifierOnchainAdapter` implementation (signatures above). Encode `waitForFinality`/`waitForSafe`/`blockDepth` and the sender strings for your chain family; submit and wait for the tx in deployer-key mode.
2. Add `GetOnRampAddress` and `GetOffRampAddress` to your `LaneConfigAdapter` implementation, returning your family's native address bytes.
3. Test stubs must be updated the same way — see the added stub methods in `deployment/changesets/add_nop_to_committee_test.go` (`stubOnchainAdapter`, `stubFullAdapter`) and `deployment/changesets/lane_expansion_test.go` (`stubLaneConfigAdapter`) for the minimal shape.

No caller-side migration is required for existing `LaneExpansion` / `PromoteLaneRouter` usage: the new `MCMS` field is a pointer and defaults to `nil` (deployer-key execution, unchanged behavior).

## New Features / Additions

### New changeset: `SetAllowedFinalityConfig`

`deployment/changesets/set_allowed_finality_config.go`. Single-entry, onchain-only. Updates the CommitteeVerifier's single allowed-finality config on every chain in `ChainSelectors` where the committee verifier for `CommitteeQualifier` is deployed.

```go
type SetAllowedFinalityConfigInput struct {
    CommitteeQualifier string
    ChainSelectors     []uint64
    WaitForFinality    bool   // full finality; zero-value/default tag, implicit when nothing else is set
    WaitForSafe        bool   // "safe" finality level
    BlockDepth         uint16 // wait up to N block confirmations
}
```

- The three finality fields are OR-combined by the adapter (a verifier can accept more than one level). Validation rejects an all-empty config (would silently mean "wait for finality") — at least one of the three must be set.
- MCMS-mode is deferred (Phase 0, CLD post-proposal-hook prerequisite), matching the other committee onchain products; deployer-key mode only for now.

### New changeset: `UpdateSenderAllowlist`

`deployment/changesets/update_sender_allowlist.go`. Single-entry, onchain-only. Adds/removes senders from a per-destination-chain allowlist on a CommitteeVerifier, or toggles the allowlist on/off for that destination.

```go
type UpdateSenderAllowlistInput struct {
    CommitteeQualifier string
    ChainSelectors     []uint64
    DestChainSelector  uint64   // required; each dest chain has an independent allowlist
    AllowlistEnabled   bool
    AddedSenders       []string // family-native address strings
    RemovedSenders     []string
}
```

- Applied on every chain in `ChainSelectors` where the committee verifier for `CommitteeQualifier` is deployed. `DestChainSelector` is required (validated). MCMS-mode deferred as above.
- Both new changesets share `validateCommitteeOnchainTargets` (qualifier required, ≥1 unique in-env chain selector, registered onchain adapter per family).

### MCMS on lane changesets

`LaneExpansionInput` and `PromoteLaneRouterInput` gained an `MCMS *mcmsutil.Input` field (`github.com/smartcontractkit/chainlink-ccip/deployment/utils/mcms`). When set, the onchain lane writes are packaged into an MCMS timelock proposal instead of being returned for deployer-key execution. `applyLaneConfig` now accumulates per-side `BatchOps` and builds output via `ccipchangesets.NewOutputBuilder(e, ccipchangesets.GetRegistry()).WithReports(...).WithBatchOps(...).WithDataStore(...).Build(mcmsCfg)`. Nil `MCMS` preserves current deployer-key behavior.

The EVM MCMS reader is registered for per-chain timelock resolution via a blank import in `integration/evm/adapters/init.go` (`_ ".../chains/evm/deployment/v1_0_0/adapters"`).

### Inbound signers on lane overrides

`RemoteLaneConfig` and `LaneChainOverrides` gained `InboundSigners []string` + `InboundThreshold uint8`, setting the committee-verifier signature quorum for inbound traffic from the remote chain during initial lane setup. When empty, signatures are left untouched — still owned by the incremental committee changesets (`AddNOPToCommittee` / `IncreaseThreshold` / `DecreaseThreshold`). The shared `ConfigureChainForLanes` sequence treats an empty `SignatureConfig` as "do not touch".

### `RemoteLaneConfig` new fields

Beyond the inbound-signer fields above, `RemoteLaneConfig` gained `RemoteOnRamps [][]byte` and `RemoteOffRamp []byte`: the remote chain's ramp addresses, pre-resolved by the lane changeset via the remote chain's adapter and passed in pre-encoded for the remote family. Empty leaves the current on-chain value untouched. The lane changeset populates these automatically; callers configuring adapters directly may set them.

## Compatibility & Requirements

- **Dependency bumps:** `chainlink-deployments-framework` v0.94.1 → v0.96.0; `chainlink-ccip/deployment` added as a direct dependency (`v0.0.0-20260630184409-79e0c5cd667f`); `chainlink-ccip/chains/evm` and `chainlink-ccip/deployment` bumped in `build/devenv`; `chainlink-ton` bumped (indirect).
- **Test cleanup:** `integration/evm/adapters/deploy_defaults_test.go` removed; a couple of test import paths were corrected (`committee_verifier_deploy_adapter_test.go`, `protocol_contracts_deploy_adapter_test.go`).

## References

- PR: https://github.com/smartcontractkit/chainlink-ccv/pull/1210
- Prior changelog entries this builds on: `2026-06-19_multi_aggregator_committee_verifier.md`, `2026-06-22_multi_aggregator_verifier_part2.md`, `2026-06-11_executor_transmitter_key_registry.md`
