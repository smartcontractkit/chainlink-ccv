# State-based offchain config inputs (topology-free configuration)

## Executive Summary

- Adds "from state" reconstruction of offchain changeset inputs: committee/verifier and executor-pool inputs are now derivable from live on-chain state + JD + persisted job specs, not only from a `topology.toml` blob.
- Motivation: live environments have no topology blob to fall back on, so the changeset inputs that were previously topology-derived must be inferrable from observed state.
- Affected packages: `chainlink-ccv/deployment/changesets` (new `*FromState` builders, `NOPIdentities`), `chainlink-ccv/deployment` (env-metadata `Merge*` + NOP-signer persistence), and `chainlink-ccv/build/devenv` (inference verification gate; removal of the legacy lane-config path).
- Headline impact: additive in `deployment` (new APIs); **breaking in `build/devenv`** — the legacy `lanes.ConnectChains` path and the `use_legacy_configure_lane` flag are removed, and the bumped chainlink-ccip ref drops the deprecated `ccipChangesets.NewTopologyCommitteePopulator`.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `devenv config key use_legacy_configure_lane` | removed | `use_legacy_configure_lane` | — | [#legacy-lane-config-removed](#legacy-lane-config-removed) |
| `deploy.ConnectAllChainsLegacy` | removed | `ConnectAllChainsLegacy\b` | — | [#legacy-lane-config-removed](#legacy-lane-config-removed) |
| `ccipChangesets.NewTopologyCommitteePopulator` (via ccip ref bump) | removed | `NewTopologyCommitteePopulator\b` | — | [#legacy-lane-config-removed](#legacy-lane-config-removed) |
| `changesets.AggregatorRef` | added | `AggregatorRef\b` | `deployment/changesets/apply_verifier_config.go:312` | [#state-input-builders](#state-input-builders) |
| `changesets.CommitteeInputFromState` | added | `CommitteeInputFromState\b` | `deployment/changesets/state_inputs.go:44` | [#state-input-builders](#state-input-builders) |
| `changesets.ApplyVerifierConfigInputFromState` | added | `ApplyVerifierConfigInputFromState\b` | `deployment/changesets/state_inputs.go:242` | [#state-input-builders](#state-input-builders) |
| `changesets.CommitteeChainSelectorsFromState` | added | `CommitteeChainSelectorsFromState\b` | `deployment/changesets/state_inputs.go:172` | [#state-input-builders](#state-input-builders) |
| `changesets.ExecutorPoolInputFromState` | added | `ExecutorPoolInputFromState\b` | `deployment/changesets/executor_state_inputs.go:48` | [#state-input-builders](#state-input-builders) |
| `changesets.ApplyExecutorConfigInputFromState` | added | `ApplyExecutorConfigInputFromState\b` | `deployment/changesets/executor_state_inputs.go:223` | [#state-input-builders](#state-input-builders) |
| `changesets.NOPIdentities` / `changesets.LoadNOPIdentities` | added | `LoadNOPIdentities\b\|NOPIdentities\b` | `deployment/changesets/nop_identities.go:27` | [#nop-identities](#nop-identities) |
| `deployment.MergeAggregatorConfig` / `MergeIndexerConfig` / `MergeTokenVerifierConfig` | added | `Merge\(Aggregator\|Indexer\|TokenVerifier\)Config\b` | `deployment/env_metadata_util.go:63` | [#env-metadata-merge-and-signers](#env-metadata-merge-and-signers) |
| `deployment.SaveNOPSigners` / `deployment.GetNOPSigners` | added | `\(Save\|Get\)NOPSigners\b` | `deployment/env_metadata_util.go:541` | [#env-metadata-merge-and-signers](#env-metadata-merge-and-signers) |

## Breaking Changes

### Legacy lane-config path removed {#legacy-lane-config-removed}

- **What changed:** `build/devenv` no longer supports the legacy `lanes.ConnectChains` + `CommitteeConfigPopulator` lane-configuration path. The `use_legacy_configure_lane` TOML flag, the `deploy.ConnectAllChainsLegacy` function, and the internal `buildCommitteeVerifierInputs`/`chainEntry` helpers are deleted. Lane configuration always uses `deploy.ConnectAllChainsCanonical` (backed by `ccipChangesets.ConfigureChainsForLanesFromTopology`).
- **Before:** `[protocol_contracts] use_legacy_configure_lane = true` selected `ConnectAllChainsLegacy`, which built a `ccipChangesets.NewTopologyCommitteePopulator` and passed it to `lanes.ConnectChains` via `ConnectChainsConfig.CommitteePopulator`.
- **After:** the flag is gone; `ConnectAllChainsCanonical` is the only path.
- **Why:** the bumped chainlink-ccip ref removes `NewTopologyCommitteePopulator` (the deprecated 2.0 populator) along with the chainlink-ccip-side offchain/committee-verifier changesets, which are superseded by `chainlink-ccv/deployment/changesets`. The legacy branch can no longer compile.
- **Who is affected:** any devenv TOML setting `use_legacy_configure_lane`, and any external caller of `deploy.ConnectAllChainsLegacy` or `ccipChangesets.NewTopologyCommitteePopulator`.

## Migration Guide

For `build/devenv` config consumers:

1. Remove `use_legacy_configure_lane` from any `[protocol_contracts]` TOML section — the key is no longer decoded (strict decoding will reject it).
2. Replace any direct call to `deploy.ConnectAllChainsLegacy(...)` with `deploy.ConnectAllChainsCanonical(...)` (identical signature).

```go
// Before
if cfg.UseLegacyConfigureLane {
    err = deploy.ConnectAllChainsLegacy(impls, blockchains, selectors, env, topology)
} else {
    err = deploy.ConnectAllChainsCanonical(impls, blockchains, selectors, env, topology)
}
```

```go
// After
err = deploy.ConnectAllChainsCanonical(impls, blockchains, selectors, env, topology)
```

For consumers of the chainlink-ccip ref bumped here: the chainlink-ccip offchain changesets (`ApplyExecutorConfig`, `GenerateAggregatorConfig`, `GenerateIndexerConfig`, `GenerateTokenVerifierConfig`, `ApplyVerifierConfig`) and `NewTopologyCommitteePopulator` are removed upstream. Use the `chainlink-ccv/deployment/changesets` equivalents and `ConfigureChainsForLanesFromTopology` for on-chain lane configuration.

## New Features / Additions

State-based ("topology-free") input reconstruction. See `deployment/changesets/state_inputs.go`, `executor_state_inputs.go`, `nop_identities.go`.

- **`CommitteeInputFromState` / `ApplyVerifierConfigInputFromState`** {#state-input-builders} — reconstruct verifier/committee changeset inputs from observed state: committee membership is read on-chain (`adapters.AllDeployedCommitteeVerifierChains` → scan signature configs → map signers to NOP aliases). Aggregators are supplied by the caller via `VerifierConfigFromStateOptions`. Bootstrap-safe: no deployed verifier yields an empty committee, not an error. State analogs of the topology-derived `CommitteeInputFromTopologyPerFamily`.
- **`ExecutorPoolInputFromState` / `ApplyExecutorConfigInputFromState`** — reconstruct the executor pool input from previously-published executor job specs persisted in the datastore (the pool has no on-chain footprint). Connection settings (indexer addresses, pyroscope URL, monitoring) are returned separately via `ExecutorConnExtras`. State analog of `ExecutorPoolInputFromTopology`.
- **`NOPIdentities` / `LoadNOPIdentities`** {#nop-identities} — the offchain half of state resolution: builds the alias↔signer maps so on-chain scans (which only see signer addresses) can be mapped back to NOP aliases. Sources: JD (`env.Offchain`, live, takes precedence) + the persisted signer index (`env.DataStore`, covers standalone NOPs JD does not manage). Build once per resolve and thread through committee/pool reconstruction. Use `AliasForSigner(family, signer)` / `NOPInputs()`.
- **`MergeAggregatorConfig` / `MergeIndexerConfig` / `MergeTokenVerifierConfig`, `SaveNOPSigners` / `GetNOPSigners`** {#env-metadata-merge-and-signers} — env-metadata helpers in `deployment/env_metadata_util.go`. The `Merge*` variants additively update offchain configs (vs. the full-replace `Save*`); `SaveNOPSigners`/`GetNOPSigners` persist the alias→signer index that `LoadNOPIdentities` reads for NOPs not managed by JD.

`build/devenv` additionally gains an always-on state-inference verification gate (`verify_inference.go`): after each topology-driven `ApplyVerifierConfig`/`ApplyExecutorConfig`, the same input is reconstructed from live state and required to match — proving the state resolvers are correct against a real environment. Genuinely-empty state (no JD client, nothing deployed) is logged and skipped, not failed.

## Compatibility & Requirements

- **Dependency bumps:** `build/devenv/go.mod` bumps `github.com/smartcontractkit/chainlink-ccip/deployment` and `.../chains/evm` to the revision that removes the chainlink-ccip-side offchain + committee-verifier changesets and `NewTopologyCommitteePopulator`.
- **Feature flags / rollout:** `use_legacy_configure_lane` removed (was already defaulting to `false` in checked-in env TOMLs).

## References

- PR: https://github.com/smartcontractkit/chainlink-ccv/pull/1202
- Prior changelog entries this builds on: `2026-06-19_multi_aggregator_committee_verifier.md`, `2026-06-22_multi_aggregator_verifier_part2.md`, `2026-06-08_upgrade_ccip_lane_config.md`, `2026-05-23_devenv_phased_legacy_elimination.md`
