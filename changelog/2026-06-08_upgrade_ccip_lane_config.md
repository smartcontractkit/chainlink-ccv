# Upgrade chainlink-ccip: simplified lane and deploy configuration

Bumps `chainlink-ccip` to `2026-06-08` (picks up [#2091](https://github.com/smartcontractkit/chainlink-ccip/pull/2091), [#2108](https://github.com/smartcontractkit/chainlink-ccip/pull/2108), [#2112](https://github.com/smartcontractkit/chainlink-ccip/pull/2112)) and adapts the devenv accordingly.

---

## Breaking: `ChainLaneProfile` removed from `cciptestinterfaces`

The `ChainLaneProfile` struct and all fields it carried (`BaseExecutionGasCost`, `FeeQuoterDestChainConfig`, `ExecutorDestChainConfig`, `DefaultExecutorQualifier`, `DefaultInboundCCVs`, `DefaultOutboundCCVs`, `TokenReceiverAllowed`, `GasForVerification`, `AllowedFinalityConfig`) have been removed from `cciptestinterfaces`.

`GetChainLaneProfile` now returns `ccipChangesets.ChainOverrides` directly (from upstream `chainlink-ccip`).

Before:
```go
GetChainLaneProfile(env *deployment.Environment, selector uint64) (ChainLaneProfile, error)
```

After:
```go
GetChainLaneProfile(env *deployment.Environment, selector uint64) (ccipChangesets.ChainOverrides, error)
```

All chain family implementations must update their `GetChainLaneProfile` return type accordingly.

---

## Breaking: `ConnectAllChainsCanonical` no longer calls `ConfigureChainsForLanesFromTopology` in incremental rounds

`ConnectAllChainsCanonical` previously iterated chain-by-chain, calling the changeset once per new chain added. It now builds all `CrossFamilyLanePair` entries up-front and applies them in a single changeset call using the new `BuildLanesCrossFamilyConfig` API.

The intermediate `buildPartialChainConfig` helper has been removed.

---

## Breaking: `DeployContractsForSelector` config shape changed

`DeployChainContractsCfg` no longer has `DefaultCfg` or `IgnoreImportedConfigFromPreviousVersion`. Configuration is now provided via a `ChainOverrides` map keyed by chain selector.

Before:
```go
ccipChangesets.DeployChainContractsCfg{
    Topology:                                ccipTopology,
    ChainSelectors:                          []uint64{selector},
    IgnoreImportedConfigFromPreviousVersion: true,
    DefaultCfg:                              cfg,
}
```

After:
```go
ccipChangesets.DeployChainContractsCfg{
    Topology:       ccipTopology,
    ChainSelectors: []uint64{selector},
    ChainOverrides: map[uint64]ccipChangesets.DeployChainContractsPerChainCfg{
        selector: cfg,
    },
}
```

---

## New: `LombardVerifierResolverQualifier` constant

`devenvcommon.LombardVerifierResolverQualifier = "LombardVerifierResolver"` has been added. The token verifier component and smoke test now use this qualifier instead of `LombardContractsQualifier` when referencing the Lombard verifier resolver contract.

---

## Fix: bidirectional curse/uncurse in reorg tests

`curseSelector` and `uncurseSelector` in the finality/reorg E2E test now apply the curse (and verify it) in both directions — `chainA → chainB` and `chainB → chainA` — for non-global curses. Previously only one direction was cursed and verified.
