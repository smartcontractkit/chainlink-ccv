# Imperative offchain changesets (Phase C)

## Summary

The three offchain-only changesets in `chainlink-ccv/deployment/changesets/`
have been migrated from `*EnvironmentTopology` inputs to imperative inputs.
This is Phase C of the use-case-first product-changeset design
(`ccv-use-case-design.md` §5.9, §5.10, §6.5, §7).

Migrated entry points:

* `ApplyVerifierConfig`
* `ApplyExecutorConfig`
* `GenerateAggregatorConfig` (replaces the previous topology-driven variant
  with what was previously called `GenerateAggregatorConfigImperative`)

After this change, no changeset in `chainlink-ccv/deployment/changesets/`
takes `*ccvdeployment.EnvironmentTopology` as input. `topology.go` itself is
retained for now because external consumers (`chainlink-ccv/build/devenv/` and
the chainlink-stellar dev-env) still use it as a TOML deployment manifest
format; per-consumer migration off topology is tracked separately.

## Breaking changes

### `ApplyVerifierConfigInput`

Before:

```go
type ApplyVerifierConfigInput struct {
    Topology                 *ccvdeployment.EnvironmentTopology
    CommitteeQualifier       string
    DefaultExecutorQualifier string
    TargetNOPs               []shared.NOPAlias
    DisableFinalityCheckers  []string
    RevokeOrphanedJobs       bool
}
```

After:

```go
type ApplyVerifierConfigInput struct {
    CommitteeQualifier       string
    DefaultExecutorQualifier string
    NOPs                     []NOPInput
    Committee                CommitteeInput
    PyroscopeURL             string
    Monitoring               ccvdeployment.MonitoringConfig
    TargetNOPs               []shared.NOPAlias
    DisableFinalityCheckers  []string
    RevokeOrphanedJobs       bool
}
```

`NOPInput` carries `Alias`, `SignerAddressByFamily` (optional — falls back to
JD lookup when empty), and `Mode`. `CommitteeInput` carries the qualifier, the
list of `AggregatorRef`s, and per-source-chain `NOPAliases` keyed by
`uint64` chain selector.

### `ApplyExecutorConfigInput`

Before:

```go
type ApplyExecutorConfigInput struct {
    Topology           *ccvdeployment.EnvironmentTopology
    ExecutorQualifier  string
    TargetNOPs         []shared.NOPAlias
    RevokeOrphanedJobs bool
}
```

After:

```go
type ApplyExecutorConfigInput struct {
    ExecutorQualifier  string
    NOPs               []NOPInput
    Pool               ExecutorPoolInput
    IndexerAddress     []string
    PyroscopeURL       string
    Monitoring         ccvdeployment.MonitoringConfig
    TargetNOPs         []shared.NOPAlias
    RevokeOrphanedJobs bool
}
```

`ExecutorPoolInput` carries the per-chain NOP membership and execution interval
plus the pool-wide tuning fields (`IndexerQueryLimit`, `BackoffDuration`,
`LookbackWindow`, `ReaderCacheExpiry`, `MaxRetryDuration`, `WorkerCount`,
`NtpServer`).

### `GenerateAggregatorConfigInput`

Before:

```go
type GenerateAggregatorConfigInput struct {
    ServiceIdentifier  string
    CommitteeQualifier string
    Topology           *ccvdeployment.EnvironmentTopology
}
```

After:

```go
type GenerateAggregatorConfigInput struct {
    ServiceIdentifier  string
    CommitteeQualifier string
    ChainSelectors     []uint64
    ThresholdOverride  *uint8
}
```

This is the type previously called `GenerateAggregatorConfigImperativeInput`;
the topology-driven variant has been removed and the imperative companion now
owns the public name. `ThresholdOverride` was already present and is unchanged
— it backs the offchain-first coupled products from Phase A
(`IncreaseThresholdOffchain`, `DecreaseThresholdOffchain`).

## Migration

Callers that already had a topology in scope can build the new inputs by
slicing the topology per call. Reference helpers live in
`chainlink-ccv/build/devenv/topology_to_imperative.go`:

* `nopInputsFromTopology(topology)` → `[]NOPInput`
* `committeeInputFromTopology(topology.NOPTopology.Committees[name])` → `CommitteeInput`
* `executorPoolInputFromTopology(topology.ExecutorPools[name])` → `ExecutorPoolInput`
* `committeeChainSelectorsFromTopology(committee)` → `[]uint64`

Coupled-committee products (`AddNOPToCommittee` / `RemoveNOPFromCommittee` /
`IncreaseThreshold` / `DecreaseThreshold` and their offchain steps) were
already imperative and are unchanged.
