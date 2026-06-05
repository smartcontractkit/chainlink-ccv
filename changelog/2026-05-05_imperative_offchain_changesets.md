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
slicing the topology per call. Exported helpers ship alongside the
changeset inputs in `chainlink-ccv/deployment/changesets/topology_inputs.go`,
so live-env consumers (`chainlink-deployments`) and the dev-env share one
implementation:

* `changesets.NOPInputsFromTopology(topology)` → `[]NOPInput`
* `changesets.CommitteeInputFromTopology(topology.NOPTopology.Committees[name])` → `CommitteeInput`
* `changesets.ExecutorPoolInputFromTopology(topology.ExecutorPools[name])` → `ExecutorPoolInput`
* `changesets.CommitteeChainSelectorsFromTopology(committee)` → `[]uint64`

Coupled-committee products (`AddNOPToCommittee` / `RemoveNOPFromCommittee` /
`IncreaseThreshold` / `DecreaseThreshold` and their offchain steps) were
already imperative and are unchanged.

### Worked example: TOML topology → imperative inputs

The live-env TOML topologies kept in
`chainlink-deployments/domains/ccv/<env>/topology.toml` are unchanged on
disk. Only the in-process boundary moves: instead of handing the full
`*EnvironmentTopology` to a changeset, the caller slices it into the new
inputs. Using `prod_testnet/topology.toml` as the reference shape:

```toml
# topology.toml (excerpt — fields not used by the new inputs are elided)
[[nop_topology.nops]]
alias = "ccv-prod-testnet-0"
name  = "DexTrac"
# ... 20 more NOPs

[nop_topology.committees.default]
qualifier = "default"
[[nop_topology.committees.default.aggregators]]
name    = "aggregator-1"
address = "aggregator-1.testnet.ccip.chain.link"
[[nop_topology.committees.default.aggregators]]
name    = "aggregator-2"
address = "aggregator-2.testnet.ccip.chain.link"

# ethereum-sepolia
[nop_topology.committees.default.chain_configs.16015286601757825753]
nop_aliases     = ["ccv-prod-testnet-0", ..., "ccv-prod-testnet-15"]
threshold       = 9                                  # onchain-only — NOT on CommitteeInput
fee_aggregator  = "0x14eaEc5b6d..."                  # onchain-only — NOT on CommitteeInput
allowlist_admin = "0x000000000..."                   # onchain-only — NOT on CommitteeInput

[executor_pools.default]
indexer_query_limit  = 100
backoff_duration     = 15_000_000_000                # 15s
lookback_window      = 3_600_000_000_000             # 1h
reader_cache_expiry  = 300_000_000_000               # 5m
max_retry_duration   = 28_800_000_000_000            # 8h
worker_count         = 100
ntp_server           = "time.google.com"

# ethereum-sepolia
[executor_pools.default.chain_configs."16015286601757825753"]
nop_aliases        = ["ccv-prod-testnet-0", ..., "ccv-prod-testnet-15"]
execution_interval = 15_000_000_000                  # 15s
```

The same data, delivered through the imperative inputs (one shape per call):

```go
// Shared across both ApplyVerifierConfig and ApplyExecutorConfig.
nops := []changesets.NOPInput{
    {Alias: "ccv-prod-testnet-0",  /* SignerAddressByFamily, Mode from topology */},
    // ...
    {Alias: "ccv-prod-testnet-20", /* ... */},
}

// ApplyVerifierConfig: one CommitteeInput per [nop_topology.committees.<name>].
// threshold / fee_aggregator / allowlist_admin are NOT carried — they belong to
// onchain state and are written by the onchain changesets, not by the offchain
// verifier-config publisher.
committee := changesets.CommitteeInput{
    Qualifier: "default",
    Aggregators: []changesets.AggregatorRef{
        {Name: "aggregator-1", Address: "aggregator-1.testnet.ccip.chain.link"},
        {Name: "aggregator-2", Address: "aggregator-2.testnet.ccip.chain.link"},
    },
    ChainConfigs: map[uint64]changesets.CommitteeChainMembership{
        16015286601757825753: {NOPAliases: []shared.NOPAlias{
            "ccv-prod-testnet-0", /* ... */, "ccv-prod-testnet-15",
        }},
        // ... one entry per [nop_topology.committees.default.chain_configs.<sel>]
    },
}

// ApplyExecutorConfig: one ExecutorPoolInput per [executor_pools.<name>].
// Pool-wide tuning that the topology folded into ExecutorPoolConfig is now
// flat on the input.
pool := changesets.ExecutorPoolInput{
    IndexerQueryLimit: 100,
    BackoffDuration:   15 * time.Second,
    LookbackWindow:    1 * time.Hour,
    ReaderCacheExpiry: 5 * time.Minute,
    MaxRetryDuration:  8 * time.Hour,
    WorkerCount:       100,
    NtpServer:         "time.google.com",
    ChainConfigs: map[uint64]changesets.ChainExecutorPoolMembership{
        16015286601757825753: {
            NOPAliases:        []shared.NOPAlias{"ccv-prod-testnet-0", /* ... */},
            ExecutionInterval: 15 * time.Second,
        },
        // ... one entry per [executor_pools.default.chain_configs."<sel>"]
    },
}

// GenerateAggregatorConfig: just the chain selectors the committee is
// deployed on — i.e. the keys of nop_topology.committees.default.chain_configs.
chainSelectors := []uint64{
    16015286601757825753, // ethereum-sepolia
    // ... etc
}
```

Field-by-field map:

| TOML key                                                            | New input field                            |
| ------------------------------------------------------------------- | ------------------------------------------ |
| `[[nop_topology.nops]].alias`                                       | `NOPInput.Alias`                           |
| (per-NOP signer addrs in topology)                                  | `NOPInput.SignerAddressByFamily`           |
| (per-NOP mode in topology)                                          | `NOPInput.Mode`                            |
| `nop_topology.committees.<n>.qualifier`                             | `CommitteeInput.Qualifier`                 |
| `nop_topology.committees.<n>.aggregators[*]`                        | `CommitteeInput.Aggregators[*]`            |
| `nop_topology.committees.<n>.chain_configs.<sel>.nop_aliases`       | `CommitteeInput.ChainConfigs[<sel>].NOPAliases` |
| `nop_topology.committees.<n>.chain_configs.<sel>.{threshold,fee_aggregator,allowlist_admin}` | _not carried — onchain-only_ |
| `executor_pools.<n>.{indexer_query_limit,backoff_duration,...}`     | `ExecutorPoolInput.{IndexerQueryLimit,BackoffDuration,...}` |
| `executor_pools.<n>.chain_configs."<sel>".nop_aliases`              | `ExecutorPoolInput.ChainConfigs[<sel>].NOPAliases` |
| `executor_pools.<n>.chain_configs."<sel>".execution_interval`       | `ExecutorPoolInput.ChainConfigs[<sel>].ExecutionInterval` |
| keys of `nop_topology.committees.<n>.chain_configs`                 | `GenerateAggregatorConfigInput.ChainSelectors` |
| `indexer_address` (top-level)                                       | `ApplyExecutorConfigInput.IndexerAddress`  |
| `monitoring`        (top-level)                                     | `ApplyExecutorConfigInput.Monitoring` / `ApplyVerifierConfigInput.Monitoring` |

The TOML stays the source of truth for live environments; the exported
helpers in `chainlink-ccv/deployment/changesets/topology_inputs.go` are
the canonical implementation of this mapping. Both the dev-env and
`chainlink-deployments` callers consume them directly when invoking the
changesets.
