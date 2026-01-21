# CCV Deployments package
This package contains changeset to configure CCV offchain components. Those changesets are meant to be used with the chainlink deployment framework and cover config changes for the aggregator, indexer, verifiers and executors.

## Environment Topology
The package defines a node topology which defines which nodes are part of which committees and executor pools.

```toml
[environment_topology]
# Global indexer endpoint for executor configuration
indexer_address = "http://indexer:8100"
# Shared pyroscope endpoint for profiling
pyroscope_url = "http://host.docker.internal:4040"

[environment_topology.monitoring]
# Contains shared monitoring configuration

[[environment_topology.nop_topology.nops]]
alias = "node-0"
name = "Node 0"

[[environment_topology.nop_topology.nops]]
alias = "node-1"
name = "Some name"

[environment_topology.nop_topology.committees.default]
qualifier = "default"
verifier_version = "1.7.0"

[[environment_topology.nop_topology.committees.default.aggregators]]
name = "default"
address = "default-aggregator:50051"
insecure_connection = true

[environment_topology.nop_topology.committees.default.chain_configs.16015286601757825753]
nop_aliases = ["node-0", "node-1"]
threshold = 2

[environment_topology.nop_topology.committees.default.chain_configs.3478487238524512106]
nop_aliases = ["node-0", "node-1"]
threshold = 2

[environment_topology.executor_pools.default]
nop_aliases = ["node-0", "default-executor-2"]
```

## Design Principles

Off-chain changesets use on-chain state as the source of truth wherever possible:

| Data Type | Source | Examples |
|-----------|--------|----------|
| Contract addresses | Datastore (deployed contracts) | CommitteeVerifier, OnRamp, OffRamp, RMNRemote |
| Committee signers | On-chain (contract state) | Signer addresses registered in CommitteeVerifier |
| Thresholds | On-chain (contract state) | Signature thresholds per source chain |

Certain fields must come from topology input because they represent concepts that do not exist on-chain:

| Field | Reason |
|-------|--------|
| Aggregator endpoints | Infrastructure endpoints, not stored on-chain |
| Executor pool membership | Organizational grouping, not an on-chain concept |
| NOP aliases | Maps nodes to job specs; used before on-chain registration |
| Indexer address | Infrastructure endpoint for executor communication |
| PyroscopeURL, Monitoring | Observability infrastructure configuration |

## Changesets

### Generate Aggregator Config

#### Input
```go
type BuildConfigInput struct {
	// ServiceIdentifier is the identifier for this aggregator service (e.g. "default-aggregator")
	ServiceIdentifier string
	// CommitteeQualifier is the unique identifier for this committee.
	CommitteeQualifier string
	// ChainSelectors are the chain selectors that will be considered. Defaults to all chain selectors in the environment.
	ChainSelectors []uint64
}
```

The Generate Aggregator Config changeset will generate the aggregator configuration for the given committee. It will use the on-chain state of the CommitteeVerifier contracts to build the configuration. The output will be saved to the datastore under the key `aggregator_config/<service_identifier>`.

#### Example Output
```toml
[aggregator_config.default-aggregator]
committee = {
  quorum_configs = {
    "16015286601757825753" = {
      source_verifier_address = "0x1234567890123456789012345678901234567890"
      signers = [{ address = "0x1234567890123456789012345678901234567890" }]
      threshold = 2
    }
  }
}
```

### Generate Indexer Config

#### Input
```go
type BuildConfigInput struct {
	// ServiceIdentifier is the identifier for this indexer service (e.g. "default-indexer")
	ServiceIdentifier string
	// VerifierNameToQualifier maps verifier names (matching VerifierConfig.Name) to qualifiers
	// used for looking up addresses in the datastore.
	CommitteeVerifierNameToQualifier map[string]string
	CCTPVerifierNameToQualifier      map[string]string
	// ChainSelectors are the source chains the indexer will monitor.
	// If empty, defaults to all chain selectors available in the environment.
	ChainSelectors []uint64
}
```

The Generate Indexer Config changeset generates the indexer configuration by querying the datastore for verifier contract addresses. The output is saved to the datastore under the key `indexer_config/<service_identifier>`.

#### Example Output
```toml
[indexer_config.default-indexer]
verifiers = [
  { name = "default-verifier", issuer_addresses = ["0x1234567890123456789012345678901234567890"] }
]
```

### Generate Verifier Config

Generates job specs for verifier nodes. Contract addresses are read from the datastore; committee topology and infrastructure endpoints come from input.

#### Input
```go
type GenerateVerifierConfigInput struct {
	// DefaultExecutorQualifier is the qualifier of the executor considered as the default executor.
	DefaultExecutorQualifier string
	// ChainSelectors is the list of chain selectors to consider. Defaults to all chain selectors in the environment.
	ChainSelectors []uint64
	// TargetNOPs limits which NOPs will have their job specs updated. Defaults to all NOPs in the committee when empty.
	TargetNOPs []string
	// NOPs is the list of NOP configurations containing signing addresses for each NOP.
	NOPs []verifierconfig.NOPInput
	// Committee contains the committee configuration including aggregators and membership.
	Committee verifierconfig.CommitteeInput
	// PyroscopeURL is the URL of the Pyroscope server for profiling (optional).
	PyroscopeURL string
	// Monitoring is the monitoring configuration containing beholder settings.
	Monitoring shared.MonitoringInput
}
```

#### Data Sources

| Field | Source | Notes |
|-------|--------|-------|
| CommitteeVerifier addresses | Datastore | Deployed contract addresses |
| OnRamp addresses | Datastore | Deployed contract addresses |
| DefaultExecutor addresses | Datastore | Deployed contract addresses |
| RMNRemote addresses | Datastore | Deployed contract addresses |
| `NOPs[].SignerAddress` | Input | Temporarily while JD is not supported, links NOP alias to signing key; enables job spec generation before on-chain registration |
| `Committee.Aggregators` | Input | Aggregator endpoints are infrastructure, not stored on-chain |
| `Committee.NOPAliases` | Input | Determines which nodes receive job specs |
| `PyroscopeURL`, `Monitoring` | Input | Observability infrastructure configuration |

#### Output

Job specs are saved to the datastore under `nop_job_specs/<nop_alias>/<job_spec_id>`.

### Generate Executor Config

Generates job specs for executor nodes. Contract addresses are read from the datastore; executor pool membership and infrastructure endpoints come from input.

#### Input
```go
type GenerateExecutorConfigInput struct {
	// ExecutorQualifier is the qualifier of the executor that is configured as part of this operation.
	ExecutorQualifier string
	// ChainSelectors is the list of chain selectors to consider. Defaults to all chain selectors in the environment.
	ChainSelectors []uint64
	// TargetNOPs limits which NOPs will have their job specs updated. Defaults to all NOPs in the executor pool when empty.
	TargetNOPs []string
	// ExecutorPool is the executor pool configuration containing pool membership and execution parameters.
	ExecutorPool ExecutorPoolInput
	// IndexerAddress is the address of the indexer service used by executors.
	IndexerAddress string
	// PyroscopeURL is the URL of the Pyroscope server for profiling (optional).
	PyroscopeURL string
	// Monitoring is the monitoring configuration containing beholder settings.
	Monitoring shared.MonitoringInput
}

type ExecutorPoolInput struct {
	// NOPAliases is the list of NOP aliases that are members of this executor pool.
	NOPAliases []string
	// ExecutionInterval is the interval between execution cycles.
	ExecutionInterval time.Duration
	// NtpServer is the NTP server address for time synchronization (optional).
	NtpServer string
	// IndexerQueryLimit is the maximum number of records to fetch from the indexer per query.
	IndexerQueryLimit uint64
	// BackoffDuration is the duration to wait before retrying after a failure.
	BackoffDuration time.Duration
	// LookbackWindow is the time window for looking back at historical data.
	LookbackWindow time.Duration
	// ReaderCacheExpiry is the TTL for cached chain reader data.
	ReaderCacheExpiry time.Duration
	// MaxRetryDuration is the maximum duration to retry failed operations.
	MaxRetryDuration time.Duration
	// WorkerCount is the number of concurrent workers for processing executions.
	WorkerCount int
}
```

#### Data Sources

| Field | Source | Notes |
|-------|--------|-------|
| OffRamp addresses | Datastore | Deployed contract addresses |
| RMNRemote addresses | Datastore | Deployed contract addresses |
| DefaultExecutor addresses | Datastore | Deployed contract addresses |
| `ExecutorPool.NOPAliases` | Input | Executor pool membership is an organizational concept, not on-chain |
| `ExecutorPool.*` parameters | Input | Operational tuning parameters, not stored on-chain |
| `IndexerAddress` | Input | Infrastructure endpoint for executor-indexer communication |
| `PyroscopeURL`, `Monitoring` | Input | Observability infrastructure configuration |

#### Output

Job specs are saved to the datastore under `nop_job_specs/<nop_alias>/<job_spec_id>`.