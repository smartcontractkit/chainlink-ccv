# CCV Deployments package
This package contains changeset to configure CCV offchain components. Those changesets are meant to be used with the chainlink deployment framework and cover config changes for the aggregator, indexer, verifiers and executors.

## Environment Topology
The package defines a node topology which defines which nodes are part of which committees and executor pools.

```toml
[environment_topology]
# Global indexer endpoint for executor configuration
indexer_address = ["http://indexer-1:8100"]
# Shared pyroscope endpoint for profiling
pyroscope_url = "http://host.docker.internal:4040"

[environment_topology.monitoring]
# Contains shared monitoring configuration

[[environment_topology.nop_topology.nops]]
alias = "node-0"
name = "Node 0"
mode = "cl"  # Managed via Job Distributor

[[environment_topology.nop_topology.nops]]
alias = "node-1"
name = "Node 1"
mode = "standalone"  # Running as standalone binary

[environment_topology.nop_topology.committees.default]
qualifier = "default"

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

### NOP Modes

Each NOP can operate in one of two modes:

| Mode | Description |
|------|-------------|
| `cl` | Managed via Job Distributor (JD). Job specs are proposed to JD and require approval on the Chainlink node. |
| `standalone` | Running as standalone binary. Job specs are generated but not proposed to JD. |

If no mode is specified, `cl` is used by default.

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
| NOP modes | Determines whether jobs are managed via JD or standalone |
| Indexer address | Infrastructure endpoint for executor communication |
| PyroscopeURL, Monitoring | Observability infrastructure configuration |

## Changesets

### Generate Aggregator Config

Generates the aggregator configuration for a committee by reading on-chain state from CommitteeVerifier contracts.

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

Generates and applies verifier job specs for nodes in a committee. For `cl` mode NOPs, job specs are proposed to JD. For `standalone` mode NOPs, specs are saved to the datastore only.

#### Input
```go
type ApplyVerifierConfigCfg struct {
    Topology *deployments.EnvironmentTopology
    // CommitteeQualifier identifies which committee from topology to use
    CommitteeQualifier string
    // DefaultExecutorQualifier is the qualifier of the default executor
    DefaultExecutorQualifier string
    // ChainSelectors limits which chains to configure. Defaults to all.
    ChainSelectors []uint64
    // TargetNOPs limits which NOPs to update. Defaults to all in committee.
    TargetNOPs []shared.NOPAlias
}
```

#### Data Sources

| Field | Source | Notes |
|-------|--------|-------|
| CommitteeVerifier addresses | Datastore | Deployed contract addresses |
| OnRamp addresses | Datastore | Deployed contract addresses |
| DefaultExecutor addresses | Datastore | Deployed contract addresses |
| RMNRemote addresses | Datastore | Deployed contract addresses |
| `SignerAddress` | JD or Topology | Fetched from JD chain configs if not set in topology |
| `Committee.Aggregators` | Topology | Aggregator endpoints are infrastructure |
| `PyroscopeURL`, `Monitoring` | Topology | Observability infrastructure configuration |

#### Behavior
1. Generates job specs for all target NOPs
2. For `cl` mode NOPs: Proposes jobs to JD
3. For `standalone` mode NOPs: Saves specs to datastore only
4. Detects and revokes orphaned jobs (NOPs removed from committee)
5. Skips unchanged job specs to avoid unnecessary proposals

### Apply Executor Config

Generates and applies executor job specs for nodes in an executor pool.

#### Input
```go
type ApplyExecutorConfigCfg struct {
    Topology *deployments.EnvironmentTopology
    // ExecutorQualifier identifies which executor pool from topology to use
    ExecutorQualifier string
    // ChainSelectors limits which chains to configure. Defaults to all.
    ChainSelectors []uint64
    // TargetNOPs limits which NOPs to update. Defaults to all in pool.
    TargetNOPs []shared.NOPAlias
}
```

#### Data Sources

| Field | Source | Notes |
|-------|--------|-------|
| OffRamp addresses | Datastore | Deployed contract addresses |
| RMNRemote addresses | Datastore | Deployed contract addresses |
| DefaultExecutor addresses | Datastore | Deployed contract addresses |
| `ExecutorPool.NOPAliases` | Topology | Executor pool membership |
| `ExecutorPool.*` parameters | Topology | Operational tuning parameters |
| `IndexerAddress` | Topology | Infrastructure endpoint |
| `PyroscopeURL`, `Monitoring` | Topology | Observability infrastructure configuration |

#### Behavior
1. Generates job specs for all target NOPs in the pool
2. For `cl` mode NOPs: Proposes jobs to JD
3. For `standalone` mode NOPs: Saves specs to datastore only
4. Detects and revokes orphaned jobs (NOPs removed from pool)

### Sync Job Proposals

Synchronizes job proposal statuses from JD and detects spec drift.

#### Input
```go
type SyncJobProposalsCfg struct {
    NOPAliases []shared.NOPAlias
}
```

#### Behavior
1. Fetches proposal status for all `cl` mode jobs from JD
2. Updates local status (pending, approved, revoked, rejected)
3. Detects spec drift (local spec differs from JD spec)
4. Removes orphaned jobs (jobs that no longer exist in JD)
5. Reports status changes and drift for visibility

