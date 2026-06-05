# Offchain Tooling Overview in CCIP 2.0

CCIP 2.0 introduces several offchain components that run alongside the on-chain contracts: executor jobs, committee verifier jobs, aggregators, indexers, and token verifiers. Each component requires configuration that references deployed contract addresses, NOP membership, signing keys, and operational parameters. The offchain changesets are responsible for producing and distributing these configurations.

The changesets fall into two distinct categories based on their delivery mechanism:

| Category | Changesets | Delivery Target |
| :---- | :---- | :---- |
| **Job Distribution** | `ApplyExecutorConfig`, `ApplyVerifierConfig` | Job Distributor (JD) via job proposals |
| **Config Generation** | `GenerateAggregatorConfig`, `GenerateIndexerConfig`, `GenerateTokenVerifierConfig` | Datastore (manual delivery today, automated PR creation planned) |

Ideally both categories share a common architecture: family-agnostic changesets delegate chain-specific address resolution and state reading to adapters, persist their output into the datastore, and keep the changeset body free of any chain-family specific logic.

---

## Context on NOP Topology

Many of the offchain changesets touch the committee verifier and executor components. Those components are run by node operators, and product drives the assignment of NOPs to specific chain tiers based on their performance.

The NOP topology was used as a central source of truth for the NOP distribution across chains based on product input. It was meant to be a **desired** state from which changesets would read and reconcile the onchain and offchain config to match the topology state. The topology follows a declarative pattern that conflicts with how we want CLOPS to be a single entrypoint and follow an imperative pattern when it comes to changesets. In this document it is assumed that the topology can be removed and that each changeset can have specific configs tailored to the inputs it needs (instead of receiving the entire topology and picking the information it needs).

---

## 1\. Job Distribution

The Apply changesets produce TOML job specs and distribute them to Node Operators via the Job Distributor (JD). These are the only offchain changesets that interact with JD.

### ApplyExecutorConfig

Produces executor job specs for each NOP in an executor pool. The flow:

1. Resolve deployed chain selectors for the pool via the `ExecutorConfigAdapter`  
2. Build per-chain config (offramp, RMN, executor proxy addresses) through `adapter.BuildChainConfig()`  
3. Assemble a TOML job spec per NOP, embedding the chain configs, indexer address, and monitoring settings  
4. Pass the specs to `ManageJobProposals` for distribution

### ApplyVerifierConfig

Produces committee verifier job specs for each NOP in a committee. The flow:

1. Resolve chain selectors from the committee's `ChainConfigs`  
2. Resolve contract addresses (committee verifier, onramp, executor proxy, RMN remote) through `adapter.ResolveVerifierContractAddresses()`  
3. Fetch signing keys for NOPs that are missing signer addresses (currently an anti-pattern that should be delegated to the adapter)  
4. Assemble a TOML job spec per NOP per aggregator, embedding the signer address and all contract addresses  
5. Pass the specs to `ManageJobProposals` for distribution

### ManageJobProposals Sequence

Both Apply changesets converge on `ManageJobProposals`, a shared sequence that handles the full proposal lifecycle:

1. **Load existing state** \-- reads previously persisted jobs from the datastore to detect drift  
2. **Diff** \-- compares new specs against existing ones; only changed or new jobs proceed  
3. **Propose** \-- for CL-mode NOPs, calls `JDClient.ProposeJob()` to create pending proposals  
4. **Revoke orphans** \-- when `RevokeOrphanedJobs` is enabled, identifies jobs that exist in the datastore but are no longer in the desired spec set, and revokes them via JD  
5. **Persist** \-- saves all job state (specs, JD job IDs, proposal status) to the datastore

The sequence also handles NOP mode transitions. When a NOP moves from CL mode to standalone, the sequence revokes the JD-managed job and clears JD metadata so the NOP can manage it independently.

The sequence is able to know which NOPs need to receive a specific job by doing a lookup of committee membership or executor pool membership based on the node name. If a node is registered in the CLD env (nodes.json) the changesets are able to correlate the node name with the nodeId to invoke JD api and propose jobs.

### NOP Modes

Each NOP has a mode that determines how its jobs are distributed:

- `JD-mode` (default) \-- jobs are proposed to JD, which distributes them to the Chainlink node  
- `standalone` \-- job specs are persisted in the datastore but not proposed to JD; the NOP manages deployment independently

The standalone mode existed to support when verifiers and executors used static configs instead of JD. The long-term direction is to phase out standalone mode as all NOPs converge on JD-based distribution

---

## 2\. Config Generation

The Generate changesets produce configuration for offchain services that run outside the Chainlink node. These services (aggregator, indexer, token verifier) are deployed independently and consume configuration that references on-chain contract addresses.

### GenerateAggregatorConfig

Produces the aggregator's committee configuration by reading on-chain state:

1. For each chain in the committee, calls `adapter.ScanCommitteeStates()` to read the deployed committee verifier contracts and extract signature configs (signers, thresholds per source chain)  
2. Resolves verifier addresses via `adapter.ResolveVerifierAddress()`  
3. Builds the quorum config (source verifier address, signers, threshold) and destination verifier map  
4. Saves the result via `SaveAggregatorConfig()`

This changeset reads on-chain state entirely through the adapter, keeping the changeset body family-agnostic.

### GenerateIndexerConfig

Produces the indexer's verifier address map:

1. For each chain in the environment, calls `adapter.ResolveVerifierAddresses()` with the qualifier and verifier kind (committee, CCTP, Lombard)  
2. Collects and deduplicates addresses across chains  
3. Saves the result via `SaveIndexerConfig()`

The input is minimal: a map of verifier names to qualifiers per kind. The adapter handles all address resolution.

### GenerateTokenVerifierConfig

Produces the token verifier's configuration:

1. For each chain, calls `adapter.ResolveTokenVerifierAddresses()` to get onramp, RMN remote, CCTP verifier, and Lombard verifier resolver addresses  
2. Applies sensible defaults for attestation API endpoints, timeouts, and intervals (mainnet vs testnet)  
3. Saves the result via `SaveTokenVerifierConfig()`

Ideally we split the generation changesets from the delivery changeset. This allow us to capture the diff of offchain config and then intentionally release the change to the target components.

---

## 3\. Datastore as Intermediate Persistence

All offchain changesets persist their output into **environment metadata in the datastore**. This creates a deliberate three-phase model:

```
Require Data --> Generation --> Persistence (datastore) --> Delivery
```

### What gets persisted

- **Apply changesets**: `ManageJobProposals` persists `JobInfo` records containing the TOML spec content, JD job ID, node ID, proposal status, and labels. This is the source of truth for drift detection \-- on the next run, the sequence compares the new spec against the persisted one and only re-proposes if something changed.  
- **Generate changesets**: configs are saved as structured metadata via `SaveAggregatorConfig`, `SaveIndexerConfig`, and `SaveTokenVerifierConfig`.

### Why do we persist the configuration

The datastore decouples **what config should exist** from **how it gets delivered**:

- For Apply changesets, the `ManageJobProposals` sequence handles delivery (proposing to JD) in the same run, but the persisted state enables idempotent re-runs and orphan detection.  
- For Generate changesets, delivery is currently manual (an operator reads the output and creates a PR or updates a deployment). The planned direction is automated PR creation, where a delivery step reads from the datastore and opens a PR against the target config repo.

---

## 4\. Repo structure

All offchain changesets use the same adapter registry pattern to remain family-agnostic. Each changeset is parameterized by a registry that maps chain families to adapter implementations.

### Where the code lives

| Layer | Current Location | Future Location | Owner |
| :---- | :---- | :---- | :---- |
| Family-agnostic changesets | `chainlink-ccip/deployment/v2_0_0/changesets/` | `chainlink-ccv/deployment/changesets/` | Platform |
| Shared offchain types & operations | `chainlink-ccip/deployment/v2_0_0/offchain/` | `chainlink-ccv/deployment` | Platform |
| Adapter interfaces & registries | `chainlink-ccip/deployment/v2_0_0/adapters/` | `chainlink-ccv/deployment/adapters/` | Platform |
| EVM adapter implementations | `chainlink-ccip/chains/evm/deployment/v2_0_0/adapters/` | Remains in EVM repo | Protocol/non-evm teams |
| Other family implementations | `chainlink-ton/deployment/`, `chainlink-solana/deployment/`, etc. | Remain in family repos | Protocol/non-evm teams |

The family-agnostic layer is planned to move to `chainlink-ccv/deployment/`. This reinforces the principle that the offchain changeset orchestration is a CCV-level concern, not specific to any chain family.

---

## 5\. Sourcing Offchain Information

Several changesets need information from external systems (JD, on-chain contracts, config files). The principle is: **changesets require data generically; adapters decide where it comes from**.

### Current state (anti-pattern)

Both `ApplyVerifierConfig` and `ConfigureChainsForLanesFromTopology` directly call `fetchSigningKeysForNOPsByFamilies` in the changeset body. This function calls `FetchNOPSigningKeys`, which reads `OnchainSigningAddress` from JD's `ListNodeChainConfigs` API. The changeset itself decides the data source, coupling the family-agnostic layer to JD.

### Desired state

The changeset should express what it needs generically \-- "signing addresses per NOP per family" \-- and the adapter should fulfill that requirement. Different families may source this data differently:

- EVM adapter: fetches from JD via `ListNodeChainConfigs`  
- A future family adapter: reads from a config file, a chain-native key registry, or a different external system

### Common building blocks

The family-agnostic deployment module (currently in `chainlink-ccip/deployment/v2_0_0/offchain/`, planned to move to `chainlink-ccv/deployment/`) provides reusable operations that adapters can compose:

- `FetchNOPSigningKeys` \-- fetches signing keys from JD for a set of NOP aliases  
- `FetchNodeChainSupport` \-- validates that NOP nodes support the required chain selectors

These are building blocks for adapters, not for changesets to call directly. The adapters own the "where"; the shared module provides the "how".

### Reference implementation

`GenerateAggregatorConfig` demonstrates the correct pattern. It calls `adapter.ScanCommitteeStates()`, which lets the EVM adapter read the on-chain committee verifier state via contract calls. The changeset never touches EVM bindings or knows how the data is retrieved.

---

## 6\. When Offchain Configs Change

Offchain configurations need to be updated under the following scenarios:

| Trigger | Impacted Components |
| :---- | :---- |
| New chain added to a committee | Verifier jobs, aggregator, indexer |
| New chain added to an executor pool | Executor jobs, indexer |
| Committee membership updated (NOPs added/removed) | Verifier jobs, aggregator |
| Quorum configuration changed (threshold, signers) | Verifier jobs, aggregator |
| Aggregator address changed | Verifier jobs |
| Indexer address changed | Executor jobs |
| NOP signing key rotated | Verifier jobs (should not be the case in the future), aggregator |
| New token verifier deployed (CCTP, Lombard) | Token verifier config, indexer |
| Executor pool membership changed | Executor jobs |

The general pattern: any change to the on-chain contract topology or NOP membership requires re-running the affected offchain changesets. The datastore persistence ensures idempotency \-- re-running a changeset when nothing has changed produces no new proposals or config updates.

---

## 7\. Planned Improvements

### Delegate signing address loading to adapters

Move `fetchSigningKeysForNOPsByFamilies` out of the changeset body and into the adapter interface. The changeset should receive signing addresses as part of the adapter's output, not fetch them itself. This aligns with the pattern already established by `GenerateAggregatorConfig` and unblocks families that don't use JD for key management.

### Simplify NOP mode logic

The standalone NOP mode (`NOPModeStandalone`) adds significant branching in `ManageJobProposals` (CL-to-standalone transitions, conditional JD calls, mode-filtered validation). As standalone mode is phased out and all NOPs converge on JD-based distribution, this complexity can be removed. The sequence should assume CL mode by default and treat standalone as a deprecated edge case during the transition period.

### Automated delivery for generated configs

Today, the Generate changesets persist configs to the datastore, and an operator manually delivers them (creates a PR, updates a config repo). The planned direction is a delivery step that:

1. Reads the generated config from the datastore  
2. Opens a PR against the target config repository with the updated config files  
3. Includes validation metadata (environment, commit hash, changeset version) in the PR description

This would close the loop on the three-phase model (generation \--\> persistence \--\> delivery) and enable fully automated config updates triggered by on-chain changes.

### CLOPS-driven offchain config updates

Today, offchain changesets are triggered manually by operators who know which configs need updating after an on-chain change. The long-term vision is that CLOPS (the self-service operations platform) automatically triggers offchain config updates as part of the workflows it already orchestrates.

When CLOPS supports use cases that require offchain config changes (e.g. changing a committee), it should generate the durable pipeline to update offchain configs automatically. This is the same way it already generates pipelines for lane connection today. The operator uses CLOPS to express intent ("add chain X to committee Y"), and CLOPS produces the full pipeline: on-chain changesets followed by the necessary offchain changesets (Apply verifier/executor configs, Generate aggregator/indexer/token-verifier configs, and deliver).

This eliminates the gap where on-chain changes succeed but offchain configs lag behind because an operator forgot to run the corresponding offchain changesets or ran them with stale inputs.

---

## 8\. Best Practices for Offchain Tooling

1. **Follow the tooling API changeset process**: following the same adapter pattern as on-chain changesets; the changeset body must not import chain-family packages  
2. **Changesets live close to the components**: config struct definitions live in the offchain package alongside the changesets that generate them, enabling shared types between generation and consumption  
3. **Changesets are family-agnostic**: all chain-specific logic (address formats, contract bindings, key sources) is behind an adapter interface; the changeset operates on generic types  
4. **Changesets require data, they don't fetch it**: when offchain information is needed, the adapter fulfills the requirement; the changeset never calls JD or reads contracts directly  
5. **Persisted output enables idempotency**: the datastore captures the full state of what was generated or proposed, allowing safe re-runs without duplicating proposals or configs  
6. **Lean inputs, adapter defaults**: changesets should require minimal user input; chain-family-specific defaults (attestation APIs, gas parameters, etc.) come from adapters  
7. **Product changesets combine offchain and onchain**: If a product changeset i.e. adding a new NOP combine onchain and offchain operation. The changeset should combine both onchain and offchain operation. If that’s not possible and multiple changesets are required we must include strict validation in the changeset to enforce the proper ordering.

---

# Potential flow with onchain/offchain orchestration

![Onchain/offchain orchestration flow](images/offchain-orchestration-flow.png)

