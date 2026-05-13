# CCV Product-Changeset Design \- Use-Case-First

## 1\. Summary

This document defines the `chainlink-ccv/deployment` product-changeset API. Two principles shape the design:

- **Use-case-first scope.** Product surface area is derived from "what actions do operators need to perform", then mapped onto changeset shapes. Each of the ten operator workflows enumerated in S5 is classified against the coupling map in S2.1 and assigned the narrowest changeset shape that still enforces correctness.  
- **CLD post-proposal hook is an assumed orchestration capability.** Products that require ordered onchain-then-offchain work decompose into two `ChangeSetV2` entries for correctness; a durable CLD pipeline with a post-proposal hook fires CLOPS automatically on timelock completion, and CLOPS spawns the step-2 offchain proposal. Operators see one workflow per product, not a two-merge process.

The combined effect: three well-defined changeset shapes (S6.1), coupling declared explicitly per product, and first-class coverage for use cases the v1 API does not address \- notably key rotation and standalone offchain config upgrades.

---

## 2\. Background

### 2.1 What couples and what doesn't

Not every CCIP 2.0 product that writes onchain has an offchain counterpart that must change in sync. The coupling map below is the spine of this document \- the proposed changeset shape for each use case (S5, S6.1) follows directly from this classification.

| Subsystem | Coupled to onchain? | Why / why not |
| :---- | :---- | :---- |
| **Committee verifier membership** (verifier node's local copy of the committee signer set) | **Yes** | Verifier keeps the committee membership in local config; must match onchain for the node to sign. |
| **Aggregator (quorum config)** | **Yes** | Aggregator stores threshold \+ signer addresses locally for each source chain. Must match onchain to tally valid signatures. |
| **Executor** | No | Reads destination state; no local mirror of onchain config that needs pre/post-update. |
| **Indexer** | No | Derives its state from onchain events; configuration additions (new lanes, new chains) are picked up by polling. |
| **Protocol contracts (onramp / offramp / fee quoter / router)** | No (among themselves) | Lane expansion wires these up onchain; no offchain component has a local mirror that must change in sync. |

**Key consequence:** Most products are either **onchain-only** or **offchain-only**. Only a narrow set \- the committee-verifier lifecycle (threshold changes, add/remove signer, key rotation) \- is coupled. A uniform two-entry changeset pattern is a correct fix for the coupled subset but an overfit for everything else.

**Lane expansion specifically:** no offchain coupling. Verifiers, executors, and indexers discover lanes by polling onchain state. Lane configuration is a pure onchain action with no offchain half.

**Chain addition:** Sequential, not coupled. Deploy the contracts, then configure offchain services to talk to them. No race window between the two \- the onchain contracts must exist before offchain services can reference them, so the natural ordering is also the only safe one.

### 2.2 CLD post-proposal hook capability

This design treats CLD post-proposal hooks as an available orchestration primitive (S6.2 gives the full contract). Operationally this means:

- A durable pipeline registered in CLD carries a post-proposal hook provided by the chainlink deployments framework. The hook fires on timelock execution, hits CLOPS, and CLOPS spawns a new offchain proposal for the step-2 changeset. The step-2 changeset runs under normal CLD pipeline execution; from an operator's perspective, the workflow completes itself once the timelock lands.  
- Coupled products decompose into two `ChangeSetV2` entries for correctness (S6.1), but the gate between them is timelock completion, not human review.  
- Step-2's `validate()` remains the correctness backstop \- asserts the step-1 change is live onchain \- in case the hook misfires or step-2 is manually invoked out of order.

Prereqs the CLD post-proposal hook mechanism must satisfy to make this work are enumerated in S6.2.

---

## 3\. Goals and Non-Goals

### Goals

- **One product \= one operator workflow.** An operator submits one CLOPS form, reviews one PR per step-1 entry, and the workflow completes itself via CLOPS callback (for coupled products) or inline (for decoupled and offchain-first single-pass products).  
- **Coupling is explicit in the API.** Each product's shape \- single-entry vs. two-entry \- directly reflects the coupling map in S2.1. No ambiguity about whether a flow needs MCMS ordering coordination.  
- **First-class coverage for all operator use cases in S5.** Including key rotation (routine and emergency), standalone offchain config upgrades, finality config updates, and sender allowlist management \- none of which map cleanly to today's v1 entry points.  
- **Compatible with CLD post-proposal hook orchestration.** Products are authored so that the step-1 → step-2 contract is purely `ChangesetOutput`\-typed; the hook \+ CLOPS orchestration is entirely external.  
- **Imperative inputs throughout.** No `*EnvironmentTopology` reconciler-shaped inputs. Every product takes scalar or slice input describing the intended change.

### Non-Goals

- **Not touching `chainlink-ccip/deployment/v2_0_0/`.** v1 keeps working; operators migrate per-product as new v2 changesets become available. Retirement is Phase H.  
- **Not migrating EVM chain-family adapters.** Coupled-onchain v2 products reach for `chainlink-ccip/deployment/v2_0_0/adapters` (`ChainFamilyRegistry`, `CommitteeVerifierContractRegistry`, `MCMSReaderRegistry`) as a stopgap import from the moment they're introduced; the move to a dedicated chainlink-ccv onchain-adapter layer is a follow-on and is not scoped here.  
- **Not specifying CLOPS internals.** S6.2 gives the minimum contract; the CLOPS team owns how that contract is implemented.  
- **Not boiling the ocean on every v1 gap.** Scope is the use cases enumerated in S5.  
- **Not upstreaming framework changes.** We do not depend on `chainlink-deployments-framework` gaining new capabilities; JD-in-hook remains read-only and we build around it.

---

## 4\. Existing v1 changesets \- survey and issues

### 4.1 Catalog

Ten exported `ChangeSetV2` constructors live in `chainlink-ccip/deployment/v2_0_0/changesets/`.

| Name | Input shape (topology?) | Purpose | Coupling |
| :---- | :---- | :---- | :---- |
| `ConfigureChainsForLanesFromTopology` | `*EnvironmentTopology` \+ `[]PartialChainConfig` \+ MCMS \- **topology** | Configure CCIP 2.0 lanes per local chain (enrich signers from topology/JD, then family-adapter onchain sequence). | Both: onchain lane writes; JD for signing-key fill-in when absent from topology. |
| `DeployChainContracts` | `WithMCMS[DeployChainContractsCfg]`, inner cfg uses `*EnvironmentTopology` \- **topology** | Deploy core 2.0 chain contracts (ramps, fee quoter, executors) per chain with MCMS. | Onchain \+ MCMS. |
| `DeployCCTPChains` | `map[uint64]CCTPChainConfig` \+ MCMS \- **imperative** | Deploy \+ wire CCTP infrastructure on selected chains. | Onchain \+ MCMS. |
| `DeployLombardChains` | `map[uint64]LombardChainConfig` \+ MCMS \- **imperative** | Deploy \+ wire Lombard token-pool / verifier stack on selected chains. | Onchain \+ MCMS. |
| `ApplyVerifierConfig` | `*EnvironmentTopology` \+ committee / executor qualifiers \+ optional NOP slice \- **topology** | Publish/refresh verifier job specs via JD (fetches signing keys, optional orphan revoke). | Offchain-only: JD \+ datastore reads. |
| `ApplyExecutorConfig` | `*EnvironmentTopology` \+ executor qualifier \+ optional NOPs \- **topology** | Publish/refresh executor job specs via JD (indexer URL from topology). | Offchain-only: JD \+ datastore reads. |
| `SyncJobProposals` | Optional `NOPAliases` \- **imperative** | Reconcile local vs JD job-proposal state (drift detection / sync). | Offchain-only: JD. |
| `GenerateAggregatorConfig` | Service id \+ committee qualifier \+ `*EnvironmentTopology` \- **topology** | Scan onchain committee state and write aggregator-config artifact to datastore. | Onchain read \+ datastore write; no JD. |
| `GenerateIndexerConfig` | Service id \+ verifier qualifier maps \- **imperative** | Emit indexer verifier-address config into datastore from deployment refs. | Offchain / artifact (datastore). |
| `GenerateTokenVerifierConfig` | Service id \+ chain selectors \+ monitoring \+ CCTP/Lombard API blocks \- **imperative** | Emit token-verifier (CCTP/Lombard) service config into datastore. | Offchain / artifact (datastore). |

`TopologyCommitteePopulator` in `configure_committee_verifiers.go` is a helper (not a `ChangeSetV2`), marked deprecated in favour of `ConfigureChainsForLanesFromTopology`.

### 4.2 What already exists in `chainlink-ccv/deployment/`

Six of the ten v1 changesets also live in `chainlink-ccv/deployment/changesets/` on main as parallel copies \- the offchain-only subset plus `orphan_cleanup` (a shared helper, not a `ChangeSetV2`). Migration to imperative inputs is partial:

| Name (chainlink-ccv copy) | Input shape today |
| :---- | :---- |
| `ApplyVerifierConfig` | Topology (`*ccvdeployment.EnvironmentTopology`) \+ committee / executor qualifiers \+ optional `[]NOPAlias`. |
| `ApplyExecutorConfig` | Topology \+ executor qualifier \+ optional `[]NOPAlias`. |
| `GenerateAggregatorConfig` | Service id \+ committee qualifier \+ topology. |
| `GenerateIndexerConfig` | Service id \+ verifier-qualifier maps \- **imperative**. |
| `GenerateTokenVerifierConfig` | Service id \+ chain selectors \+ monitoring \+ CCTP/Lombard blocks \- **imperative**. |
| `SyncJobProposals` | Optional `NOPAliases` \- **imperative**. |

Supporting infrastructure in `chainlink-ccv/deployment/`:

- `adapters/` \- chain-family-keyed *offchain* config adapters (aggregator / executor / verifier / indexer / token-verifier). No onchain / MCMS adapters.  
- `shared/`, `operations/`, `sequences/` \- JD client interface, job-proposal management sequence, per-family chain-type registry, node-chain-support fetch, signing-key fetch, propose/revoke/sync-job operations.  
- `topology.go` \- defines `EnvironmentTopology`, `NOPTopology`, `CommitteeConfig`; input type for the three remaining topology-driven changesets above.  
- `env_metadata_util.go` \- environment-metadata helpers.

No coupled-product changesets (threshold changes, add/remove signer, key rotation) exist here; those are the net-new work in S5.3 – S5.7.

### 4.3 Issues with v1

1. **Topology as reconciler-shaped input without a reconciler.** Five of the ten changesets accept `*EnvironmentTopology` and extract a slice of the full description (a committee, a set of chains, a NOP list). Each such extraction happens in-changeset, is not documented as a contract, and duplicates across products. The input shape *implies* a diff-against-state workflow the codebase does not actually perform.  
2. **No orchestrator.** For a workflow like "add a new chain", an operator runs `DeployChainContracts`, then `ConfigureChainsForLanesFromTopology`, then `ApplyVerifierConfig`, then `ApplyExecutorConfig`, in that order, with topology kept in sync between runs. The ordering and the complete set are nowhere codified; operators learn by example or by reading prior deployments.  
3. **Coupling not expressed in the API.** `ApplyVerifierConfig` (decoupled, JD-only) and `ConfigureChainsForLanesFromTopology` (onchain \+ JD via topology enrichment) have structurally similar signatures. An operator cannot tell from the API which ones require MCMS ordering coordination and which do not.  
4. **No key rotation changeset.** Signing-key discovery is baked into `ApplyVerifierConfig` / `ConfigureChainsForLanesFromTopology` / the deprecated `TopologyCommitteePopulator`, all of which fetch from JD. There is no top-level product for rotating a NOP's signing address \- emergency or routine.  
5. **Offchain-only upgrades are not first-class.** `ApplyVerifierConfig` *is* standalone, but in practice it's invoked as a sub-step of chain-addition workflows. The use case "verifier binary shipped with new config schema; no onchain work needed" does not map to a documented operator entry point.  
6. **Imperative / topology mix is inconsistent.** Of the imperative changesets (`DeployCCTPChains`, `DeployLombardChains`, `SyncJobProposals`, `GenerateIndexerConfig`, `GenerateTokenVerifierConfig`), there is no shared principle for why those five are imperative and the other five take topology. The split is historical, not designed.

---

## 5\. Use cases

Each use case subsection uses the template:

- **Operator intent** \- plain-English scenario.  
- **Current v1 flow** \- which changesets, in what order.  
- **Coupling profile** \- classified against the S2.1 map.  
- **Urgency profile** \- *routine* (weeks of planning), *time-sensitive* (days), or *emergency* (minutes-to-hours).  
- **Proposed v2 shape** \- *single-entry* / *two-entry \+ CLOPS callback* / *offchain-first single-pass* / *reuse-v1-as-imperative*.

### 5.1 Chain addition

- **Intent:** Add support for a brand-new destination chain to a running CCIP 2.0 deployment.  
- **Current v1 flow:** `DeployChainContracts` → `ConfigureChainsForLanesFromTopology` → `ApplyVerifierConfig` → `ApplyExecutorConfig`, with topology file updated between runs.  
- **Coupling:** Sequential-only. Offchain services reference onchain addresses that do not exist until the deploy lands; no race window.  
- **Urgency:** Routine.  
- **Proposed v2 shape:** A multi-changeset workflow, not a single product. Four imperative products (imperative `DeployChainContracts`, `LaneExpansion`, imperative `ApplyVerifierConfig`, imperative `ApplyExecutorConfig`) invoked in sequence, with a thin CLOPS-side "chain onboarding" form that stitches the inputs. No individual changeset in the sequence is coupled in the S2.1 sense; the ordering is enforced by sequential PR merges rather than by a single giant product.

### 5.2 Lane expansion and Router promotion

Two sequential sub-use-cases that together form the lane connection lifecycle:

#### 5.2.1 Lane expansion (wire with TestRouter)

- **Intent:** Enable a new source→destination lane between two already-deployed chains, initially wired to the TestRouter for integration testing.  
- **Current v1 flow:** `ConfigureChainsForLanesFromTopology` with `UseTestRouter=true`.  
- **Coupling:** **Onchain-only.** Verifiers are keyed by *source* chain (they validate signer sets per source); executors are keyed by *destination* chain (they execute messages arriving on a destination). Neither needs reconfiguration when a new lane is added between chains already known to both services \- the expansion is a pure onchain operation on the ramp contracts.  
- **Urgency:** Routine.  
- **Proposed v2 shape:** **Single-entry**, onchain-only. `LaneExpansion(srcChain, destChain, laneConfig, useTestRouter=true)`. Configures OnRamp and OffRamp with the TestRouter address via `ApplyDestChainConfigUpdates` / `ApplySourceChainConfigUpdates`, then wires them into the TestRouter via `ApplyRampUpdates`. Returns BatchOps in MCMS mode; runs immediately in deployer-key.

#### 5.2.2 Router promotion (TestRouter → production Router)

- **Intent:** Once a lane passes integration testing, switch the OnRamp and OffRamp from the TestRouter to the production Router so the lane goes live for real traffic.  
- **Current v1 flow:** Re-run `ConfigureChainsForLanesFromTopology` with `UseTestRouter=false`. No dedicated changeset.  
- **Coupling:** **Onchain-only.** Same as S5.2.1 \- no offchain services need to change; the Router swap is transparent to verifiers and executors.  
- **Urgency:** Routine.  
- **Proposed v2 shape:** **Single-entry**, onchain-only. `PromoteLaneRouter(srcChain, destChain, laneConfig)`. Re-configures OnRamp and OffRamp with the production Router address via `ApplyDestChainConfigUpdates` / `ApplySourceChainConfigUpdates`, then wires them into the production Router via `ApplyRampUpdates`. Returns BatchOps in MCMS mode; runs immediately in deployer-key.

### 5.3 Add signer (`AddNOPToCommittee`)

- **Intent:** Add a new NOP's signer to an existing committee.  
- **Current v1 flow:** Edit topology, run `ConfigureChainsForLanesFromTopology` \+ `ApplyVerifierConfig` \+ `GenerateAggregatorConfig`.  
- **Coupling:** **Coupled** \- committee verifier. But *additive*: a new signer that isn't yet onchain is a no-op in aggregator/verifier config, and a new signer in aggregator/verifier config ahead of onchain is safe (verifiers will sign with the larger quorum; onchain still requires the smaller).  
- **Urgency:** Routine.  
- **Proposed v2 shape:** **Offchain-first single-pass.** Regenerate aggregator config and publish new verifier job specs inline, then submit the onchain signer-add BatchOps in one Apply.

### 5.4 Remove signer (`RemoveNOPFromCommittee`)

- **Intent:** Remove a NOP's signer from a committee (voluntary exit, rotation, or administrative removal).  
- **Current v1 flow:** Edit topology; manual sequence of `ConfigureChainsForLanesFromTopology` (onchain remove) → `ApplyVerifierConfig` (revoke verifier job) \+ `GenerateAggregatorConfig` (regen without the signer).  
- **Coupling:** **Coupled** \- committee verifier. *Subtractive*: offchain config that removes a signer ahead of onchain would cause verifiers to reject signatures that onchain still considers valid. Onchain-first required.  
- **Urgency:** Routine (unless triggered by a compromise \- see S5.7).  
- **Proposed v2 shape:** **Two-entry \+ CLOPS callback.** Step-1: onchain signer-remove BatchOps. Step-2: aggregator regen \+ JD revoke of the NOP's verifier job. Step-2 fires via CLOPS callback after timelock execution.

### 5.5 Threshold increase (`IncreaseThreshold`)

- **Intent:** Raise a committee's signature threshold.  
- **Current v1 flow:** Edit topology, run `ConfigureChainsForLanesFromTopology` \+ `GenerateAggregatorConfig`.  
- **Coupling:** **Coupled** \- committee verifier. Offchain-first required (if onchain raises threshold first, verifiers still sign with the old smaller quorum → messages under-signed).  
- **Urgency:** Routine.  
- **Proposed v2 shape:** **Offchain-first single-pass.** Aggregator regen with an explicit threshold override \+ onchain threshold write in one Apply.

### 5.6 Threshold decrease (`DecreaseThreshold`)

- **Intent:** Lower a committee's signature threshold.  
- **Current v1 flow:** Same as S5.5 \- edit topology, re-run.  
- **Coupling:** **Coupled** \- committee verifier. Onchain-first required (if offchain lowers threshold first, verifiers sign with the new smaller quorum which onchain still rejects).  
- **Urgency:** Routine.  
- **Proposed v2 shape:** **Two-entry \+ CLOPS callback.** Step-1: onchain threshold-lower BatchOps. Step-2: aggregator regen.

### 5.7 Key rotation

- **Intent:** A NOP's signing key changes. Two sub-scenarios that differ on urgency:  
  - **Routine rotation:** NOP is rolling keys as hygiene; no compromise.  
  - **Emergency rotation:** NOP signing key is compromised. Attacker could sign on behalf of the NOP until the key is removed from the committee.  
- **Current v1 flow:** No product. Operators would need to compose add-signer \+ remove-signer by hand, with no shared validation that the two addresses belong to the same NOP, and no handling of the emergency case's urgency. Signing-key fetch logic in `ApplyVerifierConfig` / `ConfigureChainsForLanesFromTopology` assumes keys come from JD, which complicates "swap this key for that key" operations.  
- **Coupling:** **Coupled** \- committee verifier. Compound: additive step (new key) \+ subtractive step (old key). Ordering constraint depends on urgency \- see S6.4.  
- **Urgency:** Routine *or* emergency.  
- **Proposed v2 shape:** **New product `RotateNOPSigningKey`.** Composes `AddNOPToCommittee` \+ `RemoveNOPFromCommittee` shapes but with shared validation (same NOP identity, replacement-not-net-new invariant). The emergency sub-case needs its own shape; see S6.4 for the detailed design and the open security review it requires.

### 5.8 Token integration

- **Intent:** Onboard a new CCTP or Lombard token across a set of chains.  
- **Current v1 flow:** `DeployCCTPChains` (or `DeployLombardChains`) \+ `GenerateTokenVerifierConfig`.  
- **Coupling:** Sequential \- the verifier config references token addresses that only exist post-deploy. No race window.  
- **Urgency:** Routine.  
- **Proposed v2 shape:** **Single-entry** packaging: `TokenIntegration(tokenFamily=CCTP|Lombard, chainSelectors, …)`. Onchain deploy via BatchOps (MCMS) or immediate (deployer-key); token-verifier config DataStore write in the same Apply (lands at merge time). No coupling to committee verifier. Reuses v1 shapes behind an imperative façade.

### 5.9 Offchain-only software upgrades with new config

- **Intent:** A verifier / executor / indexer binary is released that reads a new config field. Operators need to push the updated config without any onchain change.  
- **Current v1 flow:** `ApplyVerifierConfig` (or `ApplyExecutorConfig` / `GenerateIndexerConfig`) invoked standalone \- possible but not marketed or documented as the intended entry point for this use case.  
- **Coupling:** **Offchain-only.** No onchain touch; no MCMS required.  
- **Urgency:** Time-sensitive (upgrade windows) but not emergency.  
- **Proposed v2 shape:** **Reuse as imperative.** `SyncJobProposals` and `GenerateIndexerConfig` are already imperative in `chainlink-ccv/deployment`; use as-is. `ApplyVerifierConfig` and `ApplyExecutorConfig` still take `*EnvironmentTopology` \- migrate to imperative inputs (Phase C) and document all four as operator entry points for standalone offchain upgrades. No new products.

### 5.10 Verifier / executor / indexer config changes

- **Intent:** Retune verifier / executor / indexer parameters (rate limits, monitoring endpoints, finality thresholds, indexer URLs, etc.) without touching onchain.  
- **Current v1 flow:** Same as S5.9.  
- **Coupling:** **Offchain-only.** Same as S5.9.  
- **Urgency:** Routine.  
- **Proposed v2 shape:** Same as S5.9. The two use cases collapse into the same product set once the v1 changesets are migrated to imperative inputs.

### 5.11 Finality config update (`SetAllowedFinalityConfig`)

- **Intent:** Update the allowed finality tag on a verifier or token-pool contract \- for example, tightening finality requirements after a chain reorg event, or relaxing them for a low-value lane.  
- **Current v1 flow:** No product. The `setAllowedFinalityConfig(bytes4)` function is callable directly by the contract owner (`onlyOwner`) but is not wrapped in any changeset.  
- **Coupling:** **Onchain-only.** `setAllowedFinalityConfig` is implemented on `CommitteeVerifier`, `LombardVerifier`, `CCTPVerifier`, and `TokenPool` (via `BaseVerifier._setAllowedFinalityConfig`). The executor exposes `getAllowedFinalityConfig` read-only; its finality config is set via `setDynamicConfig`, not this function. No offchain service keeps a local mirror that must change in sync \- the change takes effect onchain and services read it at the next attestation cycle.  
- **Urgency:** Routine, occasionally time-sensitive (incident response).  
- **Proposed v2 shape:** **Single-entry**, onchain-only. One product per contract family (verifier variant, token-pool variant), or a single product parameterised by contract type. Returns BatchOps in MCMS mode. No offchain half.

### 5.12 Sender allowlist management (`applyAllowlistUpdates`)

- **Intent:** Add or remove individual sender addresses from a per-destination-chain allowlist on a verifier contract, or toggle the allowlist on/off for a given destination chain.  
- **Current v1 flow:** No product. `applyAllowlistUpdates(AllowlistConfigArgs[])` is callable by the contract owner or a dedicated `allowlistAdmin` role, but is not wrapped in any changeset.  
- **Coupling:** **Onchain-only.** `applyAllowlistUpdates` is implemented on `CommitteeVerifier` (and analogously on `LombardVerifier` and `CCTPVerifier`) via `BaseVerifier._applyAllowlistUpdates`. The allowlist config is keyed by `destChainSelector` \- each destination chain has an independent allowlist (enabled flag \+ sender set). No offchain component mirrors this state.  
- **Urgency:** Routine, occasionally time-sensitive (block a malicious sender).  
- **Proposed v2 shape:** **Single-entry**, onchain-only. `UpdateSenderAllowlist(verifierRef, destChainSelector, addedSenders[], removedSenders[], enabled)`. Returns BatchOps in MCMS mode; deployer-key mode applies immediately. No offchain half.

---

## 6\. Design

### 6.1 Architectural pattern

Three product shapes, chosen per product based on its coupling profile:

**Decoupled products** (S5.1 chain-addition sub-steps, S5.2 lane expansion, S5.8 token integration, S5.9 / S5.10 offchain upgrades):

- Single `ChangeSetV2` entry.  
- In MCMS mode, `ChangesetOutput` may carry BatchOps (onchain) *and* DataStore mutations (offchain artifacts) in one PR \- any landing order is safe, so CLD's "DataStore writes immediately at merge, timelock fires later" natural ordering works regardless.

**Coupled offchain-first products** (S5.3 add signer, S5.5 threshold increase):

- Single-pass: offchain DataStore mutations \+ onchain BatchOps in one Apply.  
- Safe because the offchain change (add signer, raise threshold) is a strict superset of pre-change onchain requirements \- over-signed messages are harmless until the onchain change catches up.

**Coupled onchain-first products** (S5.4 remove signer, S5.6 threshold decrease, subtractive leg of S5.7 key rotation):

- Two `ChangeSetV2` entries: step-1 (onchain BatchOps only) \+ step-2 (offchain DataStore \+ JD writes).  
- A durable CLD pipeline's post-proposal hook fires on timelock execution, hits CLOPS, and CLOPS spawns the step-2 offchain proposal.  
- Step-2's `validate()` asserts the step-1 change is live onchain \- safety backstop in case of hook misfire, manual invocation out of order, or replay.

### 6.2 CLD post-proposal hook contract

The minimum `chainlink-ccv/deployment` depends on from the CLD post-proposal hook mechanism:

1. **Durable pipeline with post-proposal hook.** At step-1 submission time, operators register a durable pipeline in CLD that carries a post-proposal hook (provided by the chainlink deployments framework). The hook fires automatically on timelock execution; the chainlink-ccv side expresses the step-2 target as `(step-2 changeset name, step-2 input)` in the pipeline config or embedded in step-1's `ChangesetOutput` (e.g. in a structured `Reports` entry).  
2. **Hook triggers CLOPS to spawn step-2.** On timelock execution, the CLD framework fires the post-proposal hook, which calls CLOPS. CLOPS spawns a new offchain proposal for step-2. Implementation options (opens and auto-merges PR 2, or invokes a CLD pipeline endpoint directly) are CLOPS-owned; the chainlink-ccv side only requires that step-2's `Apply` eventually runs in a CLD pipeline context with a fresh env.  
3. **Retry \+ escalation.** Step-2 `validate()` failure or `Apply` error is retriable. Repeated failure surfaces to human review. Step-2 is idempotent (DataStore merges are set-like; JD revoke is a no-op on already-revoked jobs), so retries are safe.

**What must ship as prereq:** CLD post-proposal hook support in the chainlink deployments framework, plus CLOPS-side machinery to accept the hook call and spawn a step-2 proposal with retry \+ escalation policy. Tracked as Phase 0 in S7.

**What we don't depend on:** no real-time streaming, no per-changeset custom callback endpoints, no CLOPS-side knowledge of product semantics. The contract is changeset-shape-level, not per-product.

### 6.3 Use-case-to-changeset mapping

| \# | Use case | Proposed v2 product | Shape | v1 replacement / reuse |
| :---- | :---- | :---- | :---- | :---- |
| 1 | Chain addition | `DeployChainContracts`, `LaneExpansion`, `ApplyVerifierConfig`, `ApplyExecutorConfig` \- sequenced by CLOPS form | 4 × single-entry | Replaces `DeployChainContracts` \+ `ConfigureChainsForLanesFromTopology` \+ `ApplyVerifierConfig` \+ `ApplyExecutorConfig` with imperative inputs |
| 2a | Lane expansion (TestRouter) | `LaneExpansion` | Single-entry (onchain-only) | Replaces `ConfigureChainsForLanesFromTopology` with `UseTestRouter=true` |
| 2b | Router promotion | `PromoteLaneRouter` | Single-entry (onchain-only) | New; replaces re-running `ConfigureChainsForLanesFromTopology` with `UseTestRouter=false` |
| 3 | Add signer | `AddNOPToCommittee` | Offchain-first single-pass | Replaces manual orchestration of `ConfigureChainsForLanesFromTopology` \+ `ApplyVerifierConfig` \+ `GenerateAggregatorConfig` |
| 4 | Remove signer | `RemoveNOPFromCommittee` step-1 \+ `RemoveNOPOffchain` step-2 | Two-entry \+ callback | Same v1 replacement as \#3 |
| 5 | Threshold increase | `IncreaseThreshold` | Offchain-first single-pass | Same v1 replacement as \#3 |
| 6 | Threshold decrease | `DecreaseThreshold` step-1 \+ `DecreaseThresholdOffchain` step-2 | Two-entry \+ callback | Same v1 replacement as \#3 |
| 7 | Key rotation (routine) | `RotateNOPSigningKey` (composite) | Two sub-ops: offchain-first single-pass (add) \+ two-entry (remove) | New; fills v1 gap |
| 7′ | Key rotation (emergency) | `DisableCompromisedSigner` (fast) | TBD \- see S6.4 | New; fills v1 gap |
| 8 | Token integration | `TokenIntegration` (CCTP or Lombard variant) | Single-entry | Wraps `DeployCCTPChains` / `DeployLombardChains` \+ `GenerateTokenVerifierConfig` with imperative input |
| 9 | Offchain-only upgrades | Imperative `ApplyVerifierConfig` / `ApplyExecutorConfig` / `SyncJobProposals` | Single-entry (offchain-only) | Migrates v1 counterparts to imperative inputs |
| 10 | Verifier / executor / indexer config changes | Same as \#9 | Same as \#9 | Same as \#9 |
| 11 | Finality config update | `SetAllowedFinalityConfig` (verifier variant \+ token-pool variant) | Single-entry (onchain-only) | New; fills v1 gap |
| 12 | Sender allowlist management | `UpdateSenderAllowlist` | Single-entry (onchain-only) | New; fills v1 gap |

### 6.4 Key rotation (detailed)

Key rotation is the most novel use case. Two subcases with different urgency profiles:

#### 6.4.1 Routine rotation

NOP pre-generates a new keypair; wants to migrate to the new key with no service disruption.

- **Step A (additive):** Add the new signing address to the NOP's presence in the committee. Committee temporarily has `n+1` addresses for the rotating NOP (one NOP, two addresses). Aggregator regen pre-seeds the new address; verifier node picks up the new key via JD job spec update.  
- **Step B (subtractive):** After Step A lands (both offchain and onchain), remove the old signing address. Back to `n` addresses, with the new key in place.

Each step is implementable with existing primitives (`AddNOPToCommittee` for A, `RemoveNOPFromCommittee` for B). `RotateNOPSigningKey` is a composite that:

- Takes both addresses as input (`NOPAlias`, `OldAddress`, `NewAddress`).  
- Validates they belong to the same NOP identity.  
- Validates the remove-old step will not violate the `threshold ≤ signer-count` invariant at any point.  
- Invokes Step A, waits for completion (a PR merge gate for the operator), then invokes Step B.

Whether `RotateNOPSigningKey` is one "product" orchestrated by CLOPS with two PRs back-to-back, or two separate operator submissions, is a CLOPS-UX decision. At the `chainlink-ccv/deployment` layer it is two product invocations.

#### 6.4.2 Emergency rotation (compromised key)

NOP's signing key is compromised. An attacker can sign committee attestations on the NOP's behalf until the key is removed.

**The core constraint:** MCMS timelock is 3 hours. A compromised key can be used by the attacker for the entire timelock duration. This is the hard security question.

Two candidate responses, each with trade-offs, *flagged as requiring security review* before any is picked:

1. **Accept the 3h gap.** Document it as a known risk. Operators trigger rotation via the routine path; in the worst case the compromised key signs during the window but NOP thresholds should limit the blast radius.  
2. **Bypass MCMS Proposal.** Run a bypasser proposal for key rotation, similar to what we do for fast-curse. This may require legal/security signoff.

#### 6.4.3 Required inputs

Open question \- captured in S8. The `RotateNOPSigningKey` input at minimum needs:

- `NOPAlias` \- the rotating NOP.  
- `OldSigningAddress`, `NewSigningAddress` \- the two keys.  
- `CommitteeQualifier`, `ChainSelector` \- which committee.  
- `NewKeyJDJobSpec` (or ref) \- how the verifier node learns the new key.

Whether the new key's JD job-spec is pre-provisioned by the NOP (implying JD already has the new key before rotation starts) or generated in-flow is the core operational question.

### 6.5 Status of existing `chainlink-ccv/deployment` code

Today's `chainlink-ccv/deployment/` (see S4.2 for inventory) contains the offchain-only subset of v1 \- six `ChangeSetV2` exports plus support infrastructure. Positioned against this design:

| Item | Status under this design | Notes |
| :---- | :---- | :---- |
| `ApplyVerifierConfig` (topology-driven) | Migrate to imperative. Phase C. | Covers use cases S5.9 / S5.10 once imperative. A per-NOP imperative variant is also needed for coupled committee products (S5.3, S5.4, S5.7) \- see S7 Phase B open question. |
| `ApplyExecutorConfig` (topology-driven) | Migrate to imperative. Phase C. | Covers S5.9 / S5.10 once imperative. |
| `GenerateAggregatorConfig` (topology-driven) | Add an imperative companion (chain-selectors-keyed) for use *inside* coupled-committee product changesets. Phase A. | The topology-driven version can stay available for standalone aggregator regen until Phase C retires it. |
| `GenerateIndexerConfig` (imperative) | Fits design as-is. | Serves S5.9 / S5.10. |
| `GenerateTokenVerifierConfig` (imperative) | Fits design as-is; wrapped into `TokenIntegration` in Phase F. | Serves S5.8. |
| `SyncJobProposals` (imperative) | Fits design as-is. | Serves S5.9 / S5.10. |
| `orphan_cleanup.go` helper | Keep; shared helper. | Already used by the `Apply*Config` changesets. |
| `adapters/` (offchain config adapters per chain family) | Keep; extend alongside. | Phase A adds chainlink-ccip-imported onchain / committee-verifier / MCMS adapters as a stopgap (S3 Non-Goals). |
| `shared/`, `operations/`, `sequences/` | Keep; reuse. | JD-client interface, job-proposal management sequence, propose/revoke/sync-job ops all carry over unchanged. |
| `topology.go` (`EnvironmentTopology`, `NOPTopology`, `CommitteeConfig`) | Retain as input type for the three topology-driven changesets above. Does not grow. Retires in Phase C once those changesets migrate. | No new consumers of topology types in any new product. |
| `go.mod` dep on `chainlink-deployments-framework v0.94.1` | No change needed for this design. | Coupled products use `ChangeSetV2` \+ MCMS primitives that exist at v0.94.1. |

Deployer-key semantics for any coupled product added under this design are the same regardless of CLOPS callback availability \- deployer-key mode runs both halves inline in one Apply. The CLOPS shift only affects MCMS-mode flow description.

---

## 7\. Implementation plan

Listed in rough dependency order; items within a phase can parallelise.

### Phase 0 \- CLOPS prereq coordination

Out of `chainlink-ccv/deployment` scope; tracked as dependency. Gate: CLD post-proposal hook support ships (chainlink deployments framework) and CLOPS team ships the S6.2 step-2 spawning mechanism \+ retry policy. Phases B, D, E, and F produce two-entry products whose MCMS-mode execution depends on this.

### Phase A \- First coupled product \+ scaffolding

Introduce the infrastructure a coupled-committee product needs and exercise it with the simplest member of the family:

- Add a stopgap dependency on `chainlink-ccip/deployment/v2_0_0/adapters` (for `ChainFamilyRegistry`, `CommitteeVerifierContractRegistry`) and `chainlink-ccip/deployment/utils/mcms` (for MCMS proposal scaffolding). See S3 Non-Goals.  
- Introduce an imperative aggregator-regen companion to `GenerateAggregatorConfig` (keyed on chain selectors, with an explicit threshold override for offchain-first flows).  
- Introduce shared helpers for building `ConfigureChainForLanes*`\-style imperative inputs from scalar committee / chain / threshold parameters.  
- Ship `IncreaseThreshold` (S5.5, offchain-first single-pass) and `DecreaseThreshold` \+ `DecreaseThresholdOffchain` (S5.6, coupled-onchain-first two-entry). Exercises all three shapes in S6.1 except the "coupled but add-signer" offchain-first variant (deferred to Phase B).  
- Deployer-key mode ships fully in this phase; MCMS-mode `DecreaseThreshold` end-to-end waits on Phase 0\.

### Phase B \- Add / remove signer

- `AddNOPToCommittee` (S5.3, coupled offchain-first single-pass), reusing Phase A helpers.  
- `RemoveNOPFromCommittee` \+ `RemoveNOPOffchain` (S5.4, coupled onchain-first two-entry), reusing Phase A helpers.

Two design points to resolve before coding starts:

1. Shape of an imperative `ApplyVerifierConfigForNOPs` helper \- extracted from the topology-driven `ApplyVerifierConfig` in `chainlink-ccv/deployment/` into a per-NOP imperative variant covering the "provision (or revoke) a single NOP's verifier jobs" case.  
2. Mechanism for injecting new signer addresses per source chain into the imperative aggregator regen \- scalar override on its input, or a separate composed builder.

### Phase C \- Migrate topology-driven offchain changesets

Migrate `ApplyVerifierConfig`, `ApplyExecutorConfig`, and `GenerateAggregatorConfig` in `chainlink-ccv/deployment/changesets/` from `*EnvironmentTopology` inputs to imperative inputs. Covers use cases S5.9 and S5.10 for the first two; the third is subsumed by Phase A's imperative companion. No MCMS coordination required \- these are offchain-only.

When this phase lands, `topology.go` has no remaining in-tree consumers and can be retired.

### Phase D \- Key rotation

- `RotateNOPSigningKey` composite for the routine case.

### Phase E \- Chain \+ lane expansion

- Imperative `LaneExpansion` (single-entry, onchain-only) \- S5.2.  
- Imperative `DeployChainContracts` variant (single-entry, onchain-only with BatchOps) \- S5.1.  
- CLOPS-side chain-onboarding form that stitches Phase C's offchain products with these two onchain ones.

### Phase F \- Token integration

Imperative `TokenIntegration` wrapping v1 CCTP/Lombard deploys \+ `GenerateTokenVerifierConfig`. Single-entry. S5.8.

### Phase G \- `chainlink-deployments/domains/ccv` \+ `clops-ccip` integration

Sibling-repo work. Registers the chainlink-ccv products as CLOPS pipeline entries. Out of current `chainlink-ccv/deployment` scope; tracked as dependency.

### Phase H \- Retire `chainlink-ccip/deployment/v2_0_0/`

Delete once operators have migrated to the chainlink-ccv equivalents. Gated on operator sign-off per product.

---

## 8\. Risks and open questions

### Risks

- **Topology → imperative migration may surface input gaps.** For chain addition and lane expansion, do operators have ready access to the inputs the imperative API needs (chain-family addresses, finality configs, signer sets)? If not, CLOPS forms must fill the gap \- otherwise we have just moved the problem from in-changeset topology extraction to in-form input elicitation.  
- **Two aggregator builders coexist during migration.** The topology-driven `GenerateAggregatorConfig` in `chainlink-ccv/deployment` and the imperative companion introduced in Phase A both scan onchain committee state. Divergence risk until Phase C retires the topology-driven version. Phase A should factor the on-chain scan into a shared helper the two builders call, not duplicate it.  
- **Stopgap dependency on `chainlink-ccip/deployment/v2_0_0/`.** Phase A introduces a `chainlink-ccv/deployment/go.mod` import of chainlink-ccip's adapter packages. This couples v2 coupled-product work to v1's release cadence for chain-family / committee-verifier / MCMS adapters. Extraction into a dedicated chainlink-ccv onchain-adapter layer is a separate follow-up.

### Open questions

1. **Single-entry `LaneExpansion` input shape.** Does the chain-family adapter lookup still need topology-like context (e.g. default finality config, executor pool references) that is only available in the topology today? Or is the imperative input self-contained once the onchain contracts exist?  
2. **CLOPS callback retry semantics.** How aggressive is retry? Is there a visible operator error state for a step-2 that has failed its retries? Who triages?  
3. **`RotateNOPSigningKey` input \- JD job-spec pre-provisioning.** Is the new key's JD job spec already in JD before rotation starts (NOP-operated), or generated in-flow (operator-operated)? Affects what `RotateNOPSigningKey` needs in its input.  
4. **Coupling map completeness.** S2.1 is built from analysis of the committee-verifier / aggregator / executor / indexer architecture. Is there any other subsystem with a local mirror of onchain state that has been missed (e.g. indexer runtime config that embeds committee member addresses, monitoring services keyed on lanes)? A pass with the relevant subsystem owners is recommended before Phase A's coupled products land.  
5. **Shared `ApplyVerifierConfigForNOPs` helper.** S5.3 (`AddNOPToCommittee`) and S5.7 (`RotateNOPSigningKey`) both need verifier-job provisioning for a specific NOP. Is there a single imperative helper that serves both, or does each product carry its own? Resolve in Phase B; revisit in Phase D.

