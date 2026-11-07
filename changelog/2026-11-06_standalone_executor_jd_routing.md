# Standalone executor JD routing and reconciliation

## Executive Summary

- `ApplyExecutorConfig` now routes standalone executor jobs to an explicit or reconciled executor JD node instead of resolving the verifier NOP alias.
- This prevents standalone executor specs from being proposed to verifier JD records in split deployments.
- `ReconcileJobsWithJD` adopts approved, manually proposed standalone executor jobs into the datastore without modifying JD.
- Existing CL-mode and no-JD local workflows retain their previous behavior.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `changesets.ApplyExecutorConfig` | behavior-changed | `ApplyExecutorConfig\b` | `deployment/changesets/apply_executor_config.go:50` | [#standalone-routing-requirements](#standalone-routing-requirements) |
| `changesets.ApplyVerifierExecutorConfig` | behavior-changed | `ApplyVerifierExecutorConfig\b` | `deployment/changesets/apply_verifier_executor_config.go:96` | [#standalone-routing-requirements](#standalone-routing-requirements) |
| `changesets.NOPInput.ExecutorNodeID` | added | `ExecutorNodeID\b` | `deployment/changesets/inputs.go:14` | [#standalone-routing-requirements](#standalone-routing-requirements) |
| `changesets.ReconcileJobsWithJDInput` | added | `ReconcileJobsWithJDInput\b` | `deployment/changesets/reconcile_jobs_with_jd.go:20` | [#jd-reconciliation](#jd-reconciliation) |
| `changesets.ReconcileJobWithJD` | added | `ReconcileJobWithJD\b` | `deployment/changesets/reconcile_jobs_with_jd.go:25` | [#jd-reconciliation](#jd-reconciliation) |
| `changesets.ReconcileJobsWithJD` | added | `ReconcileJobsWithJD\b` | `deployment/changesets/reconcile_jobs_with_jd.go:50` | [#jd-reconciliation](#jd-reconciliation) |
| `propose_jobs.JobSpecInput.NodeID` | added | `JobSpecInput\{` | `deployment/operations/propose_jobs/propose_jobs.go:16` | [#standalone-routing-requirements](#standalone-routing-requirements) |
| `sequences.ManageJobProposalsInput.StandaloneExecutorNodeIDs` | added | `StandaloneExecutorNodeIDs\b` | `deployment/sequences/manage_job_proposals.go:24` | [#standalone-routing-requirements](#standalone-routing-requirements) |
| `shared.NodeLookup.FindByID` | added | `\.FindByID\(` | `deployment/shared/nodes.go:37` | [#standalone-routing-requirements](#standalone-routing-requirements) |

## Breaking Changes

No breaking API changes. Standalone executor publishing now fails preconditions when neither reconciled metadata nor `NOPInput.ExecutorNodeID` identifies a target JD node. It no longer falls back to the verifier NOP alias.

## Migration Guide

1. For jobs already proposed manually, run `ReconcileJobsWithJD` with the approved standalone TOML path and executor node ID before calling `ApplyExecutorConfig`.
2. For initial standalone provisioning, set `NOPInput.ExecutorNodeID` to the executor's JD node ID. Existing CL-mode inputs require no changes.
3. CLD should replace its local `CsReconcileJobsWithJD` adapter with `changesets.ReconcileJobsWithJD()` after updating the `chainlink-ccv/deployment` dependency.

## Standalone routing requirements

- **`NOPInput.ExecutorNodeID`** — explicitly selects the JD node for initial standalone executor provisioning. A conflicting value is rejected when reconciled metadata already exists.
- **Exact JD node routing** — `propose_jobs.JobSpecInput.NodeID` uses `shared.NodeLookup.FindByID` rather than NOP names. An unknown explicit ID fails without alias fallback.
- **Routing propagation** — `ApplyExecutorConfig` supplies `StandaloneExecutorNodeIDs` to `ManageJobProposals`, which forwards each changed job's node ID to the proposal operation.

## JD reconciliation

**`ReconcileJobsWithJD`** accepts `ReconcileJobsWithJDInput`, whose entries contain a NOP alias, standalone TOML path, and executor node ID. It validates executor identity, environment membership, a unique live JD job, and an approved latest proposal byte-identical to the supplied TOML. It returns a cloned datastore containing standalone mode, the live JD job ID, node ID, spec, and proposal history. It performs no JD mutations and returns no datastore output if any input fails validation.

## Compatibility & Requirements

- CL-mode proposals continue to resolve JD nodes by NOP alias.
- No-JD local environments can still emit standalone executor specs without provisioning metadata.
- Standalone executor targets must belong to `deployment.Environment.NodeIDs`.
- The combined verifier/executor changeset validates executor routing before applying either flow.

## References

- Epic: https://smartcontract-it.atlassian.net/browse/CCIP-13517
- Upstream migration task: https://smartcontract-it.atlassian.net/browse/CCIP-14558
- Original CLD reconciliation: https://github.com/smartcontractkit/chainlink-deployments/pull/21157
