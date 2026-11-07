# Standalone executor JD routing and reconciliation

## Executive Summary

- `ApplyExecutorConfig` proposes each standalone executor job to that NOP's executor JD node, never to the node named after the NOP alias (in split deployments that is the verifier).
- The executor node is declared per NOP with `NOPInput.ExecutorNodeName` (topology `executor_node_name`) or `NOPInput.ExecutorNodeID`. A declared node is authoritative: a job recorded on another node, including a CL-mode job, is moved there in the same run. A job already proposed on that node, for example by hand, is adopted rather than proposed again.
- A standalone NOP in no committee runs only an executor, so the topology defaults its executor node to its alias. Only NOPs that run a verifier and an executor under one alias (the EVM split NOPs) need `executor_node_name`; altVM and devenv executor NOPs need nothing.
- Without a declaration the changeset reuses the node recorded in the datastore, and fails closed when there is none or when that node already runs another job.
- Chain support for standalone executors is checked on the routed node, and a job that lands on a new JD job starts a new proposal history.
- `ReconcileJobsWithJD` adopts approved, manually proposed standalone executor jobs into the datastore without modifying JD.
- CL-mode routing and no-JD local spec generation are unchanged.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `changesets.ApplyExecutorConfig` | behavior-changed | `ApplyExecutorConfig\b` | `deployment/changesets/apply_executor_config.go:50` | [#standalone-routing](#standalone-routing) |
| `changesets.ApplyVerifierExecutorConfig` | behavior-changed | `ApplyVerifierExecutorConfig\b` | `deployment/changesets/apply_verifier_executor_config.go:96` | [#standalone-routing](#standalone-routing) |
| `sequences.ManageJobProposals` | behavior-changed | `ManageJobProposals\b` | `deployment/sequences/manage_job_proposals.go:54` | [#moved-jobs](#moved-jobs) |
| `changesets.NOPInputsFromTopology` | behavior-changed | `NOPInputsFromTopology\(` | `deployment/changesets/topology_inputs.go:16` | [#declaring-the-executor-node](#declaring-the-executor-node) |
| `deployment.NOPTopology.ExecutorNodeName` | added | `\.ExecutorNodeName\(` | `deployment/topology.go:113` | [#declaring-the-executor-node](#declaring-the-executor-node) |
| `changesets.NOPInput.ExecutorNodeName` | added | `ExecutorNodeName\b` | `deployment/changesets/inputs.go:21` | [#declaring-the-executor-node](#declaring-the-executor-node) |
| `changesets.NOPInput.ExecutorNodeID` | added | `ExecutorNodeID\b` | `deployment/changesets/inputs.go:19` | [#declaring-the-executor-node](#declaring-the-executor-node) |
| `deployment.NOPConfig.ExecutorNodeName` | added | `executor_node_name\|ExecutorNodeName\b` | `deployment/topology.go:92` | [#declaring-the-executor-node](#declaring-the-executor-node) |
| `changesets.ExecutorConfigFromStateOptions.ExecutorNodeNameByNOP` | added | `ExecutorNodeNameByNOP\b` | `deployment/changesets/executor_state_inputs.go:222` | [#declaring-the-executor-node](#declaring-the-executor-node) |
| `fetch_node_chain_support.FetchNodeChainSupportInput.NodeIDByNOPAlias` | added | `NodeIDByNOPAlias\b` | `deployment/operations/fetch_node_chain_support/fetch_node_chain_support.go:19` | [#standalone-routing](#standalone-routing) |
| `propose_jobs.JobSpecInput.NodeID` | added | `JobSpecInput\{` | `deployment/operations/propose_jobs/propose_jobs.go:21` | [#standalone-routing](#standalone-routing) |
| `sequences.ManageJobProposalsInput.StandaloneExecutorNodeIDs` | added | `StandaloneExecutorNodeIDs\b` | `deployment/sequences/manage_job_proposals.go:33` | [#standalone-routing](#standalone-routing) |
| `shared.NodeLookup.FindByID` | added | `\.FindByID\(` | `deployment/shared/nodes.go:37` | [#standalone-routing](#standalone-routing) |
| `changesets.ReconcileJobsWithJDInput` | added | `ReconcileJobsWithJDInput\b` | `deployment/changesets/reconcile_jobs_with_jd.go:20` | [#jd-reconciliation](#jd-reconciliation) |
| `changesets.ReconcileJobWithJD` | added | `ReconcileJobWithJD\b` | `deployment/changesets/reconcile_jobs_with_jd.go:25` | [#jd-reconciliation](#jd-reconciliation) |
| `changesets.ReconcileJobsWithJD` | added | `ReconcileJobsWithJD\b` | `deployment/changesets/reconcile_jobs_with_jd.go:51` | [#jd-reconciliation](#jd-reconciliation) |

## Breaking Changes

No Go API breaks. Standalone executor publishing now fails preconditions when a targeted standalone NOP has neither a declared executor node nor a complete standalone record in the datastore. The changeset no longer falls back to the node named after the NOP alias; for executor-only NOPs, `NOPInputsFromTopology` declares that node explicitly instead.

## Migration Guide

1. For every standalone NOP that is in a committee and an executor pool, set `executor_node_name` in `topology.toml` to its executor's JD node name, for example `executor_node_name = "executor-evm-0"`. Executor-only NOPs need nothing as long as their JD node is named after the alias. Callers that build `NOPInput` directly, without `NOPInputsFromTopology`, set `ExecutorNodeName` or `ExecutorNodeID` themselves.
2. A CL to standalone cutover is then one `apply-executor-config` run after the executor is registered with JD. It proposes the standalone spec to the executor node and records it; no `jd_propose_job` or `jd_reconcile_jobs` step is needed. If the job was already proposed to that node, the run adopts it and proposes again only when the spec differs from the generated one.
3. `ReconcileJobsWithJD` records a hand-proposed job without proposing anything. The next apply run still converges the job to the generated spec.
4. CLD should replace its local `CsReconcileJobsWithJD` adapter with `changesets.ReconcileJobsWithJD()` after updating the `chainlink-ccv/deployment` dependency.

## Declaring the executor node

`NOPInput.ExecutorNodeName` is resolved to a node ID at apply time through JD, among the environment's `NodeIDs`, so it can refer to a node registered earlier in the same pipeline. `ExecutorNodeID` targets a node ID directly. When both are set they must name the same node. Both only apply to standalone NOPs; CL-mode NOPs keep alias routing.

`NOPInputsFromTopology` fills `ExecutorNodeName` from `NOPTopology.ExecutorNodeName`: the declared `executor_node_name`, or the NOP alias for a standalone NOP that appears in no committee. Such a NOP runs only an executor, and executors of that kind (altVM executors in CLD, every devenv executor) are registered in JD under the alias. A NOP that also runs a verifier gets no default, because its alias names the verifier's node. Topology validation rejects two NOPs that resolve to the same executor node.

## Standalone routing

For each targeted standalone NOP, `ApplyExecutorConfig` resolves one node:

- A declared node wins. If the datastore records the job on a different node or in CL mode, the job is proposed to the declared node and its record moves there.
- Without a declaration, a complete standalone record (JD job ID, node ID and the expected external job ID) is reused. A missing, never-proposed, CL-mode or incomplete record fails with an error that names the field to set.
- The node must be in `deployment.Environment.NodeIDs`, no two targeted jobs may share it, and no other recorded job may run on it. A standalone bootstrap runs one job and replaces it on every new proposal, so a shared node would stop the other job. This also rejects records written by the old alias routing, which put executor jobs on verifier nodes.
- Routing is checked in `VerifyPreconditions`, so `ApplyVerifierExecutorConfig` rejects bad executor routing before either flow runs.
- `ProposeJobs` targets the node with `NodeLookup.FindByID` and fails on an unknown ID without falling back to the alias.
- Chain support is validated on the routed node through `FetchNodeChainSupportInput.NodeIDByNOPAlias`, not on the node named after the NOP.

## Moved jobs

Before proposing a job routed to a node other than the recorded one, `ManageJobProposals` lists the target node's JD jobs and adopts the live one with the job's external job ID, if any. The adopted job's proposals are then compared like any other, so a job already proposed there is not proposed again when its spec matches. More than one live match is an error.

Whenever the JD job changes (a move, or a recorded JD job that JD no longer has), the recorded proposal history and active proposal are dropped and rebuilt from the new JD job. Revisions are numbered per JD job, so mixing histories made the old job's approved revision look current. The previous JD job is logged at warn level and left in JD. JD refuses to revoke approved jobs, so removing an old approved job still needs a JD delete.

## JD reconciliation

`ReconcileJobsWithJD` accepts `ReconcileJobsWithJDInput`, whose entries contain a NOP alias, standalone TOML path, and executor node ID. It validates executor identity, environment membership, a unique live JD job, and an approved latest proposal byte-identical to the supplied TOML. It returns a cloned datastore containing standalone mode, the live JD job ID, node ID, spec, and proposal history. It performs no JD mutations and returns no datastore output if any input fails validation.

## Compatibility & Requirements

- Standalone executor bootstraps must report their chains to JD (`[[chains]]` in the bootstrap config) for pools on chains whose adapter requires JD chain support. The Solana, Aptos, Stellar and Canton executor adapters opt out, so altVM chains are not checked.
- No-JD local environments still emit standalone executor specs without a declared node. A later JD run takes the declared node.
- A NOP that runs a verifier must be in its committee before its executor is first applied, or declare `executor_node_name`. Otherwise it gets the executor-only default and its alias, which names the verifier node, is used. The one-job-per-node check fails the run once the verifier's job is recorded on that node.

## References

- Epic: https://smartcontract-it.atlassian.net/browse/CCIP-13517
- Upstream migration task: https://smartcontract-it.atlassian.net/browse/CCIP-14558
- Original CLD reconciliation: https://github.com/smartcontractkit/chainlink-deployments/pull/21157
