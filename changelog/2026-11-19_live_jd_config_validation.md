# Live JD state for verifier and executor activation

## Executive Summary

- Verifier and executor chain-support validation now queries current JD state instead of reusing an earlier operation report.
- Verifier and executor activation use the durable `offchainConfigs.jdNodes` inventory for their node-ID allowlist, including standalone executor node-name resolution.
- Registration's datastore output is therefore sufficient for activation in a later durable-pipeline job; `nodes.json` remains a compatibility fallback for environments without persisted inventory.
- The implementation is chain-family agnostic; regression coverage includes a Solana JD chain-config response.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `changesets.fetchNodeChainSupport` | behavior-changed | `fetchNodeChainSupport\(` | `deployment/changesets/apply_executor_config.go:324` | [#fresh-chain-support-reads](#fresh-chain-support-reads) |
| `changesets.withPersistedJDNodeIDs` | added | `withPersistedJDNodeIDs\(` | `deployment/changesets/jd_node_inventory.go:13` | [#durable-node-inventory-handoff](#durable-node-inventory-handoff) |
| `changesets.ApplyExecutorConfig` | behavior-changed | `ApplyExecutorConfig\(\)` | `deployment/changesets/apply_executor_config.go:50` | [#durable-node-inventory-handoff](#durable-node-inventory-handoff) |
| `changesets.ApplyVerifierConfig` | behavior-changed | `ApplyVerifierConfig\(\)` | `deployment/changesets/apply_verifier_config.go:214` | [#durable-node-inventory-handoff](#durable-node-inventory-handoff) |

## Breaking Changes

*No breaking changes.* Existing inputs, outputs, and JD operation definitions are unchanged.

## New Features / Additions

### Fresh chain-support reads

`fetchNodeChainSupport` executes `fetch-node-chain-support` with `operations.WithForceExecute`. A successful report from an earlier operation with the same input can no longer supply an empty or otherwise stale chain-support result to `validateVerifierChainSupport` or `validateExecutorChainSupport`.

This deliberately does not add framework-wide retries. The JD read can succeed with an empty result, so the caller must require a fresh read before validating the requested chains. Chain decoding still uses the existing chain-type registry and chain-selectors lookup; no family is special-cased by this change.

### Durable node-inventory handoff

`withPersistedJDNodeIDs` reads `deployment.GetJDNodes` and replaces `Environment.NodeIDs` with the sorted inventory keys when the snapshot is non-empty. Both executor preconditions and apply, and verifier apply, resolve this environment before any JD lookup or proposal management.

This covers alias lookup, standalone executor routing, chain-support validation, job proposal, and orphan cleanup without introducing chain-specific behavior. Existing environments without `offchainConfigs.jdNodes` retain the legacy CLD-provided `Environment.NodeIDs` behavior.

A downstream CLD deployment should bump its `chainlink-ccv/deployment` pin to a version containing this change and `2026-11-13_jd_node_inventory.md`. The registration job's normal datastore artifact then supplies the node inventory to later verifier or executor jobs; no separate `nodes.json` artifact commit is required for these changesets.

## Compatibility & Requirements

- No configuration or dependency changes are required.
- `nodes.json` is still written by registration and remains the fallback for pre-inventory environments and other consumers.
- Chain-support validation requires a live JD read on every apply, so it no longer benefits from operation-report reuse.

## References

- Durable inventory format and persistence: `changelog/2026-11-13_jd_node_inventory.md`.
