# Indexer retries a message when a configured verifier did not start

## Executive Summary

- When the reader of a configured verifier does not start, the indexer now counts that verifier as unavailable. The message retries until its deadline.
- Before this change, the task treated the address as unknown and ignored it. The message could become `SUCCESS` without the verifications of that verifier.
- Config validation now rejects an invalid or repeated issuer address in a verifier, so a config error stops the indexer at boot. Only a reader that does not start makes a verifier unavailable.
- Two new metrics show unavailable verifiers and the message attempts that they block.
- This change affects `indexer/pkg/registry`, `indexer/pkg/worker`, `indexer/pkg/config`, `indexer/pkg/monitoring`, `indexer/pkg/common` and `indexer/cmd`.
- It adds two registry methods, two labeler methods and one pool method. It has no schema changes.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `worker.TaskResult.UnavailableCCVs` | behavior-changed | `UnavailableCCVs` | `indexer/pkg/worker/worker.go` | [#unavailable-ccvs-include-unstarted-verifiers](#unavailable-ccvs-include-unstarted-verifiers) |
| `registry.VerifierRegistry.MarkUnavailable`, `IsUnavailable` | added | `MarkUnavailable\(\|IsUnavailable\(` | `indexer/pkg/registry/verifier_registry.go` | [#registry-records-unstarted-verifiers](#registry-records-unstarted-verifiers) |
| `common.IndexerMetricLabeler.RecordVerifierUnavailableGauge`, `IncrementUnavailableVerifierRetries` | signature-changed | `IndexerMetricLabeler\b` | `indexer/pkg/common/metrics.go` | [#metrics](#metrics) |
| `worker.Pool.SetMetrics` | added | `SetMetrics\(` | `indexer/pkg/worker/worker_pool.go` | [#metrics](#metrics) |
| `config.Config.Validate` issuer addresses | behavior-changed | `IssuerAddresses` | `indexer/pkg/config/config.go` | [#config-validation-rejects-bad-issuer-addresses](#config-validation-rejects-bad-issuer-addresses) |

## Breaking Changes

### Config validation rejects bad issuer addresses

- **What changed:** `Config.Validate` rejects a `[[Verifiers]]` entry with an issuer address that is not valid hex, or with the same address two times. Before, startup skipped that verifier.
- The same address in two verifiers is still valid. HA setups use it.
- **Who is affected:** deploy configs with a bad issuer address. The indexer does not start until you correct the config.

### IndexerMetricLabeler has two new methods

- **Who is affected:** custom `IndexerMetricLabeler` implementations. Add the two methods in [Metrics](#metrics). Regenerate mocks with `just mock`.

## Migration Guide

1. Validate each deploy config before the rollout. Correct all invalid or repeated issuer addresses.
2. Add `RecordVerifierUnavailableGauge` and `IncrementUnavailableVerifierRetries` to custom `IndexerMetricLabeler` implementations.
3. Regenerate mocks: `just mock`.

## New Features / Additions

### Registry records unstarted verifiers

- `VerifierRegistry.MarkUnavailable(address, name)` records a configured address whose reader did not start, and its verifier name.
- `VerifierRegistry.IsUnavailable(address)` returns true when the address is marked and has no registered reader.
- `cmd/main.go` calls `MarkUnavailable` for each issuer address of a verifier that `createReadersForVerifier` skips.
- After the config validation, a skip occurs only when the reader cannot be created or started.

### Unavailable CCVs include unstarted verifiers

- `Task.loadVerifierReaders` returns a fourth list: the addresses that are configured but have no started reader.
- `Execute` adds these addresses to `TaskResult.UnavailableCCVs`. The worker retries a message while `UnavailableCCVs > 0`.
- An address that is in no `[[Verifiers]]` entry stays unknown. The task logs it and does not count it, as before.
- **Why:** With more than one replica, each replica builds its own registry. A replica with a failed reader could set `SUCCESS` before the other replicas collect the missing verification.

## Metrics

- **Added:** `indexer_verifier_unavailable` (gauge, label `verifier`). It is 1 when a configured verifier has no started reader on this replica, else 0. Startup records it for each verifier. Alert when it is above 0.
- **Added:** `indexer_unavailable_verifier_retries_total` (counter, label `verifier`). It counts the message attempts that retry because the verifier has no started reader. `Pool.SetMetrics` gives the labeler to the tasks.

## Compatibility & Requirements

- **Rollout:** no special steps. The change applies per replica at startup.
