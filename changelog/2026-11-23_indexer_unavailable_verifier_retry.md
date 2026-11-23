# Indexer retries a message when a configured verifier did not start

## Executive Summary

- When the reader of a configured verifier does not start, the indexer now counts that verifier as unavailable. The message retries until its deadline.
- Before this change, the task treated the address as unknown and ignored it. The message could become `SUCCESS` without the verifications of that verifier.
- This change affects `indexer/pkg/registry`, `indexer/pkg/worker` and `indexer/cmd`.
- It adds two registry methods and changes the return values of an unexported task method. It has no config, schema or metric changes.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `worker.TaskResult.UnavailableCCVs` | behavior-changed | `UnavailableCCVs` | `indexer/pkg/worker/worker.go` | [#unavailable-ccvs-include-unstarted-verifiers](#unavailable-ccvs-include-unstarted-verifiers) |
| `registry.VerifierRegistry.MarkUnavailable`, `IsUnavailable` | added | `MarkUnavailable\(\|IsUnavailable\(` | `indexer/pkg/registry/verifier_registry.go` | [#registry-records-unstarted-verifiers](#registry-records-unstarted-verifiers) |

## Breaking Changes

*No breaking changes.*

## New Features / Additions

### Registry records unstarted verifiers

- `VerifierRegistry.MarkUnavailable(address)` records a configured address whose reader did not start.
- `VerifierRegistry.IsUnavailable(address)` returns true when the address is marked and has no registered reader.
- `cmd/main.go` calls `MarkUnavailable` for each issuer address of a verifier that `createReadersForVerifier` skips.

### Unavailable CCVs include unstarted verifiers

- `Task.loadVerifierReaders` returns a fourth list: the addresses that are configured but have no started reader.
- `Execute` adds these addresses to `TaskResult.UnavailableCCVs`. The worker retries a message while `UnavailableCCVs > 0`.
- An address that is in no `[[Verifiers]]` entry stays unknown. The task logs it and does not count it, as before.
- **Why:** With more than one replica, each replica builds its own registry. A replica with a failed reader could set `SUCCESS` before the other replicas collect the missing verification.

## Compatibility & Requirements

- **Rollout:** no special steps. The change applies per replica at startup.
