# Compact persisted job proposal metadata

## Executive Summary

- `ProposalRevision.Spec` is now runtime-only and is omitted from JSON and YAML persistence.
- `JobInfo.Spec` remains the single canonical stored jobspec; proposal IDs, revisions, statuses, and active/latest retention are preserved.
- This prevents large executor specs from being duplicated in every catalog env-metadata upload and hitting gRPC message limits.
- The current prod-testnet metadata falls from 4,580,369 to an estimated 2,460,268 bytes (46.3%) after removing proposal spec copies.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `shared.ProposalRevision.Spec` | behavior-changed | `ProposalRevision\b` | `deployment/shared/types.go:38` | [#runtime-only-proposal-specs](#runtime-only-proposal-specs) |
| `shared.JobInfo.Spec` | behavior-changed | `\.Spec\b` | `deployment/shared/types.go:54` | [#canonical-jobspec](#canonical-jobspec) |
| `sequences.ManageJobProposals` | behavior-changed | `ManageJobProposals\b` | `deployment/sequences/manage_job_proposals.go:51` | [#change-detection](#change-detection) |

## Breaking Changes

No Go API changes. Persisted `proposals[*].spec` fields are removed on the next save. Consumers that read historical proposal specs from env metadata must query JD instead; current-state consumers must use `JobInfo.Spec`.

## Migration Guide

1. Replace persisted `job.LatestProposal().Spec` reads with `job.Spec` when using the latest desired jobspec.
2. Fetch active or historical proposal specs from JD with `ListProposals` when required.
3. Run any existing `SaveJob` or `SaveJobs` path to rewrite legacy metadata without proposal spec copies. No separate backfill is needed.

## Runtime-only proposal specs

`ProposalRevision.Spec` remains available in memory for fresh JD responses and drift reports. It is tagged `json:"-" yaml:"-"`, so it is neither uploaded nor read back from persisted metadata. Legacy proposal specs are discarded during metadata decoding and removed from the stored representation on the next save.

## Canonical jobspec

`JobInfo.Spec` continues to hold the latest generated or reconciled jobspec used by executor-state reconstruction and other current-state readers. Proposal pruning still retains only active and latest proposal metadata; JD remains the source of truth for the complete revision history and its specs.

## Change detection

`ManageJobProposals` compares newly generated specs with `existing.Spec`, not `existing.LatestProposal().Spec`. It still requires a latest proposal before treating a job as proposed, preserving no-JD to JD transitions. `SyncJobProposals` compares fresh JD specs with `JobInfo.Spec` before persistence strips the runtime copies.

## Compatibility & Requirements

- No manual metadata migration or catalog message-size increase is required for this representation.
- Applying this change requires updating the CLD `chainlink-ccv/deployment` dependency and running a normal datastore-producing changeset.
- Measurement used the checked-out `domains/ccv/prod_testnet/datastore/env_metadata.json`: 120 jobs and 120 retained proposals, with 1,998,870 bytes of duplicate proposal specs removed. Exact gRPC message sizes can differ because of transport framing and serialization.

## References

- Prior proposal pruning: https://github.com/smartcontractkit/chainlink-ccv/pull/1478
- Original oversized prod-testnet pipeline: https://github.com/smartcontractkit/chainlink-deployments/pull/20955
- Implementation PR: https://github.com/smartcontractkit/chainlink-ccv/pull/1590
