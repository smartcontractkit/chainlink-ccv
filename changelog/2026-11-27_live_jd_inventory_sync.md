# Synchronize live JD state during inventory-producing changesets

## Executive Summary

- `RefreshInventory` now refreshes JD nodes and every saved job's proposals before reading onchain committees.
- Ordinary offchain changesets synchronize all saved JD jobs in the same datastore output, including jobs they did not modify.
- This prevents stale `pending` proposal statuses when NOPs have already approved or rejected a revision in JD.
- `RefreshInventory` now requires a JD client; no-JD local behavior for ordinary operations that already supported it is unchanged.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `changesets.RefreshInventory` | behavior-changed | `RefreshInventory\(` | `deployment/changesets/refresh_inventory.go:17` | [#refreshinventory-requires-live-jd](#refreshinventory-requires-live-jd) |
| `sequences.ManageJobProposals` | behavior-changed | `ManageJobProposals\b` | `deployment/sequences/manage_job_proposals.go:55` | [#normal-offchain-operations](#normal-offchain-operations) |
| `sync_job_proposals.SyncDatastore` | added | `SyncDatastore\(` | `deployment/operations/sync_job_proposals/sync_job_proposals.go:64` | [#shared-live-jd-sync](#shared-live-jd-sync) |

## Breaking Changes

### RefreshInventory requires live JD

- **What changed:** `RefreshInventory` rejects an environment without `e.Offchain` during precondition validation.
- **Before:** the changeset used the persisted JD node and job snapshot while reading only live chain state.
- **After:** the changeset first synchronizes JD nodes and all saved job proposals, then reads committees and publishes one datastore output.
- **Why:** saved proposal statuses can be stale after NOP approval or rejection, and a separate reconciliation run is easy to omit.
- **Who is affected:** callers registering `RefreshInventory` with `changeset.WithoutJD()` or invoking it in an environment without JD.

## Migration Guide

Remove `WithoutJD()` from the CCV refresh registration so the environment supplies JD and its node IDs.

```go
// Before
registry.Add("refresh-inventory",
    changeset.Configure(ccvchangesets.RefreshInventory()).WithEnvInput(),
    changeset.WithoutJD())
```

```go
// After
registry.Add("refresh-inventory",
    changeset.Configure(ccvchangesets.RefreshInventory()).WithEnvInput())
```

No Solana or Canton adapter changes are required. Other ordinary offchain registrations need no migration; they synchronize automatically when JD is available.

## New Features / Additions

### Shared live JD sync

- `sync_job_proposals.SyncDatastore` runs the existing full JD synchronization operation against a cloned datastore.
- It returns an error instead of publishing partial results when any proposal read fails.
- A nil JD client returns the input datastore unchanged for ordinary operations that support no-JD local development.

### Normal offchain operations

- `ManageJobProposals` synchronizes every saved job before proposing or revoking jobs, so an unrelated read failure cannot strand a JD mutation without its datastore output.
- Aggregator, indexer, and token-verifier generation synchronize JD when available.
- Increase/decrease-threshold operations synchronize JD in their final output; remove-NOP synchronizes before revoking jobs.
- The sync unions the freshly fetched JD roster with the legacy node allowlist and saves all updated jobs in one batch.
- Existing behavior already rebuilds the chain-agnostic inventory on every CCV metadata write, so the refreshed job state is reflected without a separate reconcile step.

`latestProposalStatus` remains the highest revision's status. `hasActiveProposal` independently records whether an approved revision exists, so an older approved revision and a newer pending revision can coexist.

## Compatibility & Requirements

- The proposal sync unions `e.NodeIDs` with the freshly fetched JD roster, so native registrations do not require a legacy `nodes.json` update.
- No dependency or chain-adapter changes are required.
