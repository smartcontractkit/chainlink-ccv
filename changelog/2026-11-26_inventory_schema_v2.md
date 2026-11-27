# Clarify verifier jobs and group onchain inventory committees

## Executive Summary

- Inventory schema version 2 stores one copy of each distinct onchain signer set and quorum, with all matching verifier deployments attached.
- This removes repeated member lists without assuming every verifier chain has the same committee.
- Consumers of `inventory.Committee`, inventory JSON, and verifier scopes are affected; Solana and Canton adapters are unchanged.
- Existing schema-v1 snapshots remain readable and are regrouped during the next inventory rebuild.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `inventory.Committee.VerifierChain` / `VerifierAddress` | behavior-changed | `\.VerifierChain\b|\.VerifierAddress\b|verifierChainSelector|verifierAddress` | `deployment/inventory/inventory.go:129` | [#onchain-verifier-locations-are-grouped](#onchain-verifier-locations-are-grouped) |
| `inventory.Committee.VerifierDeployments` | added | `VerifierDeployments|verifierDeployments` | `deployment/inventory/inventory.go:131` | [#onchain-verifier-locations-are-grouped](#onchain-verifier-locations-are-grouped) |
| `inventory.VerifierScope` | added | `\.VerifierScopes\b|verifierScopes` | `deployment/inventory/inventory.go:90` | [#verifier-scope-provenance](#verifier-scope-provenance) |
| `inventory.SchemaVersion` | behavior-changed | `SchemaVersion|schemaVersion` | `deployment/inventory/inventory.go:14` | [#onchain-verifier-locations-are-grouped](#onchain-verifier-locations-are-grouped) |

## Breaking Changes

### Onchain verifier locations are grouped

- **What changed:** normalized onchain `inventory.Committee` rows now use `verifierDeployments` instead of the singular `verifierChainSelector` and `verifierAddress` fields. `inventory.SchemaVersion` is 2.
- **Before:** every verifier contract repeated the full member list, even when the source chain, qualifier, signer set, and quorum were identical.
- **After:** identical configurations share one member list and enumerate every matching `{chainSelector, address}` deployment. Different signer sets, quorums, source chains, qualifiers, or incompatible member attribution remain separate rows.
- **Why:** repetition made the inventory difficult to consume and obscured real per-chain drift.
- **Who is affected:** consumers reading `Committee.VerifierChain` or `Committee.VerifierAddress` from a normalized inventory, or reading those JSON fields from onchain rows. Aggregator rows are unchanged.

Schema-v1 snapshots are still accepted. `ReconcileOnchainCommittees` expands both legacy singular locations and schema-v2 deployment lists before refreshing, so no chain read is required for migration. `ByChain().VerifierSignerSets` and `Rows()` continue to expose per-deployment records.

### Before

```json
{
  "schemaVersion": 1,
  "committees": [
    {
      "source": "onchain",
      "sourceChainSelector": "1",
      "qualifier": "default",
      "verifierChainSelector": "2",
      "verifierAddress": "0x0000000000000000000000000000000000000002",
      "threshold": 2,
      "members": [{"signerAddress": "0xaaa"}, {"signerAddress": "0xbbb"}]
    },
    {
      "source": "onchain",
      "sourceChainSelector": "1",
      "qualifier": "default",
      "verifierChainSelector": "3",
      "verifierAddress": "0x0000000000000000000000000000000000000003",
      "threshold": 2,
      "members": [{"signerAddress": "0xaaa"}, {"signerAddress": "0xbbb"}]
    }
  ]
}
```

### After

```json
{
  "schemaVersion": 2,
  "committees": [
    {
      "source": "onchain",
      "sourceChainSelector": "1",
      "qualifier": "default",
      "verifierDeployments": [
        {"chainSelector": "2", "address": "0x0000000000000000000000000000000000000002"},
        {"chainSelector": "3", "address": "0x0000000000000000000000000000000000000003"}
      ],
      "threshold": 2,
      "members": [{"signerAddress": "0xaaa"}, {"signerAddress": "0xbbb"}]
    }
  ]
}
```

## Migration Guide

1. For normalized onchain rows, replace direct reads of `verifierChainSelector` and `verifierAddress` with iteration over `verifierDeployments`.
2. Do not select one deployment as the source of truth for every chain. A separate row represents a genuinely different signer set or quorum.
3. Keep aggregator rows for offchain/onchain drift comparison; onchain rows are the primary deployed-contract view, not a replacement for the aggregator's own configuration.
4. Rebuild inventory through the normal CCV metadata write or refresh path to migrate saved schema-v1 snapshots.

## New Features / Additions

- **Verifier scope provenance** — every scope now includes `jobId`, optional `jdJobId`, `hasActiveProposal`, optional `activeProposalId`, and optional `latestProposalStatus` alongside its qualifier and source chains. See `deployment/inventory/inventory.go`.
  - These fields describe the last persisted JD proposal sync, not live process health. An empty active proposal is not proof that a verifier process is stopped.
  - Node-resolution behavior is unchanged in this change. Active-only resolution requires a fresh JD lifecycle sync and is intentionally not inferred from stale saved records.

## Compatibility & Requirements

- No Solana or Canton adapter changes are required. Grouping and scope metadata are implemented in CCV's chain-agnostic inventory package.
- No dependency changes are required.
