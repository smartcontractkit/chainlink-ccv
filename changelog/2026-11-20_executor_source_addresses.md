# Executor source executor addresses

## Executive Summary

- Executor job specs can carry default executor addresses by source chain independently of destination chain configuration.
- `ApplyExecutorConfig` emits the new field only for deployed chains absent from the destination pool; other pools retain the prior spec format.
- Standalone and CL-mode executors consume the optional `source_executor_addresses` map while retaining legacy chain-block fallback.
- This allows unsupported destination assignments to be removed without dropping source-lane verifier-result filtering.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `executor.Configuration.SourceExecutorAddresses` | added | `SourceExecutorAddresses|source_executor_addresses` | `executor/config.go:86` | [#source-address-configuration](#source-address-configuration) |
| `executor.Configuration.ExecutorAddressesBySourceChain` | added | `ExecutorAddressesBySourceChain\(` | `executor/config.go:211` | [#legacy-fallback-and-validation](#legacy-fallback-and-validation) |
| `changesets.ApplyExecutorConfig` | behavior-changed | `ApplyExecutorConfig\(` | `deployment/changesets/apply_executor_config.go:50` | [#source-address-generation](#source-address-generation) |

## Breaking Changes

*No breaking changes for existing specs or regenerated pools without source-only chains.*

A spec containing `source_executor_addresses` requires upgraded runtimes on every targeted NOP:

- Standalone executors on v0.22.0 and older reject the unknown TOML key during job validation. JD retains the previous job, but the replacement cannot become active.
- CL nodes with an older chainlink-ccv dependency accept and ignore the key. If the legacy chain block is absent, source-address filtering loses that address and messages from that chain cannot execute from the NOP.

## Migration Guide

1. Before removing a destination from a pool, upgrade every targeted standalone NOP to an executor image containing `source_executor_addresses` support.
2. Upgrade every targeted CL NOP to a Core release whose chainlink-ccv dependency contains the same support. An old CL job becoming active does not prove it supports the field.
3. Upgrade the deployment module and apply the topology and executor-spec changes together with `ApplyExecutorConfig`.

Pools without source-only chains omit the field and require no runtime upgrade. Existing jobs using only legacy chain blocks remain compatible with the new runtime.

## New Features / Additions

### Source address configuration

`source_executor_addresses` maps decimal source chain selectors to opaque, non-empty hex executor addresses. Entries do not create destination accessors, leader-election pools, balance readers, or chain inspectors.

```toml
[source_executor_addresses]
"1234" = "0x0000000000000000000000000000000000000001"
"5678" = "0x0000000000000000000000000000000000000000000000000000000000000002"
```

### Legacy fallback and validation

`ExecutorAddressesBySourceChain` loads legacy defaults from every `chain_configuration` entry and overlays explicit `source_executor_addresses`. Existing specs need no immediate regeneration.

Validation rejects non-numeric selectors, malformed or empty hex addresses, and conflicting values between the two forms. Matching duplicate values are accepted using decoded-address equality.

### Source address generation

`ApplyExecutorConfig` derives the map only from adapter-built executor chains absent from the destination pool. An empty map is omitted, so pools without source-only chains retain the previous spec representation and CL NOPs receive no cosmetic job change.

The implementation uses chain selectors and existing executor adapters only; it contains no chain-family-specific branches.

## Compatibility & Requirements

- **Rollout order:** all standalone and CL runtimes that will receive a source-only entry first; deployment changeset and regenerated JD specs second.
- **Address representation:** values remain `protocol.UnknownAddress`; no EVM-length assumption is introduced.
- **Deployment modes:** both standalone and CL-mode constructors use the combined source-address configuration.

## References

- Prior assigned-chain startup behavior: `changelog/2026-11-19_executor_assigned_chain_startup.md`.
