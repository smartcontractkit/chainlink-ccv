# Executor source executor addresses

## Executive Summary

- Executor job specs can carry default executor addresses by source chain independently of destination chain configuration.
- `ApplyExecutorConfig` emits addresses for every deployed executor chain, including chains absent from the destination pool.
- Standalone and CL-mode executors consume the optional `source_executor_addresses` map while retaining legacy chain-block fallback.
- This allows unsupported destination assignments to be removed without dropping source-lane verifier-result filtering.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `executor.Configuration.SourceExecutorAddresses` | added | `SourceExecutorAddresses|source_executor_addresses` | `executor/config.go:83` | [#source-address-configuration](#source-address-configuration) |
| `executor.Configuration.ExecutorAddressesBySourceChain` | added | `ExecutorAddressesBySourceChain\(` | `executor/config.go:195` | [#legacy-fallback-and-precedence](#legacy-fallback-and-precedence) |
| `changesets.ApplyExecutorConfig` | behavior-changed | `ApplyExecutorConfig\(` | `deployment/changesets/apply_executor_config.go:50` | [#source-address-generation](#source-address-generation) |

## Breaking Changes

*No breaking changes.*

## Migration Guide

1. Deploy an executor image containing `source_executor_addresses` support before publishing source-only job specs.
2. Upgrade the deployment module and regenerate executor jobs with `ApplyExecutorConfig`.
3. After the new jobs are active, unsupported destination-pool entries may be removed without removing their source executor addresses.

Old executor binaries still require the legacy `chain_configuration.default_executor_address` entries for source-chain filtering.

## New Features / Additions

### Source address configuration

`source_executor_addresses` maps decimal source chain selectors to opaque hex-encoded executor addresses. Entries do not create destination accessors, leader-election pools, balance readers, or chain inspectors.

```toml
[source_executor_addresses]
"1234" = "0x0000000000000000000000000000000000000001"
"5678" = "0x0000000000000000000000000000000000000000000000000000000000000002"
```

### Legacy fallback and precedence

`ExecutorAddressesBySourceChain` loads legacy defaults from every `chain_configuration` entry and overlays explicit `source_executor_addresses`. Existing specs therefore need no immediate regeneration, and explicit entries take precedence when both forms are present.

### Source address generation

`ApplyExecutorConfig` derives the map from all adapter-built executor chain configurations before destination-pool filtering. The implementation uses chain selectors and existing executor adapters only; it contains no chain-family-specific branches.

## Compatibility & Requirements

- **Rollout order:** executor runtime first, deployment changeset and regenerated JD specs second.
- **Address representation:** values remain `protocol.UnknownAddress`; no EVM-length assumption is introduced.
- **Deployment modes:** both standalone and CL-mode constructors use the combined source-address configuration.

## References

- Prior assigned-chain startup behavior: `changelog/2026-11-19_executor_assigned_chain_startup.md`.
