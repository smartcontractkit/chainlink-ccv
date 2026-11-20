# Executor source executor addresses

## Executive Summary

- Executor job specs can carry default executor addresses by source chain independently of destination chain configuration.
- `ApplyExecutorConfig` emits the new field only for selectors explicitly listed in `source_only_chains`; the default empty list retains the prior spec format.
- Standalone and CL-mode executors consume the optional `source_executor_addresses` map while retaining legacy chain-block fallback.
- This allows selected unsupported destination assignments to be removed without dropping source-lane verifier-result filtering or forcing unrelated dormant chains into executor specs.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `executor.Configuration.SourceExecutorAddresses` | added | `SourceExecutorAddresses|source_executor_addresses` | `executor/config.go:86` | [#source-address-configuration](#source-address-configuration) |
| `executor.Configuration.ExecutorAddressesBySourceChain` | added | `ExecutorAddressesBySourceChain\(` | `executor/config.go:215` | [#legacy-fallback-and-validation](#legacy-fallback-and-validation) |
| `changesets.ExecutorPoolInput.SourceOnlyChains` | added | `SourceOnlyChains` | `deployment/changesets/inputs.go:78` | [#opt-in-source-address-generation](#opt-in-source-address-generation) |
| `deployment.ExecutorPoolConfig.SourceOnlyChains` | added | `source_only_chains` | `deployment/topology.go:153` | [#opt-in-source-address-generation](#opt-in-source-address-generation) |
| `changesets.ApplyExecutorConfig` | behavior-changed | `ApplyExecutorConfig\(` | `deployment/changesets/apply_executor_config.go:50` | [#opt-in-source-address-generation](#opt-in-source-address-generation) |

## Breaking Changes

*No breaking changes for existing specs or applies that leave `source_only_chains` empty.*

A spec containing `source_executor_addresses` requires upgraded runtimes on every targeted NOP:

- Standalone executors on v0.22.0 and older reject the unknown TOML key during job validation. JD retains the previous job, but the replacement cannot become active.
- CL nodes with an older chainlink-ccv dependency accept and ignore the key. If the legacy chain block is absent, source-address filtering loses that address and messages from that chain cannot execute from the NOP.

## Migration Guide

1. Leave `source_only_chains` empty for ordinary executor applies; no runtime upgrade is required and the new field is omitted.
2. Before enabling a source-only selector, upgrade every targeted standalone NOP to an executor image containing `source_executor_addresses` support.
3. Upgrade every targeted CL NOP to a Core release whose chainlink-ccv dependency contains the same support. An old CL job becoming active does not prove it supports the field.
4. Set `source_only_chains` and remove the corresponding destination chain configuration in the same apply, after all targeted NOPs support the field.

Only explicitly selected chains emit the field. Dormant deployed chains outside the destination pool do not trigger a spec-format change or runtime-upgrade requirement.

## New Features / Additions

### Source address configuration

`source_executor_addresses` maps canonical decimal source chain selectors to opaque, non-empty hex executor addresses. Entries do not create destination accessors, leader-election pools, balance readers, or chain inspectors.

```toml
[source_executor_addresses]
"1234" = "0x0000000000000000000000000000000000000001"
"5678" = "0x0000000000000000000000000000000000000000000000000000000000000002"
```

### Legacy fallback and validation

`ExecutorAddressesBySourceChain` loads legacy defaults from every `chain_configuration` entry and overlays explicit `source_executor_addresses`. Existing specs need no immediate regeneration.

Validation rejects non-numeric and non-canonical selectors, malformed or empty hex addresses, and conflicting values between the two forms. Matching duplicate values are accepted using decoded-address equality.

### Opt-in source address generation

`ExecutorPoolConfig.SourceOnlyChains` and `ExecutorPoolInput.SourceOnlyChains` select the deployed chains whose addresses are emitted without destination blocks:

```toml
[executor_pools.default]
source_only_chains = ["9268731218649498074"]
```

`ApplyExecutorConfig` rejects duplicate selectors, selectors that also have a destination chain config, and selectors with no deployed executor config. `ExecutorPoolInputFromState` recovers the selector set from source-address entries in persisted jobs.

The implementation uses chain selectors and existing executor adapters only; it contains no chain-family-specific branches.

## Compatibility & Requirements

- **Default behavior:** an empty source-only list produces the previous spec representation and no cosmetic CL job update.
- **Rollout order:** all standalone and CL runtimes that will receive a source-only entry first; opt-in topology and regenerated JD specs second.
- **Address representation:** values remain `protocol.UnknownAddress`; no EVM-length assumption is introduced.
- **Deployment modes:** both standalone and CL-mode constructors use the combined source-address configuration.

## References

- Prior assigned-chain startup behavior: `changelog/2026-11-19_executor_assigned_chain_startup.md`.
