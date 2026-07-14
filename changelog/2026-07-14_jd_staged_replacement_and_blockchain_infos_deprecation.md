# Staged JD replacements and remaining `ConfigWithBlockchainInfo*` deprecations

## Executive Summary

- JD replacements now prepare the incoming job's parsed spec, chain-family local configuration,
  and registry resources before stopping the active job.
- The actual service cutover remains single-active: the old job is stopped before the prepared job
  is activated, avoiding duplicate processing and fixed-port conflicts.
- The remaining executor and token-verifier `*WithBlockchainInfo*` APIs are deprecated; app config
  now derives its chain set from app-owned address/config maps while RPC data stays operator-local.
- There are no new compile-time breaks for Solana, Canton, custom `JobRunner` implementations, or
  custom `AccessorFactory` implementations.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `lifecycle.Manager` replacement flow | behavior-changed | `bootstrap\.Run\(|NewManager\(` | `common/jd/lifecycle/manager.go:300` | [JD replacement cutover](#jd-replacement-cutover) |
| `chainaccess.AccessorFactory` optional cleanup | behavior-changed | `AccessorFactory\b|chainaccess\.Register\(` | `pkg/chainaccess/interfaces.go:104` | [Chain factory cleanup](#chain-factory-cleanup) |
| Token-verifier chain enumeration | behavior-changed | `blockchain_infos|OnRampAddresses` | `cmd/verifier/token/main.go:85` | [`blockchain_infos` config migration](#blockchain_infos-config-migration) |
| `executor.ConfigWithBlockchainInfo` | deprecated | `\bConfigWithBlockchainInfo\b` | `executor/config.go:30` | [`blockchain_infos` config migration](#blockchain_infos-config-migration) |
| `executor.LoadConfigWithBlockchainInfos` | deprecated | `\bLoadConfigWithBlockchainInfos\b` | `executor/load.go:28` | [`blockchain_infos` config migration](#blockchain_infos-config-migration) |
| `token.ConfigWithBlockchainInfos` | deprecated | `\bConfigWithBlockchainInfos\b` | `verifier/pkg/token/config.go:17` | [`blockchain_infos` config migration](#blockchain_infos-config-migration) |
| `services.TokenVerifierInput.GenerateConfigWithBlockchainInfos` | deprecated | `\.GenerateConfigWithBlockchainInfos\(` | `build/devenv/services/tokenVerifier.go:324` | [`blockchain_infos` config migration](#blockchain_infos-config-migration) |
| `verifier.LoadBlockchainInfo` | deprecated | `\bLoadBlockchainInfo\b` | `cmd/verifier/common.go:121` | [`blockchain_infos` config migration](#blockchain_infos-config-migration) |
| `lifecycle.StagedJobRunner` | added | `\bStagedJobRunner\b` | `common/jd/lifecycle/manager.go:67` | [JD replacement cutover](#jd-replacement-cutover) |
| `bootstrap.AccessorCloserRegistry.Close` | added | `AccessorCloserRegistry|\.Close\(` | `bootstrap/accessor_closer_registry.go:60` | [Chain factory cleanup](#chain-factory-cleanup) |
| `services.TokenVerifierInput.GenerateConfig` | added | `\.GenerateConfig\(` | `build/devenv/services/tokenVerifier.go:308` | [`blockchain_infos` config migration](#blockchain_infos-config-migration) |

## Breaking Changes

*No breaking changes.*

`lifecycle.JobRunner`, `bootstrap.ServiceFactory`, `chainaccess.Registry`, and
`chainaccess.AccessorFactory` retain their existing method sets. Deprecated config wrappers remain
available for source compatibility, and `bootstrap.JobSpec.GetAppConfig` continues to ignore a
legacy `blockchain_infos` table while downstream specs migrate.

## Migration Guide

1. Search for every deprecated symbol in the AI Adapter Index.
2. Decode the application config directly instead of wrapping it in a
   `ConfigWithBlockchainInfo*` type.
3. Derive source-chain selectors from `OnRampAddresses`; derive executor destination selectors
   from `Configuration.ChainConfiguration`.
4. Keep RPC URLs, chain IDs, and chain-family tuning in standalone local config or CL node config.
5. Replace token-verifier devenv calls to `GenerateConfigWithBlockchainInfos(infos)` with
   `GenerateConfig()`. Continue mounting the separate chain-family local config.
6. Custom lifecycle runners and chain factories require no changes. They may opt into the new
   preparation and cleanup hooks described below.

Executor config decoding:

```go
// Before
var wrapped executor.ConfigWithBlockchainInfo[MyChainInfo]
if err := spec.GetAppConfig(&wrapped); err != nil {
    return err
}
cfg, err := wrapped.Configuration.GetNormalizedConfig()
```

```go
// After
var raw executor.Configuration
if err := spec.GetAppConfig(&raw); err != nil {
    return err
}
cfg, err := raw.GetNormalizedConfig()
```

Token-verifier chain enumeration:

```go
// Before
var wrapped token.ConfigWithBlockchainInfos
_ = spec.GetAppConfig(&wrapped)
selectors := wrapped.BlockchainInfos.GetAllChainSelectors()
```

```go
// After
var cfg token.Config
_ = spec.GetAppConfig(&cfg)
selectors := chainaccess.Infos[string](cfg.OnRampAddresses).GetAllChainSelectors()
```

## JD replacement cutover

`lifecycle.StagedJobRunner` is an optional extension to `lifecycle.JobRunner`:

```go
type StagedJobRunner interface {
    JobRunner
    PrepareJob(ctx context.Context, spec string) error
    DiscardPreparedJob(ctx context.Context) error
}
```

For implementations of this interface, replacement order is now:

1. Persist the proposed job as pending.
2. `PrepareJob(newSpec)` while the old job remains active and ready.
3. `StopJob()` for the old job.
4. `StartJob(newSpec)`, which activates the prepared candidate.
5. Accept the pending row and approve the proposal with JD.

Preparation must not begin externally visible job processing or change readiness. If preparation
fails, the candidate and pending row are discarded and the old job is not stopped. If activation
fails after cutover, the existing old-job restart fallback still runs. Implementations that satisfy
only `JobRunner` retain the prior stop-then-start sequence.

The bootstrap runner implements the staged extension automatically. It parses the outer job spec
and constructs the chain registry before cutover, including family-local config loading and any
constructor-time RPC initialization. It does not start a second verifier/executor service: the
factories are single-instance and services may own fixed ports or perform non-idempotent work.

## Chain factory cleanup

The `chainaccess.AccessorFactory` interface is unchanged. A factory that owns constructor-time
resources may optionally also implement:

```go
Close() error
```

The concrete registry detects and invokes this method during terminal cleanup. Partial registry
construction is also cleaned up when a later family constructor fails. The EVM factory implements
the hook to close prepared or active RPC clients and head trackers. Accessor-level cleanup still
runs first.

Solana and Canton do not need a compatibility edit: their existing `AccessorFactory` implementations
still compile, and their constructor paths do not require this optional method. A downstream family
should add it only if its factory itself owns resources that are not already owned and closed by the
returned accessors.

## `blockchain_infos` config migration

The remaining wrappers were compatibility artifacts, not separate configuration authorities.
Application-owned addresses and behavior remain in the typed app config; connection credentials,
RPC endpoints, chain IDs, and chain-specific tuning remain in operator-local or CL node config.

These deprecations apply to CCV's job/app-config wrapper APIs and to shipping `blockchain_infos`
inside a JD job spec. A chain family may still use a similarly named field in its operator-local
configuration. In particular, Canton's local `ccip.Config.BlockchainInfos` is a separate config
surface and is not deprecated by this change.

The token verifier now decodes `token.Config` directly and enumerates source chains through
`Config.OnRampAddresses`. `TokenVerifierInput.GenerateConfig` serializes only that application
config. Its deprecated `GenerateConfigWithBlockchainInfos` wrapper remains callable and preserves
its legacy connection-free `blockchain_infos` output for compatibility, but internal devenv paths
no longer call it.

The executor now decodes `executor.Configuration` directly in its service factory. The deprecated
generic wrapper and loader remain callable for legacy consumers, but new code should use
`bootstrap.JobSpec.GetAppConfig` followed by `Configuration.GetNormalizedConfig`.

## New Features / Additions

- **Optional staged JD preparation** — custom runners may implement `lifecycle.StagedJobRunner` to
  move safe setup work ahead of the replacement outage window.
- **Terminal registry cleanup** — `bootstrap.AccessorCloserRegistry.Close` closes tracked accessors
  and forwards optional registry/factory cleanup exactly once.
- **Token app-only generation** — `TokenVerifierInput.GenerateConfig` emits no
  `blockchain_infos` table.

## Deprecations

- **`executor.ConfigWithBlockchainInfo`** — use `executor.Configuration`. Removal is not yet scheduled.
- **`executor.LoadConfigWithBlockchainInfos`** — use `JobSpec.GetAppConfig` plus
  `Configuration.GetNormalizedConfig`. Removal is not yet scheduled.
- **`token.ConfigWithBlockchainInfos`** — use `token.Config`. Removal is not yet scheduled.
- **`TokenVerifierInput.GenerateConfigWithBlockchainInfos`** — use `GenerateConfig`. Removal is not
  yet scheduled.
- **`verifier.LoadBlockchainInfo`** — derive selectors from app-owned address/config maps. Removal is
  not yet scheduled.

## Compatibility & Requirements

- Go remains at 1.26.2; there are no dependency-version changes.
- Existing custom `JobRunner`, `Registry`, `AccessorFactory`, and `ServiceFactory` implementations
  remain source compatible.
- Solana and Canton use `bootstrap.Run` and therefore receive staged replacement behavior without
  implementing a new interface. Their current sources contain no uses of the deprecated config
  wrappers listed above.
- Canton continues loading connection data from its operator-local config; its local
  `ccip.Config.BlockchainInfos` field is outside the job/app-config deprecation.
- EVM replacements may briefly hold old and prepared RPC clients simultaneously. Operators should
  account for that short overlap in RPC connection limits.
- Consumers upgrading across earlier bootstrap changes must also follow
  `2026-07-13_bootstrap_prune_functional_options.md`; that migration is independent of this change.

## References

- Prior change: [use config instead of blockchain info (#1267)](https://github.com/smartcontractkit/chainlink-ccv/pull/1267)
- Prior changelog: `2026-07-13_bootstrap_prune_functional_options.md`
