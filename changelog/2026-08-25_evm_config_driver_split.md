# Split EVM config off the EVM accessor driver so non-EVM binaries stop registering it

## Executive Summary

- The operator-facing EVM config types, loader, and Chainlink-node converter move out of
  `integration/pkg/accessors/evm` into a new package `integration/pkg/accessors/evmconfig` that
  registers no accessor factory.
- This fixes a boot failure introduced by `ccv migrate inspect-config` (#1369): that command made
  `cli/migrate` import the EVM accessor package, and `cmd/verifier` imports `cli/migrate`, so every
  binary built on `cmd/verifier` — including a downstream Solana verifier — ran the EVM driver's
  `init()` and registered the EVM factory. `chainaccess.NewRegistry` constructs every registered
  factory eagerly, and `CreateEVMAccessorFactory` fails when no EVM config is mounted, so a Solana
  verifier died at `bootstrap.Run` / `StartJob` with `failed to construct accessor factory for
  family evm`.
- `evm.Config`, `evm.ChainConfig`, `evm.Node`, `evm.Info`, `evm.Conversion`,
  `evm.NewConfigFromInfos`, `evm.EVMConfigPathEnv`, and `evm.DefaultEVMConfigPath` keep working as
  aliases, so devenv, configdoc, and accessor callers need no change. Only the three migration-only
  symbols added in #1369 move without an alias.
- Consumers that run no EVM chains must import `evmconfig`, never `accessors/evm`: importing the
  accessor package is still the opt-in that registers the EVM family.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `evm.LoadConfigFile → evmconfig.LoadConfigFile` | renamed | `\bLoadConfigFile\(` | `integration/pkg/accessors/evmconfig/load.go:31` | [Migration Guide](#migration-guide) |
| `evm.EffectiveChainConfigs → evmconfig.EffectiveChainConfigs` | renamed | `\bEffectiveChainConfigs\(` | `integration/pkg/accessors/evmconfig/effective_config.go:40` | [Migration Guide](#migration-guide) |
| `evm.EffectiveChain → evmconfig.EffectiveChain` | renamed | `\bEffectiveChain\b` | `integration/pkg/accessors/evmconfig/effective_config.go:15` | [Migration Guide](#migration-guide) |
| `evm.EffectiveNode → evmconfig.EffectiveNode` | renamed | `\bEffectiveNode\b` | `integration/pkg/accessors/evmconfig/effective_config.go:31` | [Migration Guide](#migration-guide) |
| `accessors/evm` package import | behavior-changed | `accessors/evm"` | `integration/pkg/accessors/evm/factory_constructor.go:20` | [Importing the accessor package is the EVM opt-in](#importing-the-accessor-package-is-the-evm-opt-in) |
| `evm.Config` / `ChainConfig` / `Node` / `Info` / `Conversion` | behavior-changed | `\bevm\.(Config|ChainConfig|Node|Info|Conversion)\b` | `integration/pkg/accessors/evm/config.go:11` | [Type aliases keep the accessor API spelling](#type-aliases-keep-the-accessor-api-spelling) |
| `evmconfig.BuildChainlinkEVMTOML` | added | `BuildChainlinkEVMTOML` | `integration/pkg/accessors/evmconfig/chainlink_config.go:28` | [New exported config surface](#new-exported-config-surface) |
| `evmconfig.ResolveConfigPath` | added | `ResolveConfigPath\(` | `integration/pkg/accessors/evmconfig/load.go:89` | [New exported config surface](#new-exported-config-surface) |
| `evmconfig.Config.ToInfos` | added | `\.ToInfos\(` | `integration/pkg/accessors/evmconfig/load.go:99` | [New exported config surface](#new-exported-config-surface) |
| `evmconfig.DefaultTXMBlockTime` | added | `DefaultTXMBlockTime` | `integration/pkg/accessors/evmconfig/chainlink_config.go:18` | [New exported config surface](#new-exported-config-surface) |
| `evmconfig.DefaultNewHeadsPollInterval` | added | `DefaultNewHeadsPollInterval` | `integration/pkg/accessors/evmconfig/chainlink_config.go:21` | [New exported config surface](#new-exported-config-surface) |

## Breaking Changes

### Migration-only symbols move to `evmconfig`

- **What changed:** `LoadConfigFile`, `EffectiveChainConfigs`, `EffectiveChain`, and `EffectiveNode`
  are no longer in `integration/pkg/accessors/evm`. They are in
  `integration/pkg/accessors/evmconfig` under the same names.
- **Before:** `evm.LoadConfigFile(path)`, `evm.EffectiveChainConfigs(cfg)`,
  `map[string]evm.EffectiveChain`.
- **After:** `evmconfig.LoadConfigFile(path)`, `evmconfig.EffectiveChainConfigs(cfg)`,
  `map[string]evmconfig.EffectiveChain`.
- **Why:** these four exist only for `ccv migrate inspect-config`. Leaving them in the accessor
  package is what dragged the EVM driver's `init()` into every binary that links the CCV CLI.
  Unlike the config types, they are one day old and have no external callers, so they moved without
  an alias rather than widening the accessor's API permanently.
- **Who is affected:** anything calling those four symbols. In this repo that is only
  `cli/migrate/inspect_config.go`.

### `evm` package's internal alias for `chainlink-evm/pkg/config` renamed

- **What changed:** inside `integration/pkg/accessors/evm`, the import alias `evmconfig` for
  `github.com/smartcontractkit/chainlink-evm/pkg/config` is now `clevmconfig`, freeing `evmconfig`
  for the new CCV package.
- **Who is affected:** nobody outside the package; import aliases are file-local. Listed because a
  downstream repo that copied these files will hit the same collision.

## Migration Guide

1. If you only read, convert, or report on EVM config — and do not run EVM chains — import
   `integration/pkg/accessors/evmconfig` instead of `integration/pkg/accessors/evm`.
2. Rewrite the four moved symbols to the `evmconfig` package qualifier.
3. Leave `evm.Config`, `evm.Info`, `evm.Node`, `evm.ChainConfig`, `evm.Conversion`,
   `evm.NewConfigFromInfos`, `evm.EVMConfigPathEnv`, and `evm.DefaultEVMConfigPath` alone — they
   still resolve, through aliases.

```go
// Before
import "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"

cfg, conversion, err := evm.LoadConfigFile(path)
chains, err := evm.EffectiveChainConfigs(*cfg) // map[string]evm.EffectiveChain
```

```go
// After
import "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evmconfig"

cfg, conversion, err := evmconfig.LoadConfigFile(path)
chains, err := evmconfig.EffectiveChainConfigs(*cfg) // map[string]evmconfig.EffectiveChain
```

## Behavior Changes

### Importing the accessor package is the EVM opt-in

`integration/pkg/accessors/evm` still registers the EVM family in `init()`
(`factory_constructor.go:20`), and the three EVM binaries still opt in by blank-importing it:

```go
_ "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm" // evm accessor driver
```

What changed is who else reaches that import. `cli/migrate` — and therefore `cmd/verifier`, which
wires the `ccv` CLI — no longer does. A binary built on `cmd/verifier` that runs no EVM chains now
registers no EVM factory, so `chainaccess.NewRegistry` no longer tries to construct one and no
longer needs an EVM config file mounted.

Verify with:

```
go list -deps ./cmd/verifier | grep 'accessors/evm$'   # no output
```

`chainaccess.NewRegistry` is unchanged: it still constructs every registered factory eagerly and
still fails the whole registry when one constructor errors. That fail-fast behavior is wanted for a
binary that genuinely runs EVM chains, so the fix is on the import side only.

### Type aliases keep the accessor API spelling

`integration/pkg/accessors/evm/config.go` re-exports the config types the accessor's callers already
use:

```go
type (
	Config      = evmconfig.Config
	ChainConfig = evmconfig.ChainConfig
	Node        = evmconfig.Node
	Info        = evmconfig.Info
	Conversion  = evmconfig.Conversion
)
```

These are Go type aliases, not new types, so `evm.Info` and `evmconfig.Info` are the same type and
values pass between the two packages freely. `build/devenv/evm/chainconfig`,
`build/devenv/services/tokenVerifier.go`, and `tools/configdoc/registry` compile unchanged.

## New Features / Additions

- **`integration/pkg/accessors/evmconfig`** — the operator-facing EVM config surface with no driver
  registration and no chainlink-evm runtime dependency (no `txm`, `logpoller`, `gas`, or `client`).
  - Usage: import this from tooling, config generators, and non-EVM services. Import
    `accessors/evm` only from a binary that actually runs EVM chains.
- Four symbols that were unexported become part of that package's API because the split put their
  callers on the other side of a package boundary: `BuildChainlinkEVMTOML` (was
  `buildChainlinkEVMTOML`, called by the accessor's `newChainlinkEVMConfig`), `ResolveConfigPath`
  and `Config.ToInfos` (called by `CreateEVMAccessorFactory`), and the `DefaultTXMBlockTime` /
  `DefaultNewHeadsPollInterval` constants.

## References

- Prior changelog entries this builds on: `2026-08-20_migration_tooling.md` (added
  `ccv migrate inspect-config`), `2026-04-14_accessor_registry.md` (the blank-import driver pattern)
