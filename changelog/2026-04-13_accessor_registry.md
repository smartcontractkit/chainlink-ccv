# Human Overview

This document outlines changes related to the `chainaccess.Registry` adopted in the following PRs:
https://github.com/smartcontractkit/chainlink-ccv/pull/1002
https://github.com/smartcontractkit/chainlink-ccv/pull/1007
https://github.com/smartcontractkit/chainlink-ccv/pull/1005

The primary purpose is to completely separate family specific accessor implementations from bootstrap applications by adopting a Registry + Driver style abstraction. Additional changes are planned, but they are much smaller and should be significantly easier to adopt than the initial set of changes outlined here.

The following is a detailed outline for how to adopt the new pattern written by AI. It did a good job.

# Adopting `chainaccess.Register` in Bootstrap Applications

> **Scope of this guide**: PRs #1002 (`chainaccess.Register` registry), #1005 (registry integrated into bootstrap), and #1007 (`bootstrap.JobSpec` as standard config envelope).

---

## Table of Contents

1. [Background and motivation](#1-background-and-motivation)
2. [Architecture overview](#2-architecture-overview)
3. [The three building blocks](#3-the-three-building-blocks)
   - [3.1 `chainaccess.Register` — family auto-registration](#31-chainaccessregister--family-auto-registration)
   - [3.2 `bootstrap.JobSpec` — standard JD config envelope](#32-bootstrapjobspec--standard-jd-config-envelope)
   - [3.3 `chainaccess.NewRegistry` — runtime factory dispatch](#33-chainaccessnewregistry--runtime-factory-dispatch)
4. [Config TOML structure](#4-config-toml-structure)
5. [Step-by-step migration guide](#5-step-by-step-migration-guide)
   - [5.1 Add the blank import](#51-add-the-blank-import)
   - [5.2 Swap the `ServiceFactory` type parameter to `bootstrap.JobSpec`](#52-swap-the-servicefactory-type-parameter-to-bootstrapjobspec)
   - [5.3 Replace `createAccessorFactoryFunc` with `chainaccess.NewRegistry`](#53-replace-createaccessorfactoryfunc-with-chainaccessnewregistry)
   - [5.4 Remove chain-family filtering boilerplate](#54-remove-chain-family-filtering-boilerplate)
   - [5.5 Update `main.go`](#55-update-maingo)
6. [Complete before / after example](#6-complete-before--after-example)
7. [Adding a new non-EVM chain family](#7-adding-a-new-non-evm-chain-family)
8. [Running without JD (`WithTOMLAppConfig`)](#8-running-without-jd-withtomlappconfig)
9. [Deprecated APIs and replacements](#9-deprecated-apis-and-replacements)
10. [FAQ](#10-faq)

---

## 1. Background and motivation

Before these PRs each bootstrap application had to:

* Pick a concrete chain-config type `T` (e.g. `evm.Info`) at compile time.
* Pass a function matching `CreateAccessorFactoryFunc[T]` through several layers of constructors.
* Manually filter chains by `chainFamily` string inside `Start()`.
* Duplicate `LoadConfigWithBlockchainInfos[T]` calls that differed only in the type parameter.

This created friction when adding a second chain family, made the `ServiceFactory` generic for a reason that leaked into user code, and forced callers to hard-code which chain packages they needed.

The new pattern moves family wiring to package `init()` functions and lets applications call a single `chainaccess.NewRegistry` call that dispatches to every registered family automatically.

---

## 2. Architecture overview

```
┌───────────────────────────────────────────────────────────────────┐
│  Binary                                                            │
│                                                                    │
│  import _ ".../integration/pkg/accessors/evm"  ← side-effect     │
│       └─ init() calls chainaccess.Register("EVM", constructor)    │
│                                                                    │
│  main()                                                            │
│    └─ bootstrap.Run("MyService", myFactory)                       │
│         └─ JD pushes JobSpec TOML                                 │
│              └─ runner parses TOML → bootstrap.JobSpec            │
│                   └─ myFactory.Start(ctx, spec, deps)             │
│                        └─ chainaccess.NewRegistry(lggr,           │
│                                spec.AppConfig)                    │
│                             ├─ calls "EVM" constructor            │
│                             └─ returns Registry (AccessorFactory) │
│                                  └─ .GetAccessor(ctx, selector)  │
│                                       └─ Accessor.SourceReader()  │
└───────────────────────────────────────────────────────────────────┘
```

Key properties:

| Property | Old pattern | New pattern |
|---|---|---|
| Family wiring | Explicit constructor arg | `init()` side-effect import |
| Generic type param on factory | `factory[T any]` | No generic param needed |
| Family filtering in `Start()` | Manual `if family != f.chainFamily` | None — Registry handles it |
| Adding a second family | Change generic param + wiring | Add one more blank import |

---

## 3. The three building blocks

### 3.1 `chainaccess.Register` — family auto-registration

```go
// pkg/chainaccess/registry.go

// AccessorFactoryConstructor creates an AccessorFactory for a specific chain family.
// cfg is the full application config TOML string (the same string the service receives).
type AccessorFactoryConstructor func(lggr logger.Logger, cfg string) (AccessorFactory, error)

// Register stores a constructor under a family name.
// Panics on duplicate registration (prevents silent mis-configuration).
func Register(name ChainFamily, constructor AccessorFactoryConstructor)
```

EVM does this in `integration/pkg/accessors/evm/factory_constructor.go`:

```go
func init() {
    chainaccess.Register(chainsel.FamilyEVM, CreateEVMAccessorFactory)
}
```

**`CreateEVMAccessorFactory`** parses `cfg` as `chainaccess.GenericConfig` (TOML), iterates the `blockchain_infos` selectors, builds an EVM multi-node client and head tracker for each, and returns an `AccessorFactory`.

No code outside the EVM package needs to change when the EVM family is updated.

### 3.2 `bootstrap.JobSpec` — standard JD config envelope

```go
// bootstrap/job.go

// JobSpec is the specification for a bootstrap service job, pushed by JD.
type JobSpec struct {
    Name          string `toml:"name"`
    ExternalJobID string `toml:"externalJobID"`
    SchemaVersion int    `toml:"schemaVersion"`
    Type          string `toml:"type"`
    // AppConfig holds the inner application config as a TOML string.
    AppConfig     string `toml:"appConfig"`
}
```

When JD pushes a job proposal the bootstrap `runner` decodes the full TOML into `bootstrap.JobSpec` and calls `fac.Start(ctx, spec, deps)`.  
The service then reads `spec.AppConfig` — which is the raw inner config TOML — to parse its own settings and pass to `chainaccess.NewRegistry`.

**This means services should use `bootstrap.ServiceFactory[bootstrap.JobSpec]`** as their factory type, not a custom app-config struct.

### 3.3 `chainaccess.NewRegistry` — runtime factory dispatch

```go
// pkg/chainaccess/registry.go

// NewRegistry calls every registered AccessorFactoryConstructor with cfg,
// stores the resulting AccessorFactory keyed by family, and returns a
// Registry that implements AccessorFactory.
func NewRegistry(lggr logger.Logger, config string) (AccessorFactory, error)

// GetAccessor looks up the chain family for chainSelector, finds the right
// factory, and returns a ready-to-use Accessor.
func (r *Registry) GetAccessor(ctx context.Context, chainSelector protocol.ChainSelector) (Accessor, error)
```

The service calls this **once per job start** and then calls `GetAccessor` for each chain selector it wants to read.  
The `Registry` automatically routes EVM selectors to the EVM factory, Stellar selectors to the Stellar factory, and so on.

---

## 4. Config TOML structure

### 4.1 Full shape expected by `GenericConfig`

`chainaccess.NewRegistry` decodes the config string into `chainaccess.GenericConfig`:

```toml
# ── Shared addresses used by every SourceReader ──────────────────────────────

[on_ramp_addresses]
# key = chain-selector string, value = contract address hex
"5009297550715157269" = "0xOnRampAddressOnEthereumMainnet"
"4051577828743386545" = "0xOnRampAddressOnArbitrumMainnet"

[rmn_remote_addresses]
"5009297550715157269" = "0xRMNRemoteOnEthereumMainnet"
"4051577828743386545" = "0xRMNRemoteOnArbitrumMainnet"

# ── Per-chain connection info (EVM-specific fields shown) ─────────────────────

[blockchain_infos."5009297550715157269"]
chain_id         = "1"
type             = "evm"
family           = "evm"
unique_chain_name = "ethereum-mainnet"

[[blockchain_infos."5009297550715157269".nodes]]
external_http_url = "https://eth-mainnet.example.com"
internal_http_url = "http://eth-node:8545"
external_ws_url   = "wss://eth-mainnet.example.com"
internal_ws_url   = "ws://eth-node:8546"

[blockchain_infos."4051577828743386545"]
chain_id         = "42161"
type             = "evm"
family           = "evm"
unique_chain_name = "arbitrum-mainnet"

[[blockchain_infos."4051577828743386545".nodes]]
external_http_url = "https://arb-mainnet.example.com"
internal_http_url = "http://arb-node:8545"
external_ws_url   = "wss://arb-mainnet.example.com"
internal_ws_url   = "ws://arb-node:8546"
```

`on_ramp_addresses` and `rmn_remote_addresses` map to `chainaccess.CommitteeConfig`.  
`blockchain_infos` is decoded generically (`map[string]any`) and re-decoded into the family-specific `Info` type (`evm.Info`) by the EVM constructor.

### 4.2 Overlay with the application's own config

`chainaccess.NewRegistry` takes the **full** app config string.  
Family constructors decode only the keys they care about (using a non-strict TOML decode), so your application-level keys (`verifier_id`, `aggregator_address`, etc.) are silently ignored by the registry.  
Conversely, `blockchain_infos` and the shared addresses are ignored by your application-level strict decode.

> **Important:** when using `commit.LoadConfigWithBlockchainInfos` (which does a **strict** decode), pass `spec.AppConfig` as the string and keep `blockchain_infos` present — the strict decoder must see it or it will error on unknown keys. Use `LoadConfigWithBlockchainInfos[any]` if you no longer need a typed `T` on the infos.

### 4.3 JobSpec envelope (sent by JD)

JD wraps the inner config in a `JobSpec` TOML envelope. The `appConfig` field is the **TOML-encoded** inner config as a string value:

```toml
name          = "my-verifier-ethereum"
externalJobID = "d1b43400-0000-0000-0000-000000000001"
schemaVersion = 1
type          = "ccv"
appConfig     = """
verifier_id = "committee-verifier-1"
aggregator_address = "aggregator.example.com:443"
...
"""
```

---

## 5. Step-by-step migration guide

### 5.1 Add the blank import

In your `main.go` (or any file compiled into the binary), add a blank import for every chain family you want to support:

```go
import (
    // Registers the EVM AccessorFactoryConstructor via init().
    _ "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
)
```

If you later add Stellar support, add:

```go
    _ "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/stellar"
```

No other code changes are needed to pick up the new family.

### 5.2 Swap the `ServiceFactory` type parameter to `bootstrap.JobSpec`

**Before:**
```go
// main.go
bootstrap.Run(
    "EVMCommitteeVerifier",
    cmd.NewCommitteeVerifierServiceFactory[evm.Info](
        chainsel.FamilyEVM,
        deprecatedCreateAccessorFactory,
    ),
    bootstrap.WithLogLevel[bootstrap.JobSpec](zapcore.InfoLevel),
)
```

**After:**
```go
// main.go
bootstrap.Run(
    "CommitteeVerifier",
    &myFactory{},
    bootstrap.WithLogLevel[bootstrap.JobSpec](zapcore.InfoLevel),
)
```

Your factory should implement `bootstrap.ServiceFactory[bootstrap.JobSpec]`:

```go
type myFactory struct { /* fields for shutdown */ }

var _ bootstrap.ServiceFactory[bootstrap.JobSpec] = (*myFactory)(nil)

func (f *myFactory) Start(ctx context.Context, spec bootstrap.JobSpec, deps bootstrap.ServiceDeps) error { ... }
func (f *myFactory) Stop(ctx context.Context) error { ... }
```

### 5.3 Replace `createAccessorFactoryFunc` with `chainaccess.NewRegistry`

**Before:**
```go
func (f *factory[T]) Start(ctx context.Context, spec bootstrap.JobSpec, deps bootstrap.ServiceDeps) error {
    config, blockchainInfos, err := commit.LoadConfigWithBlockchainInfos[T](spec.AppConfig)
    // ...

    accessorFactory, err := f.createAccessorFactoryFunc(ctx, lggr, blockchainInfos, *config)
    // ...
}
```

**After:**
```go
func (f *myFactory) Start(ctx context.Context, spec bootstrap.JobSpec, deps bootstrap.ServiceDeps) error {
    lggr := logger.Sugared(logger.Named(deps.Logger, "MyService"))

    // 1. Parse the application's own config (strict decode).
    //    blockchain_infos must still be present in spec.AppConfig.
    config, _, err := commit.LoadConfigWithBlockchainInfos[any](spec.AppConfig)
    if err != nil {
        return fmt.Errorf("failed to load config: %w", err)
    }

    // 2. Build the registry — all registered families are initialized from the
    //    same config string. No generic type parameter, no family wiring.
    registry, err := chainaccess.NewRegistry(lggr, spec.AppConfig)
    if err != nil {
        return fmt.Errorf("failed to create chain access registry: %w", err)
    }

    // 3. Get an Accessor for each chain you want to read.
    sourceReaders := make(map[protocol.ChainSelector]chainaccess.SourceReader)
    for selector := range config.OnRampAddresses {
        sel, _ := strconv.ParseUint(selector, 10, 64)
        chainSel := protocol.ChainSelector(sel)
        accessor, err := registry.GetAccessor(ctx, chainSel)
        if err != nil {
            lggr.Errorw("Failed to get accessor", "selector", chainSel, "error", err)
            continue
        }
        sourceReaders[chainSel] = accessor.SourceReader()
    }
    // ... start your coordinator
}
```

### 5.4 Remove chain-family filtering boilerplate

The old pattern required skipping selectors that did not match the expected family:

```go
// OLD — no longer needed
if family != f.chainFamily {
    lggr.Warnw("Skipping chain — wrong family", "selector", selector)
    continue
}
```

`Registry.GetAccessor` returns an error when no factory is registered for the selector's family. Log and skip those selectors the same way you would log any other `GetAccessor` error. You no longer need to pass or store `chainFamily`.

### 5.5 Update `main.go`

Remove all references to:

* `chainFamily string` constructor arguments.
* `CreateAccessorFactoryFunc[T]` / `CreateExecutorComponentsFunc[T]`.
* The `deprecatedCreateAccessorFactory` wrapper function.
* Generic type parameters on `NewCommitteeVerifierServiceFactory[T]` / `NewServiceFactory[T]`.

Keep:

* The blank import(s) for each chain family.
* `bootstrap.Run(...)` with your non-generic factory.

---

## 6. Complete before / after example

### Before

```go
// verifier/cmd/committee/main.go  (BEFORE)

package main

import (
    _ "github.com/lib/pq"
    "go.uber.org/zap/zapcore"

    chainsel "github.com/smartcontractkit/chain-selectors"
    "github.com/smartcontractkit/chainlink-ccv/bootstrap"
    "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
    "github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
    cmd "github.com/smartcontractkit/chainlink-ccv/verifier/cmd"
    "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"
    "github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func deprecatedCreateAccessorFactory(
    ctx context.Context,
    lggr logger.Logger,
    infos map[string]evm.Info,
    cfg commit.Config,
) (chainaccess.AccessorFactory, error) {
    genericConfig := chainaccess.GenericConfig{
        CommitteeConfig: cfg.CommitteeConfig,
    }
    return evm.CreateAccessorFactory(ctx, lggr, genericConfig, infos)
}

func main() {
    if err := bootstrap.Run(
        "EVMCommitteeVerifier",
        cmd.NewCommitteeVerifierServiceFactory[evm.Info](   // generic param ← EVM only
            chainsel.FamilyEVM,                             // family string
            deprecatedCreateAccessorFactory,                // wiring function
        ),
        bootstrap.WithLogLevel[bootstrap.JobSpec](zapcore.InfoLevel),
    ); err != nil {
        panic(err)
    }
}
```

```go
// verifier/cmd/servicefactory.go  (BEFORE — simplified)

type factory[T any] struct {
    createAccessorFactoryFunc CreateAccessorFactoryFunc[T]
    chainFamily               string
    // ...
}

func (f *factory[T]) Start(ctx context.Context, spec bootstrap.JobSpec, deps bootstrap.ServiceDeps) error {
    config, blockchainInfos, err := commit.LoadConfigWithBlockchainInfos[T](spec.AppConfig)
    // ...

    accessorFactory, err := f.createAccessorFactoryFunc(ctx, lggr, blockchainInfos, *config)
    // ...

    for _, selector := range chainSelectors {
        family, _ := chainsel.GetSelectorFamily(uint64(selector))
        if family != f.chainFamily {          // ← manual family guard
            continue
        }
        accessor, err := accessorFactory.GetAccessor(ctx, selector)
        sourceReaders[selector] = accessor.SourceReader()
    }
    // ...
}
```

### After

```go
// verifier/cmd/committee/main.go  (AFTER)

package main

import (
    _ "github.com/lib/pq"
    "go.uber.org/zap/zapcore"

    // Single blank import wires the EVM family automatically.
    _ "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"

    "github.com/smartcontractkit/chainlink-ccv/bootstrap"
    cmd "github.com/smartcontractkit/chainlink-ccv/verifier/cmd"
)

func main() {
    if err := bootstrap.Run(
        "CommitteeVerifier",
        cmd.NewCommitteeVerifierServiceFactory(), // no generic param, no wiring
        bootstrap.WithLogLevel[bootstrap.JobSpec](zapcore.InfoLevel),
    ); err != nil {
        panic(err)
    }
}
```

```go
// verifier/cmd/servicefactory.go  (AFTER — simplified)

import "github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"

type factory struct { /* no T, no chainFamily, no createAccessorFactoryFunc */ }

func NewCommitteeVerifierServiceFactory() bootstrap.ServiceFactory[bootstrap.JobSpec] {
    return &factory{}
}

func (f *factory) Start(ctx context.Context, spec bootstrap.JobSpec, deps bootstrap.ServiceDeps) error {
    lggr := logger.Sugared(logger.Named(deps.Logger, "CommitteeVerifier"))

    // Parse application config.
    config, _, err := commit.LoadConfigWithBlockchainInfos[any](spec.AppConfig)
    if err != nil {
        return fmt.Errorf("failed to load config: %w", err)
    }

    // Create registry — dispatches to all registered families automatically.
    registry, err := chainaccess.NewRegistry(lggr, spec.AppConfig)
    if err != nil {
        return fmt.Errorf("failed to create registry: %w", err)
    }

    sourceReaders := make(map[protocol.ChainSelector]chainaccess.SourceReader)
    for strSel := range config.OnRampAddresses {
        sel, _ := strconv.ParseUint(strSel, 10, 64)
        chainSel := protocol.ChainSelector(sel)
        accessor, err := registry.GetAccessor(ctx, chainSel)
        if err != nil {
            lggr.Warnw("Skipping chain — no accessor", "selector", chainSel, "error", err)
            continue
        }
        sourceReaders[chainSel] = accessor.SourceReader()
    }

    // ... start coordinator using sourceReaders
}
```

The TOML config file is **unchanged** — only the Go wiring changes.

---

## 7. Adding a new non-EVM chain family

If your application needs to support a new chain family (e.g. Stellar), implement `AccessorFactoryConstructor` in a new package and register it:

```go
// integration/pkg/accessors/stellar/factory_constructor.go

package stellar

import (
    chainsel "github.com/smartcontractkit/chain-selectors"
    "github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
    "github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func init() {
    chainaccess.Register(chainsel.FamilyStellar, CreateStellarAccessorFactory)
}

func CreateStellarAccessorFactory(lggr logger.Logger, cfg string) (chainaccess.AccessorFactory, error) {
    var genericConfig chainaccess.GenericConfig
    if _, err := toml.Decode(cfg, &genericConfig); err != nil {
        return nil, fmt.Errorf("decode generic config: %w", err)
    }
    // Build Stellar-specific clients from genericConfig.ChainConfig ...
    return &stellarFactory{ /* ... */ }, nil
}
```

In your binary, add one blank import:

```go
import _ "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/stellar"
```

`chainaccess.NewRegistry` will now return a Registry that handles both EVM and Stellar selectors with zero changes to service code.

### Implementing `AccessorFactory` for the new family

Your factory must implement:

```go
type AccessorFactory interface {
    GetAccessor(ctx context.Context, chainSelector protocol.ChainSelector) (Accessor, error)
}

type Accessor interface {
    SourceReader() SourceReader
}
```

`SourceReader` must satisfy all methods in `chainaccess.SourceReader`:
* `FetchMessageSentEvents`
* `GetBlocksHeaders`
* `LatestAndFinalizedBlock`
* `LatestSafeBlock`
* `GetRMNCursedSubjects`

See `integration/pkg/accessors/evm/evm_source_reader.go` as the reference EVM implementation.

---

## 8. Running without JD (`WithTOMLAppConfig`)

Some services (e.g. the token verifier) load config directly from a file instead of JD.  
The registry pattern is identical — only the bootstrap option differs:

```go
// main.go
bootstrap.Run(
    "TokenVerifier",
    &tokenFactory{},
    bootstrap.WithTOMLAppConfig[bootstrap.JobSpec](configPath), // ← loads file, wraps as JobSpec
)
```

> `WithTOMLAppConfig` reads the file, wraps the contents in a synthetic `bootstrap.JobSpec` with the file contents as `AppConfig`, and calls `factory.Start` with it.  
> Your `Start` implementation is identical whether config comes from JD or a file.

When using `WithTOMLAppConfig` the config file is the **inner app config** (no `name`/`externalJobID` envelope), so the file format matches section 4.1 directly.

---

## 9. Deprecated APIs and replacements

| Deprecated symbol | Package | Replacement |
|---|---|---|
| `CreateAccessorFactoryFunc[T]` | `verifier/cmd` | Remove — call `chainaccess.NewRegistry` directly |
| `NewServiceFactory[T](chainFamily, fn)` | `verifier/cmd` | `NewCommitteeVerifierServiceFactory()` (no generics) |
| `NewCommitteeVerifierServiceFactory[T](chainFamily, fn)` | `verifier/cmd` | `NewCommitteeVerifierServiceFactory()` (no generics) |
| `NewServiceFactory[T](chainFamily, fn)` | `cmd/executor` | `NewServiceFactory()` (no generics) |
| `CreateExecutorComponentsFunc[T]` | `cmd/executor` | Remove — call `chainaccess.NewRegistry` directly |
| `evm.CreateAccessorFactory(ctx, lggr, genericConfig, infos)` | `integration/pkg/accessors/evm` | Blank-import the package; call `chainaccess.NewRegistry(lggr, cfg)` |
| `commit.LoadConfigWithBlockchainInfos[T](cfg)` returning `Infos[T]` | `verifier/pkg/commit` | Call with `[any]` — the `Infos` return value is no longer needed when using the registry |

All deprecated symbols remain compilable (they are not removed yet) to allow incremental migration.

---

## 10. FAQ

**Q: Do I need to change my TOML config files?**  
No. The TOML structure is unchanged. `on_ramp_addresses`, `rmn_remote_addresses`, and `blockchain_infos` were already present and stay where they are.

**Q: What happens if `blockchain_infos` contains selectors from multiple families?**  
Each family's `AccessorFactoryConstructor` iterates only the selectors that belong to its family (using `chainsel.IsEvm` etc.) and skips the rest. `chainaccess.NewRegistry` calls all registered constructors, so every selector is handled by exactly one factory.

**Q: What if `GetAccessor` returns an error for a selector?**  
Log and skip it. This is normal when a selector's family has no registered constructor in the binary. It is **not** normal if the family's blank import is present and the config's `blockchain_infos` entry is correct — treat that as a bug and check the RPC URL configuration.

**Q: Can I still use `evm.CreateAccessorFactory` directly in tests?**  
Yes. The function is public and unchanged. The registry wraps it but does not replace it. Use it in unit tests where you want to construct an `AccessorFactory` without relying on `init()` global state.

**Q: The generic `factory[T]` was ensuring type-safety for `evm.Info` fields at compile time. What replaces that?**  
The EVM `AccessorFactoryConstructor` still decodes `evm.Info` internally and returns an error if the config is malformed. The difference is that the error surfaces at `chainaccess.NewRegistry` call-time (startup) rather than at compile time. Existing integration tests catch mis-configuration before deployment.

**Q: My service calls `LoadConfigWithBlockchainInfos[evm.Info]` and uses the returned `Infos[evm.Info]` map directly. Do I need to change that?**  
If you only need `blockchainInfos` to construct the accessor factory, you can drop it and switch to `LoadConfigWithBlockchainInfos[any]` — the returned `Infos[any]` can be ignored. If you need the typed map for other purposes (e.g. reading `ChainID`), keep `LoadConfigWithBlockchainInfos[evm.Info]` as-is; it is independent of the registry.

