# Devenv Chain Family Registry Consolidation

## Executive Summary

- Consolidates devenv chain-family extension registration into `github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg`.
- Replaces separate global registries for implementation factories, CLDF providers, chain config loaders, launchers, modifiers, and extra-args serializers.
- Affects downstream product repos that register chain-family devenv integrations, especially `chainlink-canton`, Solana integrations, and any repo importing old devenv registry packages.
- Introduces breaking API changes: old registry packages/functions are removed, `committeeverifier.New` and `executor.New` take explicit modifier maps, and extra-args serializers are looked up through `chainreg`.

## AI Adapter Index

The expected consumer of this changelog is an AI adapting a downstream repo. This table is its entry point: every symbol or behavior touched gets one row, with a grep pattern for finding consumer call sites and an anchor into the rest of this file for migration detail. The AI is expected to:

1. Read this table.
2. Run each `Search` pattern against the consumer repo.
3. For rows that produce hits, read **only** the linked `Section`. Skip rows with zero hits.
4. Treat any symbol *not* listed here as unchanged — do not load source for it.

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `chainimpl.ImplFactory` | removed | `chainimpl\.ImplFactory\b|build/devenv/chainimpl` | — | [#chainimpl-registry-removed](#chainimpl-registry-removed) |
| `chainimpl.RegisterImplFactory` | removed | `chainimpl\.RegisterImplFactory\(` | — | [#chainimpl-registry-removed](#chainimpl-registry-removed) |
| `chainimpl.GetImplFactory` | removed | `chainimpl\.GetImplFactory\(` | — | [#chainimpl-registry-removed](#chainimpl-registry-removed) |
| `chainimpl.GetAllImplFactories` | removed | `chainimpl\.GetAllImplFactories\(` | — | [#chainimpl-registry-removed](#chainimpl-registry-removed) |
| `registry.CLDFProviderFactory` | removed | `registry\.CLDFProviderFactory\b|build/devenv/registry` | — | [#cldf-provider-registry-removed](#cldf-provider-registry-removed) |
| `registry.CLDFProviderRegistry` | removed | `registry\.CLDFProviderRegistry\b` | — | [#cldf-provider-registry-removed](#cldf-provider-registry-removed) |
| `registry.GetGlobalCLDFProviderRegistry` | removed | `registry\.GetGlobalCLDFProviderRegistry\(` | — | [#cldf-provider-registry-removed](#cldf-provider-registry-removed) |
| `registry.RegisterCLDFProviderFactory` | removed | `registry\.RegisterCLDFProviderFactory\(` | — | [#cldf-provider-registry-removed](#cldf-provider-registry-removed) |
| `chainconfig.ChainConfigLoader` | removed | `chainconfig\.ChainConfigLoader\b|services/chainconfig` | — | [#chainconfig-registry-removed](#chainconfig-registry-removed) |
| `chainconfig.RegisterChainConfigLoader` | removed | `chainconfig\.RegisterChainConfigLoader\(` | — | [#chainconfig-registry-removed](#chainconfig-registry-removed) |
| `chainconfig.GetChainConfigLoader` | removed | `chainconfig\.GetChainConfigLoader\(` | — | [#chainconfig-registry-removed](#chainconfig-registry-removed) |
| `ccv.RegisterLauncher` | removed | `ccv\.RegisterLauncher\(` | — | [#generic-service-launcher-registry-removed](#generic-service-launcher-registry-removed) |
| `ccv.Launcher` | removed | `ccv\.Launcher\b` | — | [#generic-service-launcher-registry-removed](#generic-service-launcher-registry-removed) |
| `committeeverifier.RegisterModifier` | removed | `committeeverifier\.RegisterModifier\(` | — | [#modifier-global-registries-removed](#modifier-global-registries-removed) |
| `executor.RegisterModifier` | removed | `executor\.RegisterModifier\(` | — | [#modifier-global-registries-removed](#modifier-global-registries-removed) |
| `cciptestinterfaces.RegisterExtraArgsSerializer` | removed | `cciptestinterfaces\.RegisterExtraArgsSerializer\(` | — | [#extra-args-registry-moved-to-chainreg](#extra-args-registry-moved-to-chainreg) |
| `cciptestinterfaces.GetExtraArgsSerializer` | removed | `cciptestinterfaces\.GetExtraArgsSerializer\(` | — | [#extra-args-registry-moved-to-chainreg](#extra-args-registry-moved-to-chainreg) |
| `cciptestinterfaces.ExtraArgsSerializerEntry` | removed | `cciptestinterfaces\.ExtraArgsSerializerEntry\b` | — | [#extra-args-registry-moved-to-chainreg](#extra-args-registry-moved-to-chainreg) |
| `committeeverifier.New` | signature-changed | `committeeverifier\.New\(` | `build/devenv/services/committeeverifier/base.go:196` | [#modifier-dependency-injection](#modifier-dependency-injection) |
| `executor.New` | signature-changed | `executor\.New\(` | `build/devenv/services/executor/base.go:156` | [#modifier-dependency-injection](#modifier-dependency-injection) |
| `chainreg.Registry.Add` | behavior-changed | `\.Add\([^)]*chainreg\.Registration|chainreg\.Register\(` | `build/devenv/chainreg/registry.go:42` | [#chainreg-registration-merge-behavior](#chainreg-registration-merge-behavior) |
| `chainreg.Registration` | added | `chainreg\.Registration\b` | `build/devenv/chainreg/types.go:88` | [#new-chainreg-package](#new-chainreg-package) |
| `chainreg.ImplFactory` | added | `chainreg\.ImplFactory\b` | `build/devenv/chainreg/types.go:22` | [#new-chainreg-package](#new-chainreg-package) |
| `chainreg.CLDFProviderFactory` | added | `chainreg\.CLDFProviderFactory\b` | `build/devenv/chainreg/types.go:55` | [#new-chainreg-package](#new-chainreg-package) |
| `chainreg.ChainConfigLoader` | added | `chainreg\.ChainConfigLoader\b` | `build/devenv/chainreg/types.go:58` | [#new-chainreg-package](#new-chainreg-package) |
| `chainreg.GenericServiceDefinition` | added | `chainreg\.GenericServiceDefinition\b` | `build/devenv/chainreg/types.go:61` | [#new-chainreg-package](#new-chainreg-package) |
| `chainreg.Launcher` | added | `chainreg\.Launcher\b` | `build/devenv/chainreg/types.go:68` | [#new-chainreg-package](#new-chainreg-package) |
| `chainreg.VerifierModifier` | added | `chainreg\.VerifierModifier\b` | `build/devenv/chainreg/types.go:78` | [#new-chainreg-package](#new-chainreg-package) |
| `chainreg.ExecutorModifier` | added | `chainreg\.ExecutorModifier\b` | `build/devenv/chainreg/types.go:81` | [#new-chainreg-package](#new-chainreg-package) |
| `chainreg.ExtraArgsSerializer` | added | `chainreg\.ExtraArgsSerializer\b` | `build/devenv/chainreg/types.go:84` | [#extra-args-registry-moved-to-chainreg](#extra-args-registry-moved-to-chainreg) |
| `chainreg.GetRegistry` | added | `chainreg\.GetRegistry\(` | `build/devenv/chainreg/registry.go:28` | [#new-chainreg-package](#new-chainreg-package) |
| `chainreg.Register` | added | `chainreg\.Register\(` | `build/devenv/chainreg/registry.go:36` | [#new-chainreg-package](#new-chainreg-package) |
| `chainreg.Registry.Get` | added | `\.Get\([^)]*family|chainreg\.GetRegistry\(\)\.Get\(` | `build/devenv/chainreg/registry.go:88` | [#new-chainreg-package](#new-chainreg-package) |
| `chainreg.Registry.GetAll` | added | `chainreg\.GetRegistry\(\)\.GetAll\(` | `build/devenv/chainreg/registry.go:100` | [#new-chainreg-package](#new-chainreg-package) |
| `chainreg.Registry.GetAllImplFactories` | added | `chainreg\.GetRegistry\(\)\.GetAllImplFactories\(` | `build/devenv/chainreg/registry.go:110` | [#new-chainreg-package](#new-chainreg-package) |
| `chainreg.Registry.GetVerifierModifiers` | added | `chainreg\.GetRegistry\(\)\.GetVerifierModifiers\(` | `build/devenv/chainreg/registry.go:124` | [#modifier-dependency-injection](#modifier-dependency-injection) |
| `chainreg.Registry.GetExtraArgsSerializer` | added | `chainreg\.GetRegistry\(\)\.GetExtraArgsSerializer\(` | `build/devenv/chainreg/registry.go:138` | [#extra-args-registry-moved-to-chainreg](#extra-args-registry-moved-to-chainreg) |
| `chainreg.Registry.GetExecutorModifiers` | added | `chainreg\.GetRegistry\(\)\.GetExecutorModifiers\(` | `build/devenv/chainreg/registry.go:151` | [#modifier-dependency-injection](#modifier-dependency-injection) |

## Breaking Changes

### Chainimpl Registry Removed

- **What changed:** `build/devenv/chainimpl` was removed. `chainimpl.ImplFactory`, `chainimpl.RegisterImplFactory`, `chainimpl.GetImplFactory`, and `chainimpl.GetAllImplFactories` are no longer available.
- **Before:** product repos registered implementation factories separately:
  ```go
  chainimpl.RegisterImplFactory(chainsel.FamilyCanton, NewImplFactory())
  ```
- **After:** implementation factories are fields on `chainreg.Registration`:
  ```go
  chainreg.Register(chainsel.FamilyCanton, chainreg.Registration{
      ImplFactory: NewImplFactory(),
  })
  ```
- **Why:** implementation factories are one part of a chain-family registration; keeping them in a separate global registry forced product repos to register multiple related objects independently.
- **Who is affected:** any downstream repo importing `github.com/smartcontractkit/chainlink-ccv/build/devenv/chainimpl` or calling its register/get helpers.

### CLDF Provider Registry Removed

- **What changed:** `build/devenv/registry` was removed. `registry.CLDFProviderFactory`, `registry.CLDFProviderRegistry`, `registry.GetGlobalCLDFProviderRegistry`, and `registry.RegisterCLDFProviderFactory` are no longer available.
- **Before:** product repos registered CLDF providers separately:
  ```go
  registry.RegisterCLDFProviderFactory(chainsel.FamilyCanton, NewCLDFProviderFactory())
  ```
- **After:** CLDF providers are registered through `chainreg.Registration.CLDFProvider`:
  ```go
  chainreg.Register(chainsel.FamilyCanton, chainreg.Registration{
      CLDFProvider: NewCLDFProviderFactory(),
  })
  ```
- **Why:** CLDF provider lookup is keyed by chain family and belongs with the rest of the chain-family integration.
- **Who is affected:** any downstream repo importing `github.com/smartcontractkit/chainlink-ccv/build/devenv/registry`.

### Chainconfig Registry Removed

- **What changed:** the global `services/chainconfig` registry was removed. `chainconfig.ChainConfigLoader`, `chainconfig.RegisterChainConfigLoader`, and `chainconfig.GetChainConfigLoader` are no longer available.
- **Before:** product repos registered chain config loaders separately:
  ```go
  chainconfig.RegisterChainConfigLoader(chainsel.FamilyCanton, CommitteeVerifierConfigLoader)
  ```
- **After:** chain config loaders are registered through `chainreg.Registration.ChainConfigLoader`:
  ```go
  chainreg.Register(chainsel.FamilyCanton, chainreg.Registration{
      ChainConfigLoader: CommitteeVerifierConfigLoader,
  })
  ```
- **Why:** chain config loading is chain-family keyed and is now resolved through the same registry as implementation factories and CLDF providers.
- **Who is affected:** downstream repos importing `github.com/smartcontractkit/chainlink-ccv/build/devenv/services/chainconfig`.

### Generic Service Launcher Registry Removed

- **What changed:** `ccv.RegisterLauncher` and `ccv.Launcher` were removed. `ccv.GenericServiceDefinition` remains as an alias for `chainreg.GenericServiceDefinition`.
- **Before:** product repos registered generic launchers separately:
  ```go
  ccv.RegisterLauncher(chainsel.FamilyCanton, launcher)
  ```
- **After:** launchers are registered through `chainreg.Registration.Launcher`:
  ```go
  chainreg.Register(chainsel.FamilyCanton, chainreg.Registration{
      Launcher: launcher,
  })
  ```
- **Why:** generic service launchers are chain-family keyed and should be registered with other chain-family capabilities.
- **Who is affected:** downstream repos calling `ccv.RegisterLauncher` or referencing `ccv.Launcher`.

### Modifier Global Registries Removed

- **What changed:** `committeeverifier.RegisterModifier` and `executor.RegisterModifier` were removed. Modifier implementations are now supplied through `chainreg.Registration.VerifierModifier` and `chainreg.Registration.ExecutorModifier`, then injected into service constructors.
- **Before:** verifier and executor packages held global modifier maps populated via package init:
  ```go
  committeeverifier.RegisterModifier(chainsel.FamilyCanton, CommitteeVerifierModifier)
  executor.RegisterModifier(chainsel.FamilyCanton, ExecutorModifier)
  ```
- **After:** modifiers are part of chain registration:
  ```go
  chainreg.Register(chainsel.FamilyCanton, chainreg.Registration{
      VerifierModifier: CommitteeVerifierModifier,
      ExecutorModifier: ExecutorModifier,
  })
  ```
- **Why:** direct global modifier registration made ownership unclear and made service packages depend on hidden process-global state. The new call path builds modifier maps from `chainreg` at the composition boundary and passes them explicitly.
- **Who is affected:** downstream repos registering verifier or executor modifiers, and direct callers of `committeeverifier.New` or `executor.New`.

### Modifier Dependency Injection

- **What changed:** `committeeverifier.New` and `executor.New` now require a modifier map as the fourth argument.
- **Before:**
  ```go
  verifierOut, err := committeeverifier.New(verifierInput, blockchainOutputs, jdInfra)
  executorOut, err := executor.New(executorInput, blockchainOutputs, jdInfra)
  ```
- **After:**
  ```go
  verifierOut, err := committeeverifier.New(
      verifierInput,
      blockchainOutputs,
      jdInfra,
      chainreg.GetRegistry().GetVerifierModifiers(),
  )

  executorOut, err := executor.New(
      executorInput,
      blockchainOutputs,
      jdInfra,
      chainreg.GetRegistry().GetExecutorModifiers(),
  )
  ```
- **Why:** modifier lookup is now explicit and avoids service packages importing `chainreg`, preventing import cycles.
- **Who is affected:** direct callers of `committeeverifier.New` and `executor.New`. The main `ccv` environment and phased executor component were updated internally.

### Extra Args Registry Moved To Chainreg

- **What changed:** `cciptestinterfaces` no longer owns a global serializer registry. `cciptestinterfaces.RegisterExtraArgsSerializer`, `cciptestinterfaces.GetExtraArgsSerializer`, and `cciptestinterfaces.ExtraArgsSerializerEntry` were removed. The serializer function type remains as `cciptestinterfaces.ExtraArgsSerializer` and is aliased by `chainreg.ExtraArgsSerializer`.
- **Before:**
  ```go
  cciptestinterfaces.RegisterExtraArgsSerializer(
      cciptestinterfaces.ExtraArgsSerializerEntry{
          Family:  chainsel.FamilyCanton,
          Version: 1,
      },
      BuildExtraArgsV1,
  )
  ```
- **After:**
  ```go
  chainreg.Register(chainsel.FamilyCanton, chainreg.Registration{
      ExtraArgsSerializers: map[uint8]chainreg.ExtraArgsSerializer{
          1: BuildExtraArgsV1,
      },
  })
  ```
- **Why:** `cciptestinterfaces` should remain an interface/type package. Serializer storage and lookup now live with the rest of chain-family registration.
- **Who is affected:** product repos registering extra-args serializers or looking them up directly.

### Chainreg Registration Merge Behavior

- **What changed:** `chainreg.Registry.Add` merges fields when a family is already registered. Existing fields win; incoming fields only fill missing fields. `ExtraArgsSerializers` are merged per version, with existing versions winning.
- **Before:** the old per-capability registries generally no-oped on duplicate keys.
- **After:** partial registrations can compose:
  ```go
  chainreg.Register(chainsel.FamilyCanton, chainreg.Registration{
      ExtraArgsSerializers: map[uint8]chainreg.ExtraArgsSerializer{1: BuildExtraArgsV1},
  })

  chainreg.Register(chainsel.FamilyCanton, chainreg.Registration{
      ImplFactory:       NewImplFactory(),
      ChainConfigLoader: CommitteeVerifierConfigLoader,
  })
  ```
- **Why:** `build/devenv/evm` temporarily provides cross-family serializer defaults for Canton and Solana while TODOs track moving those defaults to the product repos.
- **Who is affected:** product repos that call `chainreg.Register` more than once for the same family. Later calls cannot override fields already registered.

## Migration Guide

1. Replace old registry imports with `chainreg`:
   ```go
   import "github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
   ```

2. Collapse separate product-repo init registrations into one `chainreg.Register` call per chain family:
   ```go
   // Before
   chainimpl.RegisterImplFactory(chainsel.FamilyCanton, NewImplFactory())
   registry.RegisterCLDFProviderFactory(chainsel.FamilyCanton, NewCLDFProviderFactory())
   chainconfig.RegisterChainConfigLoader(chainsel.FamilyCanton, CommitteeVerifierConfigLoader)
   ccv.RegisterLauncher(chainsel.FamilyCanton, launcher)
   committeeverifier.RegisterModifier(chainsel.FamilyCanton, CommitteeVerifierModifier)
   ```

   ```go
   // After
   if err := chainreg.Register(chainsel.FamilyCanton, chainreg.Registration{
       ImplFactory:       NewImplFactory(),
       CLDFProvider:      NewCLDFProviderFactory(),
       ChainConfigLoader: CommitteeVerifierConfigLoader,
       Launcher:          launcher,
       VerifierModifier:  CommitteeVerifierModifier,
       ExecutorModifier:  ExecutorModifier,
       ExtraArgsSerializers: map[uint8]chainreg.ExtraArgsSerializer{
           1: BuildExtraArgsV1,
       },
   }); err != nil {
       panic("canton chainreg: " + err.Error())
   }
   ```

3. Replace direct implementation-factory lookup:
   ```go
   // Before
   factory, err := chainimpl.GetImplFactory(family)
   ```

   ```go
   // After
   reg, err := chainreg.GetRegistry().Get(family)
   if err != nil {
       return err
   }
   factory := reg.ImplFactory
   ```

4. Replace direct CLDF provider lookup:
   ```go
   // Before
   factory, ok := registry.GetGlobalCLDFProviderRegistry().Get(family)
   ```

   ```go
   // After
   reg, err := chainreg.GetRegistry().Get(family)
   if err != nil {
       return err
   }
   factory := reg.CLDFProvider
   ```

5. Replace direct chain config loader lookup:
   ```go
   // Before
   loader, err := chainconfig.GetChainConfigLoader(family)
   ```

   ```go
   // After
   reg, err := chainreg.GetRegistry().Get(family)
   if err != nil {
       return err
   }
   loader := reg.ChainConfigLoader
   ```

6. Move extra-args serializer registrations into `chainreg.Registration.ExtraArgsSerializers`:
   ```go
   // Before
   cciptestinterfaces.RegisterExtraArgsSerializer(
       cciptestinterfaces.ExtraArgsSerializerEntry{Family: chainsel.FamilyCanton, Version: 1},
       BuildExtraArgsV1,
   )
   ```

   ```go
   // After
   chainreg.Register(chainsel.FamilyCanton, chainreg.Registration{
       ExtraArgsSerializers: map[uint8]chainreg.ExtraArgsSerializer{
           1: BuildExtraArgsV1,
       },
   })
   ```

7. Replace direct extra-args serializer lookup:
   ```go
   // Before
   serializer, ok := cciptestinterfaces.GetExtraArgsSerializer(
       cciptestinterfaces.ExtraArgsSerializerEntry{Family: family, Version: version},
   )
   ```

   ```go
   // After
   serializer, ok := chainreg.GetRegistry().GetExtraArgsSerializer(family, version)
   ```

8. Update direct `committeeverifier.New` and `executor.New` calls to pass modifier maps:
   ```go
   // Before
   out, err := committeeverifier.New(input, outputs, jdInfra)
   ```

   ```go
   // After
   out, err := committeeverifier.New(input, outputs, jdInfra, chainreg.GetRegistry().GetVerifierModifiers())
   ```

   ```go
   // Before
   out, err := executor.New(input, outputs, jdInfra)
   ```

   ```go
   // After
   out, err := executor.New(input, outputs, jdInfra, chainreg.GetRegistry().GetExecutorModifiers())
   ```

9. If a product repo previously relied on EVM package init side effects for Canton or Solana extra-args serializers, move those serializers into the owning product repo. `build/devenv/evm/registration.go:56` still carries temporary TODO-backed defaults for Canton and Solana.

10. Run:
    ```sh
    go test ./...
    ```

## New Features / Additions

- **`chainreg` package** — adds a single chain-family registry for devenv extension points. See `build/devenv/chainreg/types.go:88` and `build/devenv/chainreg/registry.go:9`.
  - Usage: register all capabilities for a chain family from product repo `init()` functions.

- **Process-wide `chainreg.GetRegistry()` singleton** — provides access to the default registry without exporting mutable package state. See `build/devenv/chainreg/registry.go:28`.
  - Usage: internal devenv code resolves chain-family capabilities through `chainreg.GetRegistry().Get(family)`.

- **Unified `chainreg.Registration` struct** — groups `ImplFactory`, `CLDFProvider`, `ChainConfigLoader`, `Launcher`, `VerifierModifier`, `ExecutorModifier`, and `ExtraArgsSerializers`. See `build/devenv/chainreg/types.go:88`.
  - Usage: downstream chain-family integrations should populate the fields they support.

- **Modifier map accessors** — `chainreg.Registry.GetVerifierModifiers` and `chainreg.Registry.GetExecutorModifiers` build explicit DI maps for verifier and executor services. See `build/devenv/chainreg/registry.go:124` and `build/devenv/chainreg/registry.go:151`.
  - Usage: pass these maps to `committeeverifier.New` and `executor.New`.

- **Extra-args serializer lookup through `chainreg`** — `chainreg.Registry.GetExtraArgsSerializer` replaces the old `cciptestinterfaces` global serializer registry. See `build/devenv/chainreg/registry.go:138`.
  - Usage: resolve serializers by chain family and version from the same registry as other chain-family capabilities.

- **EVM registration colocation** — EVM implementation factory, CLDF provider factory, chain config loader, verifier/executor modifiers, token adapter registration, and extra-args serializer defaults now live in `build/devenv/evm/registration.go`.
  - Usage: EVM is registered when the `build/devenv/evm` package is linked via `build/devenv/register.go`.

## Compatibility & Requirements

- **Minimum versions:** no Go version change.
- **Dependency bumps:** none in this diff.
- **Supported environments / chains:** EVM registration remains built into `chainlink-ccv`. Canton and Solana serializer defaults are temporarily registered from the EVM package until product repos own their serializer registration.
- **Feature flags / rollout:** no feature flag. This is a breaking API migration.

## Examples

```go
// Example: product repo registration for one chain family.
package devenv

import (
    chainsel "github.com/smartcontractkit/chain-selectors"
    "github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
)

func init() {
    if err := chainreg.Register(chainsel.FamilyCanton, chainreg.Registration{
        ImplFactory:       NewImplFactory(),
        CLDFProvider:      NewCLDFProviderFactory(),
        ChainConfigLoader: CommitteeVerifierConfigLoader,
        Launcher:          NewLauncher(),
        VerifierModifier:  CommitteeVerifierModifier,
        ExtraArgsSerializers: map[uint8]chainreg.ExtraArgsSerializer{
            1: BuildExtraArgsV1,
        },
    }); err != nil {
        panic("canton chainreg: " + err.Error())
    }
}
```

```go
// Example: direct service constructor call after modifier DI.
out, err := committeeverifier.New(
    input,
    blockchainOutputs,
    jdInfra,
    chainreg.GetRegistry().GetVerifierModifiers(),
)
```

```go
// Example: extra-args serializer lookup after registry consolidation.
serializer, ok := chainreg.GetRegistry().GetExtraArgsSerializer(chainsel.FamilyCanton, 1)
if !ok {
    return fmt.Errorf("extra-args serializer not found")
}
extraArgs, err := serializer(provider)
```

## References

- Prior changelog entries this builds on: `changelog/2026-04-27_extra_args_data_provider.md`, `changelog/2026-04-22_standalone_executor_registry.md`, `changelog/2026-05-15_devenv_lib_implfactory_cldf_clients.md`
