# Executor transmitter keys resolved via chainreg instead of per-family BootstrapKeys fields

## Executive Summary

- Replaces the hard-coded per-chain-family transmitter address fields on `services.BootstrapKeys` with a generic `PublicKeys map[string]string` keyed by full keystore key name, plus a `PublicKeyHex(keyName)` accessor.
- Moves per-family executor transmitter knowledge (which key name to fetch, how to decode it into an on-chain address) into a new `chainreg.ExecutorInfo` interface registered per family via `chainreg.Registration.ExecutorInfo`, so a new chain family no longer requires edits to shared devenv code.
- Relocates the EVM transmitter key-name constant from `executor.DefaultEVMTransmitterKeyName` (removed) to `contracttransmitter.DefaultKeyName`.
- Affects: downstream product repos that read `BootstrapKeys.EVMTransmitterAddress`, reference `executor.DefaultEVMTransmitterKeyName`, or call `services/executor.New`; and any repo registering a chain family that needs executor transmitter funding in devenv.
- Introduces breaking changes: `BootstrapKeys.EVMTransmitterAddress` removed, `executor.DefaultEVMTransmitterKeyName` removed, `services/executor.New` signature changed.

## AI Adapter Index

The expected consumer of this changelog is an AI adapting a downstream repo. This table is its entry point: every symbol or behavior touched gets one row, with a grep pattern for finding consumer call sites and an anchor into the rest of this file for migration detail. The AI is expected to:

1. Read this table.
2. Run each `Search` pattern against the consumer repo.
3. For rows that produce hits, read **only** the linked `Section`. Skip rows with zero hits.
4. Treat any symbol *not* listed here as unchanged — do not load source for it.

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `services.BootstrapKeys.EVMTransmitterAddress` | removed | `\.EVMTransmitterAddress\b|evm_transmitter_address` | — | [#bootstrapkeys-evmtransmitteraddress-removed](#bootstrapkeys-evmtransmitteraddress-removed) |
| `executor.DefaultEVMTransmitterKeyName → contracttransmitter.DefaultKeyName` | removed | `executor\.DefaultEVMTransmitterKeyName\b` | `integration/pkg/contracttransmitter/keystore_evm_contract_transmitter.go:33` | [#defaultevmtransmitterkeyname-removed](#defaultevmtransmitterkeyname-removed) |
| `executorsvc.New` | signature-changed | `executor\.New\(|executorsvc\.New\(` | `build/devenv/services/executor/base.go:164` | [#executor-new-signature](#executor-new-signature) |
| `services.FetchBootstrapKeys` | behavior-changed | `FetchBootstrapKeys\(` | `build/devenv/services/bootstrap.go:115` | [#fetchbootstrapkeys-behavior](#fetchbootstrapkeys-behavior) |
| `chainaccess.DestinationChainConfig.TransmitterKeyName` | behavior-changed | `TransmitterKeyName\b|transmitter_key_name` | `pkg/chainaccess/registry.go:161` | [#destinationchainconfig-transmitterkeyname](#destinationchainconfig-transmitterkeyname) |
| `services.BootstrapKeys.PublicKeys` | added | `\.PublicKeys\b|public_keys` | `build/devenv/services/bootstrap.go:102` | [#bootstrapkeys-publickeys](#bootstrapkeys-publickeys) |
| `services.BootstrapKeys.PublicKeyHex` | added | `\.PublicKeyHex\(` | `build/devenv/services/bootstrap.go:106` | [#bootstrapkeys-publickeyhex](#bootstrapkeys-publickeyhex) |
| `contracttransmitter.DefaultKeyName` | added | `contracttransmitter\.DefaultKeyName\b` | `integration/pkg/contracttransmitter/keystore_evm_contract_transmitter.go:33` | [#defaultevmtransmitterkeyname-removed](#defaultevmtransmitterkeyname-removed) |
| `chainreg.ExecutorInfo` | added | `chainreg\.ExecutorInfo\b` | `build/devenv/chainreg/types.go:59` | [#chainreg-executorinfo](#chainreg-executorinfo) |
| `chainreg.ExecutorInfo.ExecutorTransmitterKeyName` | added | `ExecutorTransmitterKeyName\(` | `build/devenv/chainreg/types.go:64` | [#chainreg-executorinfo](#chainreg-executorinfo) |
| `chainreg.ExecutorInfo.ExecutorTransmitterAddress` | added | `ExecutorTransmitterAddress\(` | `build/devenv/chainreg/types.go:70` | [#chainreg-executorinfo](#chainreg-executorinfo) |
| `chainreg.Registration.ExecutorInfo` | added | `Registration\{[^}]*ExecutorInfo|\.ExecutorInfo\b` | `build/devenv/chainreg/types.go:134` | [#registration-executorinfo-field](#registration-executorinfo-field) |

## Breaking Changes

### `BootstrapKeys.EVMTransmitterAddress` removed

- **What changed:** the `EVMTransmitterAddress string` field (TOML `evm_transmitter_address`) is removed from `services.BootstrapKeys`. Transmitter public keys are now stored generically in `BootstrapKeys.PublicKeys` keyed by full keystore key name.
- **Before:**
  ```go
  addr := keys.EVMTransmitterAddress // Ethereum address hex
  ```
- **After:**
  ```go
  // Raw public key hex for any requested key name:
  rawHex := keys.PublicKeyHex(contracttransmitter.DefaultKeyName)
  // EVM callers derive the address themselves, or use the family's ExecutorInfo:
  reg, err := chainreg.GetRegistry().Get(family)
  if err != nil || reg.ExecutorInfo == nil {
      // handle missing registration / ExecutorInfo per your context
  }
  addr := reg.ExecutorInfo.ExecutorTransmitterAddress(keys)
  ```
- **Why:** one named field per chain family meant every new family had to extend `BootstrapKeys` and the devenv funding code. A generic map plus per-family `ExecutorInfo` removes that coupling.
- **Who is affected:** any consumer reading `BootstrapKeys.EVMTransmitterAddress` or parsing the `evm_transmitter_address` TOML key.

### `executor.DefaultEVMTransmitterKeyName` removed

- **What changed:** the constant is removed from package `executor` (`executor/const.go`) and reintroduced as `contracttransmitter.DefaultKeyName` in `integration/pkg/contracttransmitter`. The string value is unchanged: `"evm/tx/executor_evm_transmitter_key"`.
- **Before:**
  ```go
  import "github.com/smartcontractkit/chainlink-ccv/executor"
  name := executor.DefaultEVMTransmitterKeyName
  ```
- **After:**
  ```go
  import "github.com/smartcontractkit/chainlink-ccv/integration/pkg/contracttransmitter"
  name := contracttransmitter.DefaultKeyName
  ```
- **Why:** the key name is an EVM contract-transmitter detail; it belongs with the EVM transmitter implementation, not in the shared `executor` package. This keeps `services.FetchBootstrapKeys` and the `executor` package free of family-specific key names.
- **Who is affected:** call sites referencing `executor.DefaultEVMTransmitterKeyName` (e.g. executor entrypoints, accessor factories, devenv bootstrap key fetch).

### `executorsvc.New` signature — `transmitterKeyName` added

- **What changed:** `build/devenv/services/executor.New` and its internal `launchExecutor` gained a trailing `transmitterKeyName string` parameter.
- **Before:**
  ```go
  func New(in *Input, outputs []*blockchain.Output, jdInfra *jobs.JDInfrastructure, modifiers map[string]ReqModifier) (*Output, error)
  ```
- **After:**
  ```go
  func New(in *Input, outputs []*blockchain.Output, jdInfra *jobs.JDInfrastructure, modifiers map[string]ReqModifier, transmitterKeyName string) (*Output, error)
  ```
- **Why:** the executor service must not import `chainreg` (import cycle), so the caller resolves the family's transmitter key name from the registry and passes it in. The service fetches/funds only the keys it is told about; pass `""` for families with no bootstrap-managed transmitter key.
- **Who is affected:** any code constructing executor services directly via `services/executor.New`. The in-repo caller (`build/devenv/components/executor/component.go`) already resolves the name via `chainreg.GetRegistry().Get(family)` and `reg.ExecutorInfo.ExecutorTransmitterKeyName()`.

## Migration Guide

1. Replace `executor.DefaultEVMTransmitterKeyName` with `contracttransmitter.DefaultKeyName` and update the import:

```go
// Before
import "github.com/smartcontractkit/chainlink-ccv/executor"
keyName := executor.DefaultEVMTransmitterKeyName

// After
import "github.com/smartcontractkit/chainlink-ccv/integration/pkg/contracttransmitter"
keyName := contracttransmitter.DefaultKeyName
```

2. Replace reads of `BootstrapKeys.EVMTransmitterAddress`. If you only need the raw public key, use `PublicKeyHex`. If you need the EVM on-chain address, resolve via the registry (which decodes per family) or derive it yourself:

```go
// Before
addr := keys.EVMTransmitterAddress

// After (registry path — recommended; family-aware)
reg, err := chainreg.GetRegistry().Get(family)
if err != nil || reg.ExecutorInfo == nil {
    // handle missing registration / ExecutorInfo per your context
}
addr := reg.ExecutorInfo.ExecutorTransmitterAddress(keys)

// After (manual EVM derivation)
rawHex := keys.PublicKeyHex(contracttransmitter.DefaultKeyName)
raw, _ := hex.DecodeString(rawHex)
pubKey, _ := crypto.UnmarshalPubkey(raw)
addr := hex.EncodeToString(crypto.PubkeyToAddress(*pubKey).Bytes())
```

3. Update calls to `services/executor.New` to pass a transmitter key name resolved from `chainreg`:

```go
// Before
out, err := executorsvc.New(exec, blockchainOutputs, jdInfra, chainreg.GetRegistry().GetExecutorModifiers())

// After
family := exec.ChainFamily
if family == "" {
    family = chainsel.FamilyEVM
}
var transmitterKeyName string
if reg, err := chainreg.GetRegistry().Get(family); err == nil && reg.ExecutorInfo != nil {
    transmitterKeyName = reg.ExecutorInfo.ExecutorTransmitterKeyName()
}
out, err := executorsvc.New(exec, blockchainOutputs, jdInfra, chainreg.GetRegistry().GetExecutorModifiers(), transmitterKeyName)
```

4. For a product repo registering a new chain family that needs executor transmitter funding in devenv, implement `chainreg.ExecutorInfo` and set it on the registration:

```go
type myExecutorInfo struct{}

func (myExecutorInfo) ExecutorTransmitterKeyName() string {
    return "solana/tx/executor_solana_transmitter_key" // family's bootstrap.WithKey name
}

func (myExecutorInfo) ExecutorTransmitterAddress(keys services.BootstrapKeys) string {
    rawHex := keys.PublicKeyHex("solana/tx/executor_solana_transmitter_key")
    if rawHex == "" {
        return ""
    }
    return rawHex // Solana address == 32-byte Ed25519 pubkey hex; decode/encode per family
}

func init() {
    _ = chainreg.Register(chainsel.FamilySolana, chainreg.Registration{
        // ... existing fields ...
        ExecutorInfo: myExecutorInfo{},
    })
}
```

5. Build to surface signature/symbol errors:

```sh
go build ./...
(cd build/devenv && go build ./...)
```

## New Features / Additions

- **`services.BootstrapKeys.PublicKeys`** — `map[string]string` of full keystore key name → lowercase hex-encoded raw public key bytes (TOML `public_keys`). See `build/devenv/services/bootstrap.go:102`.
  - Usage: replaces named per-family transmitter address fields; `FetchBootstrapKeys` populates it for every requested key name other than the CSA and ECDSA signing keys (which keep dedicated fields).

- **`services.BootstrapKeys.PublicKeyHex(keyName)`** — returns the hex-encoded raw public key for `keyName`, or `""` if absent. See `build/devenv/services/bootstrap.go:106`.
  - Usage: the accessor families use to pull their transmitter key out of `PublicKeys`.

- **`chainreg.ExecutorInfo`** — per-family interface exposing `ExecutorTransmitterKeyName()` and `ExecutorTransmitterAddress(keys services.BootstrapKeys)`. See `build/devenv/chainreg/types.go:59`.
  - Usage: register via `Registration.ExecutorInfo` so devenv learns which bootstrap key to fetch and how to turn it into a fundable on-chain address — without shared devenv code knowing about the family.

- **`chainreg.Registration.ExecutorInfo`** — optional field carrying the family's `ExecutorInfo`; merged by `Registry.Add` (existing value wins). See `build/devenv/chainreg/types.go:130`.
  - Usage: callers resolve transmitter key names and on-chain addresses via `chainreg.GetRegistry().Get(family)` and then `reg.ExecutorInfo` (see `build/devenv/components/executor/component.go` and `build/devenv/environment.go`). In-repo callers rely on `executorsvc.ApplyDefaults` (`build/devenv/services/executor/base.go:140`) normalizing an empty `ChainFamily` to EVM before the lookup; downstream callers that don't run `ApplyDefaults` should default an empty `family` to EVM at the call site (see Migration step 3).

## Behavior Changes

### `FetchBootstrapKeys` behavior

- **What changed:** `services.FetchBootstrapKeys` no longer references `executor.DefaultEVMTransmitterKeyName` or derives an EVM address itself. It still populates `CSAPublicKey`, `ECDSAPublicKey`, and `ECDSAAddress` for the CSA and ECDSA signing keys; every other requested key name is stored verbatim (raw public key hex) in `BootstrapKeys.PublicKeys`.
- **Before:** the function special-cased the EVM transmitter key and set `BootstrapKeys.EVMTransmitterAddress`.
- **After:** address derivation is the caller's / family's responsibility via `chainreg.ExecutorInfo`.
- **Who is affected:** callers relying on `FetchBootstrapKeys` to compute an EVM address; they must now derive it (see Migration step 2). A stale TODO about coupling to commit/executor/JD key names was also removed.

### `DestinationChainConfig.TransmitterKeyName`

- **What changed:** documentation/semantics generalized. Empty `TransmitterKeyName` no longer means "EVM defaults to `executor.DefaultEVMTransmitterKeyName`"; it now means "accessors fall back to their family's default transmitter key (defined by each family's transmitter package)". The TOML field name and type are unchanged.
- **Before:** EVM accessor defaulted to `executor.DefaultEVMTransmitterKeyName`.
- **After:** EVM accessor defaults to `contracttransmitter.DefaultKeyName`; other families default to their own package's key name.
- **Who is affected:** no config change required; documentation-only for consumers, but the EVM default constant moved (see [#defaultevmtransmitterkeyname-removed](#defaultevmtransmitterkeyname-removed)).

## Compatibility & Requirements

- **Minimum versions:** no Go version change.
- **Dependency bumps:** none.
- **Supported environments / chains:** EVM registers `ExecutorInfo` automatically when `build/devenv/evm` is linked (`build/devenv/evm/registration.go`). Other families must register their own `ExecutorInfo` to get executor transmitter funding in devenv; families that omit it simply get no transmitter address (funding is skipped) rather than a build break.
- **Feature flags / rollout:** none.

## References

- Related changelog entries this builds on: `changelog/2026-05-01_executor_keystore_transmitter.md`, `changelog/2026-05-18_devenv_chainreg.md`, `changelog/2026-06-03_chainreg_address_resolver.md`
