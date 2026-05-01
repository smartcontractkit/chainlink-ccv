# Executor contract transmitter uses keystore-managed key

## Summary

The executor's EVM contract transmitter is now backed by a keystore-managed ECDSA key
declared at startup via `bootstrap.WithKey`, replacing the raw private key previously
injected through the `EXECUTOR_TRANSMITTER_PRIVATE_KEY` environment variable and the
`transmitter_private_key` field. Key material never leaves the keystore; signing is
delegated via `evmkeys.TxKey`.

---

## Breaking change: `NewFactory` signature — `transmitterPrivateKey` removed

The `transmitterPrivateKey string` parameter is removed from `evm.NewFactory`.

Before:
```go
factory := evm.NewFactory(lggr, onRamps, rmnAddrs, headTrackers, chainClients,
    destChainConfigs, visibilityWindow, rpcURLs, transmitterPrivateKey)
```

After:
```go
factory := evm.NewFactory(lggr, onRamps, rmnAddrs, headTrackers, chainClients,
    destChainConfigs, visibilityWindow, rpcURLs)
```

---

## Breaking change: `EXECUTOR_TRANSMITTER_PRIVATE_KEY` env var removed

`CreateAccessorFactory` no longer reads this environment variable. The transmitter is
provisioned through the keystore only. Deployments that set it will silently ignore it.

---

## Breaking change: executor key name changed

The ECDSA key provisioned by the executor entrypoint changed name. Any existing keystore
with the old name will not be found; the new name is created on first boot.

| | Before | After |
|-|--------|-------|
| Key name | `"default_evm_key"` | `"evm/tx/executor_evm_transmitter_key"` |
| Constant | *(none)* | `executor.DefaultEVMTransmitterKeyName` |

The `evm/tx/` prefix follows the `evmkeys` convention and is embedded in the constant so
that `evmkeys.GetTxKeys` can be called with `WithNoPrefix()`.

---

## Breaking change: `ImplFactory` methods removed

`GenerateTransmitterKey` and `TransmitterAddress` are removed from the `ImplFactory`
interface. Devenv no longer generates raw private keys; transmitter addresses are instead
read from the bootstrap HTTP server after the executor container starts.

The following devenv helpers are also removed:
- `executor.Input.TransmitterPrivateKey` field
- `executor.Input.GetTransmitterAddress`
- `executor.SetTransmitterPrivateKey`
- `executor.TransmitterKeyGenerator` type
- `executor.TransmitterAddressResolver` type

---

## Breaking change: `chainaccess.Registry` is now an interface

`chainaccess.Registry` was a concrete struct; it is now an interface. The concrete
implementation is unexported. `NewRegistry` returns the interface.

Before:
```go
var reg *chainaccess.Registry = chainaccess.NewRegistry(...)
```

After:
```go
var reg chainaccess.Registry = chainaccess.NewRegistry(...)
```

`bootstrap.ServiceDeps.Registry` is updated accordingly (`*chainaccess.Registry` →
`chainaccess.Registry`).

---

## Breaking change: key name constants moved

`keys.DefaultCSAKeyName`, `keys.DefaultECDSASigningKeyName`, and
`keys.DefaultEdDSASigningKeyName` have moved out of `bootstrap/keys` into canonical
packages.

| Constant | Before | After |
|----------|--------|-------|
| CSA key name | `keys.DefaultCSAKeyName` | `bootstrap.DefaultCSAKeyName` |
| ECDSA signing key name | `keys.DefaultECDSASigningKeyName` | `commit.DefaultECDSASigningKeyName` |

The EdDSA signing key name is now unexported (`bootstrap.defaultEdDSASigningKeyName`) and
part of the deprecated default key set.

---

## New: `KeystoreEVMContractTransmitter`

A keystore-backed contract transmitter that signs OffRamp execute transactions without
exposing private key material. Uses `evmkeys.GetTxKeys` with `WithNoPrefix()` so the full
keystore path is passed as-is.

```go
ct, err := contracttransmitter.NewEVMContractTransmitterFromKeystore(
    ctx, lggr, chainSelector, rpcURL, ks,
    executor.DefaultEVMTransmitterKeyName, offRampAddress,
)
```

---

## New: `bootstrap.KeystoreSetter` interface

Accessors that require a keystore for signing implement this interface. The bootstrap
framework calls it automatically via `KeystoreRegistry`; implementations do not need to
arrange injection themselves.

```go
type KeystoreSetter interface {
    SetKeystore(ks keystore.Keystore)
}
```

The EVM accessor's `SetKeystore` builds and installs a `KeystoreEVMContractTransmitter`,
replacing any previously set transmitter. It is a no-op when `ks` is nil, `keyName` is
empty, or no RPC URL is available for the chain.

---

## New: `bootstrap.KeystoreRegistry`

A `chainaccess.Registry` wrapper that automatically calls `SetKeystore` on every accessor
returned by `GetAccessor` that implements `KeystoreSetter`. Logs a warning if an accessor
does not implement the interface. `bootstrap.Run` wraps the registry with this
automatically in JD mode.

```go
reg := bootstrap.NewKeystoreRegistry(lggr, inner, ks)
```

---

## New: `DestinationChainConfig.TransmitterKeyName`

Optional TOML field to override the transmitter key name per destination chain.
Defaults to `executor.DefaultEVMTransmitterKeyName` when empty.

```toml
[chain_configuration."12922642891491394802"]
transmitter_key_name = "evm/tx/my_custom_key"
```

---

## New: `executor.DefaultEVMTransmitterKeyName`

Constant for the full keystore path of the EVM transmitter key, exported from the
`executor` package so entrypoints, devenv, and the accessor can all reference the same
name without duplication.

```go
const DefaultEVMTransmitterKeyName = "evm/tx/executor_evm_transmitter_key"
```
