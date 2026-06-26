# Standalone verifier nodes publish signing keys to JD on connect

## Summary

Committee verifier nodes now push their onchain signing address to JD via
`feedsmanager.UpdateNode` on every JD connect, making it available to
deployment changesets via `NodeService.ListNodeChainConfigs`. Previously,
standalone verifiers had no path to register signing keys in JD; devenv
worked around this by injecting keys directly from the bootstrap HTTP server.

---

## Breaking change: `ClientInterface` gains `UpdateNode`

Any code that implements `client.ClientInterface` (e.g. a test double outside
this repo) must add the new method.

```go
// New method on ClientInterface
UpdateNode(ctx context.Context, req *pb.UpdateNodeRequest) error
```

The `MockClientInterface` in `internal/mocks` is already updated.

---

## New: `[[chains]]` section in bootstrap config

Operators declare which chains a node has a signing identity on. The
bootstrapper derives the onchain signing address from the node's `ECDSA_S256`
key and calls `feedsmanager.UpdateNode` once after each JD connect.

```toml
[[chains]]
type = "EVM"
id   = "1"

[[chains]]
type = "EVM"
id   = "137"
```

`[[chains]]` is optional — nodes without it skip the sync silently. `type` is
case-insensitive; accepted values: `EVM`, `SOLANA`, `APTOS`, `STARKNET`,
`TRON`, `TON`, `SUI`. Stellar and Canton require a JD proto update first.

Address format per chain family:

| Family | Format |
|--------|--------|
| EVM | EIP-55 checksummed address, `0x`-prefixed |
| SOLANA | 20-byte keccak256 address, lowercase hex, no prefix |
| APTOS | Full uncompressed secp256k1 pubkey, lowercase hex, no prefix |

---

## New: `lifecycle.Manager` `OnConnectHook`

An optional callback invoked each time the JD connection is established.
Failures are logged as warnings and do not block job processing. Used
internally by the bootstrapper to fire the signing-key sync; exposed so
other callers can attach post-connect logic without forking the manager.

```go
lifecycle.Config{
    // ...
    OnConnectHook: func(ctx context.Context) error { ... },
}
```

---

## Devenv: signing key sync wired end-to-end

`launchVerifier` now populates `[[chains]]` from `blockchain.Output.ChainID`
so devenv bootstrap configs include the chain section automatically. The
manual signer-address enrichment in `enrichEnvironmentTopology` is skipped
for EVM, Solana, and Aptos — the verifier changeset's existing JD fallback
path now runs for those families instead.
