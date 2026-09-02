# Explicit auto-adoption signer address for the verifier backbones

## Executive Summary

- Introduces the explicit `signer_address` sentinel value `"auto"` (`commit.AutoSignerAddress`): the verifier adopts whatever address the keystore holds instead of asserting a configured one.
- On the postgres auto-generate backend a fresh volume generates a random signing key, which previously crashed the loop on an empty or mismatched `signer_address`; setting `signer_address = "auto"` boots a fresh volume cleanly, and restarts reuse the same persisted key.
- The empty string stays an error — it now exclusively means "forgot to set it" — so auto-adoption requires deliberate intent and is never conflated with omission.
- A non-empty, non-sentinel `signer_address` is still validated strictly; the fail-fast guarantee for pinned deployments is unchanged.
- Adds a bootstrap info-server endpoint returning the checksummed signer address directly, so an operator no longer derives it from the public key (keccak math).
- Scope is verifier bootstrap only: no aggregator changes, no wire-format changes; `[key_import]` and KMS paths are untouched.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `commit.ValidateSignerAddress` | behavior-changed | `ValidateSignerAddress\(` | `verifier/pkg/commit/signer.go:35` | [#auto-adoption-sentinel](#auto-adoption-sentinel) |
| `commit.AutoSignerAddress` | added | `AutoSignerAddress\b` | `verifier/pkg/commit/signer.go:19` | [#auto-adoption-sentinel](#auto-adoption-sentinel) |
| `bootstrap.GetKeyAddressesEndpoint` | added | `GetKeyAddressesEndpoint\b` | `bootstrap/http.go:22` | [#signer-address-endpoint](#signer-address-endpoint) |
| `bootstrap.infoServer.handleGetKeyAddresses` | added | `handleGetKeyAddresses\b` | `bootstrap/http.go:134` | [#signer-address-endpoint](#signer-address-endpoint) |

## Breaking Changes

*No breaking changes.* `ValidateSignerAddress` keeps its signature; every value it rejected before (empty, malformed, mismatched) is still rejected. The only new behavior is the `"auto"` sentinel accepting whatever the keystore holds.

## Auto-adoption sentinel

- **What changed:** `ValidateSignerAddress` returns `nil` (confirms without checking) when `configured == AutoSignerAddress` (`"auto"`).
- **Before:** `hexutil.Decode("")` errored, and any set-but-mismatched address failed the boot with "signing address does not match signer_address". Empty and "deliberately don't pin" were indistinguishable.
- **After:** `signer_address = "auto"` opts out explicitly and adopts the keystore's address; the caller logs it (`Using signer address`). Empty still errors ("invalid signer_address"), so forgetting the field cannot be silently confused with choosing auto-adoption. Any other set value is decoded and matched strictly as before.
- **Why:** the postgres auto-generate backend creates a fresh key on an empty volume, so a first boot has no address to affirm. An explicit sentinel makes that intent unambiguous while keeping the empty-string case as the fail-fast "forgot to set it" signal.
- **Who is affected:** standalone verifier auto-generate deployments set `signer_address = "auto"`. CL-mode specs always pin a real address, so they behave identically.

```toml
# standalone verifier job, postgres auto-generate backend
signer_address = "auto"
```

## Signer-address endpoint

`POST` `/keystore/reader/getaddresses` on the bootstrap info server takes the same `keystore.GetKeysRequest{KeyNames: [...]}` body as `/keystore/reader/getkeys` and returns a JSON map of `keyName → checksummed address` (`0x`-prefixed, EIP-55). Only `ECDSA_S256` keys have a derivable EVM address; requesting any other key type returns HTTP 400.

```bash
# Operator reads the verifier's adopted signing address in one call.
curl -s localhost:PORT/keystore/reader/getaddresses \
  -d '{"keyNames":["bootstrap_default_ecdsa_signing_key"]}'
# => {"bootstrap_default_ecdsa_signing_key":"0xAbC…"}
```

## Compatibility & Requirements

- **Rollout:** none. The verifier job spec schema is unchanged; `signer_address` accepts one new string value (`"auto"`).
- **Rollback:** a binary swap.
