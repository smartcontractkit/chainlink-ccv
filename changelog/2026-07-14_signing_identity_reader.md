# SigningIdentityReader: family-specific signer identity from JD

## What changed

Bootstrap now pushes both `OnchainSigningAddress` (20-byte EVM address) and
`OnchainSigningPubKey` (raw secp256k1 pubkey) into every JD bundle for all chain
families. A new `SigningIdentityReader` registry lets each family declare which field
to read. `fetch_signing_keys` indexes all registered family variants from every bundle,
replacing the old cross-family keccak derivation in `signer_translation.go` (deleted).

## Why

Cross-family lanes need the NOP's signer in the destination verifier's native format.
EVM verifiers check 20-byte addresses; Canton verifiers check full pubkeys. JD stores
both; the reader selects the right one per family.

## Downstream changes

This PR introduces `SigningIdentityReader` — a new registry that replaces the old
direct read of `OnchainSigningAddress`. Chain product repos that need a non-EVM signer
format (e.g. Canton reads `OnchainSigningPubKey`) must register a reader. Address-class
families that use the same 20-byte EVM address also register so `fetch_signing_keys`
indexes their family key.

EVM is pre-registered. CCV and CCIP each have their own registry — register in both if
the family participates in CCV job specs and CCIP lane config.

### Canton example

```go
// deployment/adapters/signing_identity.go
type cantonSigningIdentityReader struct{}

func (cantonSigningIdentityReader) FromBundle(b *nodev1.OCR2Config_OCRKeyBundle) (string, error) {
    if b == nil || b.OnchainSigningPubKey == "" {
        return "", fmt.Errorf("missing OnchainSigningPubKey")
    }
    return b.OnchainSigningPubKey, nil
}

// deployment/adapters/init.go — register in both registries
ccvshared.RegisterSigningIdentityReader(chainsel.FamilyCanton, cantonSigningIdentityReader{})
ccipshared.RegisterSigningIdentityReader(chainsel.FamilyCanton, cantonSigningIdentityReader{})
```

## Migration

No manual migration needed. The bootstrapper pushes `OnchainSigningAddress` via
`UpdateNodeRequest` on every JD connect (startup/reconnect), so existing JD rows are
automatically updated to the EVM address format when nodes restart with the new code.
