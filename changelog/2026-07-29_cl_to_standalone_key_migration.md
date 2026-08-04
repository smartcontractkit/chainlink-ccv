# Adopting Chainlink node keys into a standalone keystore

## Summary

An EVM node operator running CCV as jobs on a Chainlink node can move to two standalone processes, a
verifier and an executor, keeping the identity anything outside the node depends on: the onchain
signing key registered in the `CommitteeVerifier` signer set. It does not have to be regenerated, so
the move needs no contract reconfiguration.

The verifier imports that signing key; the executor imports nothing. It runs a single fresh
transmitter key, funded during the cutover, in place of the node's per-chain accounts — so no gas is
moved and the operator's old accounts are left where they are.

The operator-facing surface is one exported file and a `[key_import]` block. The bootstrapper gained
that section, which adopts a key exported from a Chainlink node in place of generating one, and the
EVM accessor now reads a Chainlink node's own TOML config directly, so there is nothing to convert
and no tooling to run.

`docs/migration/evm-cl-to-standalone.md` is the operator procedure.

## New: `[key_import]` in the bootstrap config

```toml
[key_import]
path          = "/etc/ccv/migration/key.json"
password_path = "/etc/ccv/migration/export-password.txt"
expected_id   = "0x1234...abcd"
```

Two paths and a check, aimed at operators who are not going to enjoy a multi-step runbook. The
section names neither the keystore key nor the export format. An application declares exactly one
key it can import into — a verifier its signing key, an executor its transmitter key, never the CSA
key — so the target is unambiguous, and the format is read from the file (an OCR2 bundle declares
its chain type, an eth key carries an address). An application declaring two importable keys is an
error rather than a guess.

`expected_id` pins the address the export must carry, and is required: it is the check that fails
the boot when the wrong node's export is mounted — without it the process signs with another
operator's key, which the committee rejects with nothing in the logs pointing at the cause.

The import runs only when the key is absent, so it is a no-op on restart and the exported files can
be unmounted once the process has come up once.

## New: `ccv migrate export` and `ccv migrate inspect`

The verifier image ships a `ccv migrate` command group that replaces the manual half of the key
export. Only the verifier's signing key is exported, so the executor image does not carry it. `ccv
migrate export` talks to the node's API and, in one command: runs the
one-verifier-job preflight, resolves the EVM OCR2 bundle from the node's own listing (the same source
the node's JD chain config was built from), exports it under a generated password, verifies the
export decodes to the identity the node registered, and writes a ready-made `[key_import]` snippet
with `expected_id` already filled in. The operator never transcribes a bundle ID, an address, or a
password. `ccv migrate inspect` prints the identity a mounted export carries, so a wrong-node mount
is caught before boot rather than by a process refusing to start.

The client is a four-endpoint REST client in `cli/migrate`, not the Chainlink SDK or the testing
framework: those live in the devenv module, and importing either would drag the node dependency
graph into the production binaries.

## The EVM config needs no conversion

The standalone EVM accessor accepts a Chainlink node's own TOML directly. `loadConfig` tells the two
formats apart by their top-level table — `chains` is the standalone format, `EVM` is a node config —
and translates the latter at startup, resolving chain IDs to chain selectors. An operator mounts the
file their node already runs with.

The node's chain defaults are applied before finality is translated, so a chain the operator never
configured explicitly keeps the behavior it had instead of moving onto finality tags. Send-only
nodes, `Order`, `HTTPURLExtraWrite` and `IsLoadBalancedRPC` have no standalone equivalent and are
dropped, each logged at warn so nothing goes missing quietly.

## The CSA key is not exported

JD identifies a node by the CSA key it authenticates with, so preserving a node operator's JD record
looks like it needs the CSA private key moved as well. It does not: `UpdateNodeRequest` carries a
`public_key`, so the existing record is repointed at the standalone verifier's own CSA key. The node
ID, the NOP alias, and the job history are preserved, and the key stays on the machine that
generated it.

This is why the Chainlink node must be stopped before the standalone verifier starts. One JD record
cannot have two owners.

## One JD record becomes two

A CL-mode node runs the `ccvcommitteeverifier` and `ccvexecutor` jobs under a single JD record.
Standalone runs two processes with two keystores, so it needs two. The verifier adopts the operator's
existing record, keeping the NOP alias that `ApplyVerifierConfig` and `fetch_signing_keys` look it up
by; the executor registers a new one. Reusing the record for the verifier rather than registering a
second is what avoids a duplicate entry for the operator alongside an abandoned one.

The two processes differ in what they carry across. The verifier imports the node's signing key. The
executor imports nothing: it generates a fresh transmitter key that the cutover funds, one account in
place of the node's per-chain transmitters. That is the single-key executor a live deployment runs,
brought up per operator here rather than centrally.

## Implementation notes

The OCR2 export is decoded in `bootstrap/keys` rather than through
`chainlink-common/keystore/corekeys/ocr2key`. That package's `FromEncryptedJSON` switches over every
supported chain type, so importing it would link the Cosmos, Solana, Starknet and TON keyrings, and
their module requirements, into both binaries. The decoder reads the export format directly, which
is a serialization contract for files already on operator disks rather than an API that can move.

Every import cross-checks the extracted key against the identity the export publishes before the key
reaches the keystore, so a bundle that did not decode as expected fails rather than importing a key
that signs as somebody else.
