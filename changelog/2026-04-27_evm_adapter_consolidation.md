# EVM adapter consolidation

## Summary

PRs:
* https://github.com/smartcontractkit/chainlink-ccv/pull/1054
* https://github.com/smartcontractkit/chainlink-ccip/pull/2009

All EVM-specific ccv adapter implementations have moved from `chainlink-ccv/evm`
into `chainlink-ccip/chains/evm/deployment/v2_0_0/adapters`. The `chainlink-ccv/evm`
module is now a thin init-only package responsible solely for chain-type registration
and EVM address normalization.

Three related changes accompany the move:

1. `ScanCommitteeStates` is no longer part of `AggregatorConfigAdapter` — it has
   moved to the new `CommitteeVerifierOnchainAdapter` interface alongside `ApplySignatureConfigs`.
2. The ccv adapter `Registry.Register` now **merges** rather than "first-wins", so
   two packages can each register disjoint fields for the same chain family without
   conflict.
3. Two new changesets — `increase_threshold` and `decrease_threshold` — drive
   `CommitteeVerifier` signature-config updates through the onchain adapter interface.

---

## Breaking change: `AggregatorConfigAdapter` no longer has `ScanCommitteeStates`

`ScanCommitteeStates` has been removed from `AggregatorConfigAdapter` and placed on
the new `CommitteeVerifierOnchainAdapter`:

```go
// deployment/adapters/aggregator_config.go
type AggregatorConfigAdapter interface {
    ResolveVerifierAddress(ds datastore.DataStore, chainSelector uint64, qualifier string) (string, error)
}

// deployment/adapters/committee_verifier_onchain.go
type CommitteeVerifierOnchainAdapter interface {
    ScanCommitteeStates(ctx context.Context, env deployment.Environment, chainSelector uint64) ([]*CommitteeState, error)
    ApplySignatureConfigs(ctx context.Context, env deployment.Environment, destChainSelector uint64, qualifier string, change SignatureConfigChange) error
}
```

`CommitteeVerifierOnchainAdapter` is a new field on `ChainAdapters`:

```go
type ChainAdapters struct {
    Aggregator               AggregatorConfigAdapter
    Executor                 ExecutorConfigAdapter
    Verifier                 VerifierConfigAdapter
    Indexer                  IndexerConfigAdapter
    TokenVerifier            TokenVerifierConfigAdapter
    CommitteeVerifierOnchain CommitteeVerifierOnchainAdapter  // new
}
```

**Action required:** any code calling `a.Aggregator.ScanCommitteeStates(...)` must
switch to `a.CommitteeVerifierOnchain.ScanCommitteeStates(...)`.

---

## Breaking change: `chainlink-ccv/evm` no longer registers EVM adapters

`chainlink-ccv/evm` no longer calls `adapters.GetRegistry().Register(...)`. The five
EVM adapter implementations (`Aggregator`, `Executor`, `Verifier`, `Indexer`,
`TokenVerifier`) were deleted from that module along with their go-ethereum and
gobinding dependencies.

Binaries that previously relied on `_ "github.com/smartcontractkit/chainlink-ccv/evm"`
to wire EVM adapters must now also import the ccip EVM adapters package:

```go
import (
    // Chain-type registration + address normalization (unchanged).
    _ "github.com/smartcontractkit/chainlink-ccv/evm"

    // EVM ccv adapter implementations + CommitteeVerifierOnchain (new requirement).
    _ "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/adapters"
)
```

The ccip package's `init()` registers all six EVM ccv adapters
(`Aggregator`, `Executor`, `Verifier`, `Indexer`, `TokenVerifier`,
`CommitteeVerifierOnchain`) into `ccvdeploymentadapters.GetRegistry()` in a single
merge call.

---

## Merge-style registry registration

`Registry.Register` previously used first-wins semantics. It now **merges**: non-nil
fields in the provided `ChainAdapters` overwrite the corresponding field in the
existing entry; nil fields are left unchanged.

This allows `chainlink-ccv/evm` and `chainlink-ccip/chains/evm` to each register
their slice of adapters independently without either clobbering the other:

```go
// chainlink-ccv/evm: chain-type and address normalization only (no adapter fields)

// chainlink-ccip/chains/evm init():
ccvdeploymentadapters.GetRegistry().Register(chainsel.FamilyEVM, ccvdeploymentadapters.ChainAdapters{
    Aggregator:               &EVMCCVAggregatorConfigAdapter{},
    Executor:                 &EVMCCVExecutorConfigAdapter{},
    Verifier:                 &EVMCCVVerifierConfigAdapter{},
    Indexer:                  &EVMCCVIndexerConfigAdapter{},
    TokenVerifier:            &EVMCCVTokenVerifierConfigAdapter{},
    CommitteeVerifierOnchain: &EVMCCVCommitteeVerifierOnchainAdapter{},
})
```

---

## New changesets: `increase_threshold` and `decrease_threshold`

Two new changesets in `deployment/changesets/` manage `CommitteeVerifier`
signature-config lifecycle using the `CommitteeVerifierOnchainAdapter`:

| Changeset | Purpose |
|-----------|---------|
| `IncreaseThreshold` | Adds source chains to a `CommitteeVerifier` or raises their threshold/signer set |
| `DecreaseThreshold` | Removes source chains from a `CommitteeVerifier` or reduces their threshold/signer set |

Both changesets read current on-chain state via `CommitteeVerifierOnchain.ScanCommitteeStates`
before computing and applying the delta, so they are safe to re-run idempotently.

---

## `chainlink-ccv/evm` go.mod footprint

As a result of removing the five adapter files, `chainlink-ccv/evm` shed its
`go-ethereum`, `Masterminds/semver`, and all EVM/crypto transitive dependencies.
The module's direct dependencies are now:

```
github.com/smartcontractkit/chain-selectors
github.com/smartcontractkit/chainlink-ccv/deployment
github.com/smartcontractkit/chainlink-protos/job-distributor
```
