# Aggregator config: separate source vs destination verifier resolution

## Executive Summary

- Splits `AggregatorConfigAdapter` address resolution into two methods: source (quorum configs) and destination (`DestinationVerifiers` map).
- Allows chain families where the verifier contract used for source-side quorum metadata differs from the one used for destination-side entries (same selector can play both roles).
- Affects `github.com/smartcontractkit/chainlink-ccv/deployment/adapters` and all implementations of `AggregatorConfigAdapter` (including registrations in `chainlink-ccip/chains/evm` and similar).
- **Breaking:** `ResolveVerifierAddress` is removed from the interface; consumers must implement `ResolveSourceVerifierAddress` and `ResolveDestinationVerifierAddress`.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `adapters.AggregatorConfigAdapter.ResolveVerifierAddress` | removed | `\bResolveVerifierAddress\b` | — | [#aggregatorconfigadapter-resolver-split](#aggregatorconfigadapter-resolver-split) |
| `adapters.AggregatorConfigAdapter.ResolveSourceVerifierAddress` | added | `\bResolveSourceVerifierAddress\b` | `deployment/adapters/aggregator_config.go:36` | [#aggregatorconfigadapter-resolver-split](#aggregatorconfigadapter-resolver-split) |
| `adapters.AggregatorConfigAdapter.ResolveDestinationVerifierAddress` | added | `\bResolveDestinationVerifierAddress\b` | `deployment/adapters/aggregator_config.go:41` | [#aggregatorconfigadapter-resolver-split](#aggregatorconfigadapter-resolver-split) |
| `changesets.buildQuorumConfigs` | behavior-changed | `buildQuorumConfigs\b` | `deployment/changesets/generate_aggregator_config.go:257` | [#generate-aggregator-config-internal-wiring](#generate-aggregator-config-internal-wiring) |
| `changesets.buildDestinationVerifiers` | behavior-changed | `buildDestinationVerifiers\b` | `deployment/changesets/generate_aggregator_config.go:332` | [#generate-aggregator-config-internal-wiring](#generate-aggregator-config-internal-wiring) |

## Breaking Changes

### AggregatorConfigAdapter resolver split

- **What changed:** Interface method `ResolveVerifierAddress(ds, chainSelector, qualifier) (string, error)` replaced by two methods.
- **Before:** Single resolver used for both quorum `SourceVerifierAddress` and destination verifier map entries.
- **After:** `ResolveSourceVerifierAddress` feeds `model.QuorumConfig.SourceVerifierAddress`; `ResolveDestinationVerifierAddress` feeds `model.Committee.DestinationVerifiers`.
- **Why:** Some deployments need different verifier contract addresses for source vs destination semantics even when the CCIP chain selector is the same for both.
- **Who is affected:** Any type that implements `adapters.AggregatorConfigAdapter` and any fork that registers adapters against `adapters.Registry`.

### Generate-aggregator-config internal wiring

- **What changed:** Quorum building vs destination map building call different resolver methods.
- **Where:** `deployment/changesets/generate_aggregator_config.go` — `buildQuorumConfigs` uses `ResolveSourceVerifierAddress` at line 257; `buildDestinationVerifiers` uses `ResolveDestinationVerifierAddress` at line 332.
- **Who is affected:** Forks that vendor or patch `generate_aggregator_config.go` must keep those call sites aligned with adapter semantics.

## Migration Guide

1. Replace `ResolveVerifierAddress` with `ResolveSourceVerifierAddress` and `ResolveDestinationVerifierAddress` on every `AggregatorConfigAdapter` implementation.
2. If behavior should stay identical to pre-change: implement both methods by calling the previous single-resolution logic (duplicate body or shared private helper).
3. Update tests and stubs that embed or mock `AggregatorConfigAdapter` (pattern in `deployment/changesets/add_nop_to_committee_test.go` near `stubAggregatorAdapter` / `stubFullAdapter`).
4. Bump `github.com/smartcontractkit/chainlink-ccv/deployment` (and transitively `chainlink-ccip/chains/evm` / `chainlink-ccip/deployment` if your module pins them) so adapter implementations compile against the new interface.
5. Run `go test ./deployment/...` (and any package registering adapters) to catch missing interface methods.

When source and destination addresses should match, delegate both methods to one helper:

```go
func (a *Adapter) ResolveSourceVerifierAddress(ds datastore.DataStore, chainSelector uint64, qualifier string) (string, error) {
    return a.lookupVerifier(ds, chainSelector, qualifier)
}

func (a *Adapter) ResolveDestinationVerifierAddress(ds datastore.DataStore, chainSelector uint64, qualifier string) (string, error) {
    return a.lookupVerifier(ds, chainSelector, qualifier)
}
```

When they differ, split logic inside the two methods (same signatures as above).

```go
// Before (consumer implementing the old interface)
func (a *Adapter) ResolveVerifierAddress(ds datastore.DataStore, chainSelector uint64, qualifier string) (string, error) {
    return lookup(ds, chainSelector, qualifier)
}
```

```go
// After
func (a *Adapter) ResolveSourceVerifierAddress(ds datastore.DataStore, chainSelector uint64, qualifier string) (string, error) {
    return lookup(ds, chainSelector, qualifier)
}

func (a *Adapter) ResolveDestinationVerifierAddress(ds datastore.DataStore, chainSelector uint64, qualifier string) (string, error) {
    return lookup(ds, chainSelector, qualifier)
}
```

## New Features / Additions

- **Distinct source/destination verifier addresses in aggregator committee JSON** — Chain-specific adapters can now supply different addresses for quorum vs destination maps while keeping one selector. See `deployment/adapters/aggregator_config.go` and `deployment/changesets/generate_aggregator_config.go`.

## Compatibility & Requirements

- **Dependency bumps (devenv module):** `build/devenv/go.mod` updates pseudo-versions for:
  - `github.com/smartcontractkit/chainlink-ccip/chains/evm`
  - `github.com/smartcontractkit/chainlink-ccip/deployment`
  - `github.com/smartcontractkit/chainlink-ccv/deployment`
- Integrators using the CCIP EVM aggregator adapter must use a `chainlink-ccip` revision that implements the new interface methods alongside this `chainlink-ccv` revision.

## References

- Prior changelog this extends: `changelog/2026-04-27_evm_adapter_consolidation.md` (documents earlier `AggregatorConfigAdapter` shape with `ResolveVerifierAddress`).
- Diff basis: `git diff main` at branch tip (committed changes only; local unstaged edits are not reflected).
- Recent commits vs `main`: `a41224d7` (adapter split), `154c06f8` (dependency bumps), `fdf01423` (merge main).
