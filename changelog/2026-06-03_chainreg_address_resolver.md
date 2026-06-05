# Chainreg Address Resolver for TCAPI Contract Lookups

## Executive Summary

- Adds a per-chain-family `chainreg.AddressResolver` interface for resolving devenv test contract addresses (receiver, executor, committee CCV, token pool).
- Replaces EVM-specific `tcapi.GetContractAddress` call sites in TCAPI v3 test cases with family-aware resolver lookups through `chainreg`.
- Affects downstream product repos that resolve devenv contract addresses in tests — especially `chainlink-canton` e2e/load tests still calling `tcapi.GetContractAddress`, and any repo registering a new chain family for TCAPI.
- Introduces breaking changes: `tcapi.GetContractAddress` is removed; TCAPI v3 cases skip when a chain family lacks `AddressResolver`; `Run` now returns an error (instead of proceeding) when prerequisites are not met.

## AI Adapter Index

The expected consumer of this changelog is an AI adapting a downstream repo. This table is its entry point: every symbol or behavior touched gets one row, with a grep pattern for finding consumer call sites and an anchor into the rest of this file for migration detail. The AI is expected to:

1. Read this table.
2. Run each `Search` pattern against the consumer repo.
3. For rows that produce hits, read **only** the linked `Section`. Skip rows with zero hits.
4. Treat any symbol *not* listed here as unchanged — do not load source for it.

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `tcapi.GetContractAddress` | removed | `tcapi\.GetContractAddress\(` | — | [#getcontractaddress-removed](#getcontractaddress-removed) |
| `tcapi.TestCase.Run` | behavior-changed | `\.Run\(ctx\)|TestCase.*Run` | `build/devenv/tests/e2e/tcapi/types.go:38` | [#testcase-hydration-behavior](#testcase-hydration-behavior) |
| `tcapi.TestCase.HavePrerequisites` | behavior-changed | `HavePrerequisites\(ctx\)` | `build/devenv/tests/e2e/tcapi/types.go:46` | [#testcase-hydration-behavior](#testcase-hydration-behavior) |
| `tcapi.DefaultExecTimeout` | renamed | `DefaultExecTimeout` | `build/devenv/tests/e2e/tcapi/types.go:22` | [#timeout-constants-moved](#timeout-constants-moved) |
| `tcapi.DefaultSentTimeout` | renamed | `DefaultSentTimeout` | `build/devenv/tests/e2e/tcapi/types.go:23` | [#timeout-constants-moved](#timeout-constants-moved) |
| `chainreg.AddressResolver` | added | `chainreg\.AddressResolver\b` | `build/devenv/chainreg/types.go:90` | [#chainreg-addressresolver](#chainreg-addressresolver) |
| `chainreg.AddressResolver.GetContractReceiver` | added | `\.GetContractReceiver\(` | `build/devenv/chainreg/types.go:93` | [#chainreg-addressresolver](#chainreg-addressresolver) |
| `chainreg.AddressResolver.GetExecutor` | added | `\.GetExecutor\(` | `build/devenv/chainreg/types.go:96` | [#chainreg-addressresolver](#chainreg-addressresolver) |
| `chainreg.AddressResolver.GetCommitteeCCV` | added | `\.GetCommitteeCCV\(` | `build/devenv/chainreg/types.go:101` | [#chainreg-addressresolver](#chainreg-addressresolver) |
| `chainreg.AddressResolver.GetTokenPool` | added | `\.GetTokenPool\(` | `build/devenv/chainreg/types.go:104` | [#chainreg-addressresolver](#chainreg-addressresolver) |
| `chainreg.Registration.AddressResolver` | added | `Registration\{[^}]*AddressResolver|\.AddressResolver\b` | `build/devenv/chainreg/types.go:117` | [#registration-addressresolver-field](#registration-addressresolver-field) |
| `evm.AddressResolver` | added | `evm\.AddressResolver\b|build/devenv/evm/registration\.go.*AddressResolver` | `build/devenv/evm/registration.go:263` | [#evm-addressresolver-implementation](#evm-addressresolver-implementation) |

## Breaking Changes

### `GetContractAddress` removed

- **What changed:** `tcapi.GetContractAddress` and `build/devenv/tests/e2e/tcapi/contracts.go` were deleted.
- **Before:**
  ```go
  addr, err := tcapi.GetContractAddress(
      ds, chainSelector,
      datastore.ContractType(sequences.ExecutorProxyType),
      proxy.Deploy.Version(),
      common.DefaultExecutorQualifier,
      "executor",
  )
  ```
- **After:** resolve through the chain family's registered `AddressResolver`:
  ```go
  reg, err := chainreg.GetRegistry().Get(family)
  if err != nil {
      return err
  }
  addr, err := reg.AddressResolver.GetExecutor(ds, chainSelector, common.DefaultExecutorQualifier)
  ```
- **Why:** TCAPI test cases must work across chain families (EVM, Canton, Solana). Hard-coded EVM contract types and deployment versions belong in per-family registrations, not in shared TCAPI helpers.
- **Who is affected:** any downstream repo importing `tcapi.GetContractAddress`. Known call sites: `chainlink-canton/ccip/devenv/tests/e2e/evm2canton_e2e_test.go`, `canton2evm_e2e_test.go`, and `ccip/devenv/tests/load/load_helpers.go`.
- **Fallback:** if a consumer still needs the generic datastore lookup (contract type + version + qualifier) rather than the semantic `AddressResolver` methods, copy the removed helper into a local test helper package in their own repo. The full prior implementation is in [GetContractAddress removed helper source](#getcontractaddress-removed-helper-source); rename the function as needed (e.g. `getContractAddress`) to avoid colliding with family-specific helpers.

### TCAPI v3 cases require `AddressResolver` on both chain families

- **What changed:** `basic/v3` and `token_transfer/v3` hydrate functions look up `chainreg.GetRegistry().Get(family).AddressResolver` for both source and destination selectors. If either family has a nil `AddressResolver`, `HavePrerequisites` returns false and `Run` returns an error.
- **Before:** TCAPI cases resolved addresses with EVM-specific contract types regardless of chain family.
- **After:** each chain family must register an `AddressResolver` implementation for TCAPI cases involving that family to run.
- **Why:** contract address layout (type, version, qualifier semantics) is family-specific.
- **Who is affected:** product repos registering new chain families for devenv/TCAPI without implementing `AddressResolver`.

### TestCase hydration behavior

- **What changed:** TCAPI v3 implementations (`v3TestCase`, `tokenTransferV3TestCase`) cache hydration state. `Run` calls `ensureHydrated` and returns an error when prerequisites fail. `HavePrerequisites` performs the same hydration and returns false on failure; a successful call is reused by subsequent `Run`.
- **Before:** `Run` did not hydrate; callers were expected to call `HavePrerequisites` first. Hydration had no cached state.
- **After:** `Run(ctx)` is self-sufficient. Calling `HavePrerequisites(ctx)` before `Run(ctx)` is optional but recommended for skip-vs-fail semantics in test loops.
- **Why:** makes `Run` safe to call directly while preserving skip behavior via `HavePrerequisites`.
- **Who is affected:** callers that invoke `Run(ctx)` without a prior `HavePrerequisites(ctx)` check and expect a skip rather than a test failure.

## Migration Guide

1. Replace `tcapi.GetContractAddress` imports and calls. Preferred path: use `chainreg.AddressResolver` (steps 2–5). If you need ad-hoc lookups for contract types not covered by the resolver interface, copy the removed helper into your repo (see [removed helper source](#getcontractaddress-removed-helper-source) below) and update call sites to use your local copy.

2. Resolve the chain family from the selector, then use the registered resolver:

```go
// Before
ccvAddr, err := tcapi.GetContractAddress(
    ds, srcSelector,
    datastore.ContractType(versioned_verifier_resolver.CommitteeVerifierResolverType),
    versioned_verifier_resolver.Version.String(),
    common.DefaultCommitteeVerifierQualifier,
    "committee verifier proxy",
)

// After
srcFamily, err := chain_selectors.GetSelectorFamily(srcSelector)
if err != nil {
    return err
}
reg, err := chainreg.GetRegistry().Get(srcFamily)
if err != nil {
    return err
}
if reg.AddressResolver == nil {
    return fmt.Errorf("no AddressResolver for family %s", srcFamily)
}
ccvAddr, err := reg.AddressResolver.GetCommitteeCCV(ds, srcSelector, common.DefaultCommitteeVerifierQualifier)
```

3. Wrap CCV addresses into `protocol.CCV` when building message options (same as TCAPI internals):

```go
ccv := protocol.CCV{CCVAddress: ccvAddr, Args: []byte{}, ArgsLen: 0}
```

4. For product repos registering a new chain family, implement and register `AddressResolver`:

```go
// In product repo init(), alongside other chainreg fields:
if err := chainreg.Register(chainsel.FamilyCanton, chainreg.Registration{
    // ... existing fields ...
    AddressResolver: &CantonAddressResolver{},
}); err != nil {
    panic("canton chainreg: " + err.Error())
}
```

5. Implement the four resolver methods using that family's contract types and deployment versions. See `build/devenv/evm/registration.go:251` (`getContractAddress` helper) and `build/devenv/evm/registration.go:263` (`AddressResolver` methods) as the EVM reference.

6. Update test loops that only checked prerequisites implicitly via `Run` failure:

```go
// Recommended: skip when env lacks contracts
if tc.HavePrerequisites(ctx) {
    t.Run(tc.Name(), func(t *testing.T) {
        require.NoError(t, tc.Run(ctx))
    })
}

// Also valid: Run alone (fails the subtest instead of skipping)
require.NoError(t, tc.Run(ctx))
```

7. If importing timeout constants, note they moved from the deleted `contracts.go` to `types.go` — import path unchanged (`tcapi.DefaultExecTimeout`, `tcapi.DefaultSentTimeout`).

8. Run:
   ```sh
   go test ./...
   ```

### `GetContractAddress` removed helper source

Copy this into a local test helper package if you need the generic lookup outside `chainreg.AddressResolver`:

```go
import (
	"fmt"

	"github.com/Masterminds/semver/v3"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

// GetContractAddress returns the contract address for the given chain and contract reference.
func GetContractAddress(ds datastore.DataStore, chainSelector uint64, contractType datastore.ContractType, version, qualifier, contractName string) (protocol.UnknownAddress, error) {
	ref, err := ds.Addresses().Get(
		datastore.NewAddressRefKey(chainSelector, contractType, semver.MustParse(version), qualifier),
	)
	if err != nil {
		return protocol.UnknownAddress{}, fmt.Errorf("failed to get %s address for chain selector %d, ContractType: %s, ContractVersion: %s: %w",
			contractName, chainSelector, contractType, version, err)
	}
	return protocol.NewUnknownAddressFromHex(ref.Address)
}
```

## New Features / Additions

- **`chainreg.AddressResolver` interface** — family-scoped contract address resolution for devenv tests. See `build/devenv/chainreg/types.go:90`.
  - Usage: implement per chain family; TCAPI and downstream e2e tests resolve receiver, executor, committee CCV, and token pool addresses through it.

- **`chainreg.Registration.AddressResolver` field** — optional resolver attached to chain-family registration. See `build/devenv/chainreg/types.go:117`.
  - Usage: set alongside `ImplFactory`, `ExtraArgsSerializers`, etc. in product repo `init()`.

- **`evm.AddressResolver`** — EVM implementation using v2.0.0 devenv deployment contract types. See `build/devenv/evm/registration.go:263`.
  - Usage: registered automatically when `build/devenv/evm` is linked via `build/devenv/register.go`. Maps:
    - `GetContractReceiver` → `mock_receiver_v2` (`mock_receiver_v2.Deploy.Version()`)
    - `GetExecutor` → executor proxy (`executorops.Deploy.Version()`)
    - `GetCommitteeCCV` → committee verifier resolver proxy (`versioned_verifier_resolver.Version`)
    - `GetTokenPool` → pool address from `TokenCombination` address refs (`Type`, `Version`, `Qualifier`); no hardcoded contract type or version

- **TCAPI v3 `loadV3Env` helper** — loads datastore, destination chain, and source/destination resolvers for basic v3 hydration. See `build/devenv/tests/e2e/tcapi/basic/v3.go:177`.
  - Usage: internal to `basic/v3`; downstream repos should mirror the pattern (family lookup → resolver → method call) rather than importing unexported helpers.

- **TCAPI v3 `ensureHydrated` caching** — one-shot prerequisite hydration shared by `Run` and `HavePrerequisites`. See `build/devenv/tests/e2e/tcapi/basic/v3.go:49` and `build/devenv/tests/e2e/tcapi/token_transfer/v3.go:52`.
  - Usage: no caller action required; documents that repeated `Run`/`HavePrerequisites` calls do not re-query the datastore.

### Timeout constants moved

- **What changed:** `DefaultExecTimeout` and `DefaultSentTimeout` moved from deleted `tcapi/contracts.go` to `tcapi/types.go`.
- **Before:** defined in `build/devenv/tests/e2e/tcapi/contracts.go`.
- **After:** `build/devenv/tests/e2e/tcapi/types.go:22` and `build/devenv/tests/e2e/tcapi/types.go:23`.
- **Impact:** same package (`tcapi`); no import path change for existing consumers of these constants.

## Compatibility & Requirements

- **Minimum versions:** no Go version change.
- **Dependency bumps:** none in this diff.
- **Supported environments / chains:** EVM `AddressResolver` is registered in `build/devenv/evm/registration.go:59`. Non-EVM TCAPI cases (e.g. EVM↔Canton) require the non-EVM family to register its own `AddressResolver` or TCAPI cases will be skipped/fail prerequisites.
- **Feature flags / rollout:** no feature flag. EVM consumers get resolver behavior by linking `build/devenv/evm`; other families must opt in via `chainreg.Register`.

## Examples

```go
// Example: resolve executor and committee CCV for a cross-family test.
ds, err := lib.DataStore()
if err != nil {
    return err
}

srcFamily, err := chain_selectors.GetSelectorFamily(srcSelector)
if err != nil {
    return err
}
srcReg, err := chainreg.GetRegistry().Get(srcFamily)
if err != nil {
    return err
}

executor, err := srcReg.AddressResolver.GetExecutor(ds, srcSelector, common.DefaultExecutorQualifier)
if err != nil {
    return err
}

ccvAddr, err := srcReg.AddressResolver.GetCommitteeCCV(ds, srcSelector, common.DefaultCommitteeVerifierQualifier)
if err != nil {
    return err
}
ccvs := []protocol.CCV{{CCVAddress: ccvAddr, Args: []byte{}, ArgsLen: 0}}
```

```go
// Example: Canton product repo AddressResolver skeleton.
type CantonAddressResolver struct{}

func (CantonAddressResolver) GetContractReceiver(ds datastore.DataStore, chainSelector uint64, qualifier string) (protocol.UnknownAddress, error) {
    // lookup Canton receiver contract in ds for chainSelector + qualifier
    return protocol.UnknownAddress{}, nil
}

func (CantonAddressResolver) GetExecutor(ds datastore.DataStore, chainSelector uint64, qualifier string) (protocol.UnknownAddress, error) {
    return protocol.UnknownAddress{}, nil
}

func (CantonAddressResolver) GetCommitteeCCV(ds datastore.DataStore, chainSelector uint64, qualifier string) (protocol.UnknownAddress, error) {
    return protocol.UnknownAddress{}, nil
}

func (CantonAddressResolver) GetTokenPool(ds datastore.DataStore, chainSelector uint64, contractType datastore.ContractType, version *semver.Version, qualifier string) (protocol.UnknownAddress, error) {
    return protocol.UnknownAddress{}, nil
}
```

## References

- PR: https://github.com/smartcontractkit/chainlink-ccv/pull/1121
- Related issue: CCIP-10587
- Prior changelog entries this builds on: `changelog/2026-05-18_devenv_chainreg.md`, `changelog/2026-05-18_simplify_tcapi.md`
