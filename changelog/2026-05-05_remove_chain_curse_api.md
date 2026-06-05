# Remove `cciptestinterfaces.Chain` curse API; use `fastcurse` + shared CLDF env

## Executive Summary

- Removes `Curse`/`Uncurse` from the `build/devenv/cciptestinterfaces.Chain` interface and drops the CCIP17 EVM implementation of those methods.
- Consolidates curse operations in devenv tests around `chainlink-ccip/deployment/fastcurse` changesets, instead of direct RMN Remote contract calls.
- Updates `build/devenv.Lib` to construct and retain a CLDF `deployment.Environment` once, and exposes it via `(*Lib).CLDFEnvironment()`.
- Introduces a **breaking change** for any downstream code that previously invoked `Chain.Curse` / `Chain.Uncurse`.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `cciptestinterfaces.Chain.Curse` | removed | `\.Curse\(` | `build/devenv/cciptestinterfaces/interface.go:136` | [#chain-curse-removed](#chain-curse-removed) |
| `cciptestinterfaces.Chain.Uncurse` | removed | `\.Uncurse\(` | `build/devenv/cciptestinterfaces/interface.go:136` | [#chain-uncurse-removed](#chain-uncurse-removed) |
| `ccv.Lib.CLDFEnvironment` | added | `CLDFEnvironment\(` | `build/devenv/lib.go:101` | [#lib-cldfenvironment-added](#lib-cldfenvironment-added) |
| `generateExecutorJobSpecs` | signature-changed | `generateExecutorJobSpecs\(` | `build/devenv/environment.go:539` | [#generateexecutorjobspecs-signature](#generateexecutorjobspecs-signature) |
| `generateVerifierJobSpecs` | signature-changed | `generateVerifierJobSpecs\(` | `build/devenv/environment.go:616` | [#generateverifierjobspecs-signature](#generateverifierjobspecs-signature) |
| `e2e.curseSelector` | added | `curseSelector\(` | `build/devenv/tests/e2e/finality_reorg_curse_test.go:777` | [#e2e-curse-helpers](#e2e-curse-helpers) |
| `e2e.uncurseSelector` | added | `uncurseSelector\(` | `build/devenv/tests/e2e/finality_reorg_curse_test.go:793` | [#e2e-curse-helpers](#e2e-curse-helpers) |

## Breaking Changes

### Chain curse API removed

- **What changed:** `cciptestinterfaces.Chain` no longer includes `Curse(ctx, subjects)` / `Uncurse(ctx, subjects)`.
- **Before:** Consumers could call `impl.Curse(ctx, subjects)` / `impl.Uncurse(ctx, subjects)` on a chain implementation.
- **After:** Consumers must perform curse/uncurse via CCIP “fastcurse” changesets (see migration below) and an available CLDF `deployment.Environment`.
- **Why:** Centralizes curse operations behind changesets + adapter registry (and avoids embedding RMN Remote contract binding logic in the devenv chain impl).
- **Who is affected:** Any downstream repo code that calls `.Curse(` or `.Uncurse(` on objects implementing `cciptestinterfaces.Chain`.

## Migration Guide

1. Stop calling `cciptestinterfaces.Chain.Curse` / `.Uncurse`.
   - Find call sites by grepping for `\.Curse\(` and `\.Uncurse\(`.
2. Obtain a CLDF environment (`*deployment.Environment`).
   - If you already use `ccv.NewLib`, prefer `(*ccv.Lib).CLDFEnvironment()` (`build/devenv/lib.go:101`).
   - Otherwise construct one via `NewCLDFOperationsEnvironment(...)` (same function `NewLib` uses at `build/devenv/lib.go:44`).
3. Apply curses via `fastcurse` changesets.
   - Use the pattern implemented in `build/devenv/tests/e2e/finality_reorg_curse_test.go:777`.

### Example migration (test-style)

```go
// Before (no longer compiles)
err := srcImpl.Curse(ctx, subjects)
require.NoError(t, err)

// After
cldfEnv, err := lib.CLDFEnvironment()
require.NoError(t, err)

curseCS := fastcurse.CurseChangeset(fastcurse.GetCurseRegistry(), changesets.GetRegistry())
_, err = curseCS.Apply(*cldfEnv, fastcurse.RMNCurseConfig{
	CurseActions: []fastcurse.CurseActionInput{
		{
			ChainSelector:        srcImpl.ChainSelector(),
			SubjectChainSelector: destSelector, // 0 if global curse
			Version:              semver.MustParse("1.6.0"),
			IsGlobalCurse:        false, // true for global curse
		},
	},
})
require.NoError(t, err)
```

## New Features / Additions

- **`(*ccv.Lib).CLDFEnvironment()`** — returns the CLDF `*deployment.Environment` created during `ccv.NewLib(...)` initialization. See `build/devenv/lib.go:101`.
  - Usage: lets tests/tools reuse the same CLDF environment without rebuilding it inside `Chains()` or other call paths.

## Compatibility & Requirements *(optional)*

- Curse/uncurse operations now rely on the `chainlink-ccip` curse adapter registry. The e2e test ensures this is registered via a blank import:
  - `build/devenv/tests/e2e/finality_reorg_curse_test.go:17`

