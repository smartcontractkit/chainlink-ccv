# Simplify TCAPI test cases around `ccv.Lib`

## Executive Summary

- Refactors e2e TCAPI test cases so each case stores a `ccv.Lib` plus source/destination chain selectors and can run itself with only `Run(ctx)`.
- Removes the `tcapi.TestHarness` setup layer from the public test API; callers now construct `ccv.Lib` directly and fetch aggregators/indexer monitors from it.
- Affects `build/devenv/tests/e2e/tcapi`, `basic` v3 messaging cases, token-transfer v3 cases, smoke tests, replay CLI tests, and composable EVM POC tests.
- Introduces breaking changes for downstream tests that instantiate TCAPI cases, call `TestCase.Run`, call `NewTestHarness`, or use `tcapi.GetContractAddress` with `*ccv.Cfg`.

## AI Adapter Index

The expected consumer of this changelog is an AI adapting a downstream repo. This table is its entry point: every symbol or behavior touched gets one row, with a grep pattern for finding consumer call sites and an anchor into the rest of this file for migration detail. The AI is expected to:

1. Read this table.
2. Run each `Search` pattern against the consumer repo.
3. For rows that produce hits, read **only** the linked `Section`. Skip rows with zero hits.
4. Treat any symbol *not* listed here as unchanged - do not load source for it.

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `tcapi.TestCase.Run` | signature-changed | `\.Run\(.*TestHarness|\.Run\(.*cfg|\.Run\(.*ccvCfg|\.Run\(ctx,\s*` | `build/devenv/tests/e2e/tcapi/types.go:27` | [#testcase-run-signature](#testcase-run-signature) |
| `tcapi.TestCase.HavePrerequisites` | signature-changed | `HavePrerequisites\(` | `build/devenv/tests/e2e/tcapi/types.go:31` | [#testcase-prerequisites-signature](#testcase-prerequisites-signature) |
| `tcapi.TestHarness` | removed | `\bTestHarness\b` | - | [#testharness-removed](#testharness-removed) |
| `tcapi.NewTestHarness` | removed | `NewTestHarness\(` | - | [#testharness-removed](#testharness-removed) |
| `tcapi.SetupAggregatorClients` | removed | `SetupAggregatorClients\(` | - | [#testharness-removed](#testharness-removed) |
| `tcapi.SetupIndexerMonitor` / `tcapi.SetupAllIndexerMonitors` | removed | `Setup(All)?IndexerMonitor(s)?\(` | - | [#testharness-removed](#testharness-removed) |
| `basic.*` TCAPI constructors | signature-changed | `(basic\.)?(CustomExecutor|EOAReceiverDefaultVerifier|EOAReceiverSecondaryVerifier|ReceiverSecondaryVerifierRequired|ReceiverSecondaryRequiredTertiaryOptionalThreshold1|ReceiverQuaternaryAllThreeVerifiers|ReceiverQuaternaryDefaultAndSecondary|ReceiverQuaternaryDefaultAndTertiary|MaxDataSize|EOAReceiverDefaultVerifier_SafeTag|All)\(` | `build/devenv/tests/e2e/tcapi/basic/v3.go:151` | [#basic-v3-constructor-signatures](#basic-v3-constructor-signatures) |
| `token_transfer.TokenTransfer` | signature-changed | `TokenTransfer\(` | `build/devenv/tests/e2e/tcapi/token_transfer/v3.go:185` | [#token-transfer-v3-constructor-signatures](#token-transfer-v3-constructor-signatures) |
| `token_transfer.All` / `token_transfer.All17` | signature-changed | `token_transfer\.All(17)?\(` | `build/devenv/tests/e2e/tcapi/token_transfer/v3.go:252` | [#token-transfer-v3-constructor-signatures](#token-transfer-v3-constructor-signatures) |
| `tcapi.GetContractAddress` | signature-changed | `GetContractAddress\(` | `build/devenv/tests/e2e/tcapi/contracts.go:18` | [#getcontractaddress-datastore-signature](#getcontractaddress-datastore-signature) |
| `ccv.Lib.IndexerMonitor` | added | `\.IndexerMonitor\(` | `build/devenv/lib.go:55` | [#lib-indexer-and-aggregator-clients](#lib-indexer-and-aggregator-clients) |
| `ccv.Lib.AllAggregators` | added | `\.AllAggregators\(` | `build/devenv/lib.go:63` | [#lib-indexer-and-aggregator-clients](#lib-indexer-and-aggregator-clients) |

## Breaking Changes

### `TestCase.Run` signature

- **What changed:** `tcapi.TestCase.Run` now takes only `context.Context`.
- **Before:** `Run(ctx context.Context, harness tcapi.TestHarness, cfg *ccv.Cfg) error`.
- **After:** `Run(ctx context.Context) error`.
- **Why:** TCAPI cases now carry `ccv.Lib` and chain selectors internally, and resolve chains, aggregators, indexer monitors, and datastore access from that `Lib` at runtime.
- **Who is affected:** Downstream smoke/e2e tests that construct TCAPI cases and pass a `TestHarness` or `*ccv.Cfg` into `Run`.

### `TestCase.HavePrerequisites` signature

- **What changed:** `HavePrerequisites` no longer accepts `*ccv.Cfg`.
- **Before:** `HavePrerequisites(ctx context.Context, cfg *ccv.Cfg) bool`.
- **After:** `HavePrerequisites(ctx context.Context) bool`.
- **Why:** Prerequisite hydration now uses `tc.lib.DataStore()` and `tc.lib.ChainsMap(ctx)` instead of directly reading `Cfg`.
- **Who is affected:** Callers that skip or select test cases by calling `HavePrerequisites(ctx, cfg)`.

### `TestHarness` removed

- **What changed:** `tcapi.TestHarness`, `NewTestHarness`, `SetupAggregatorClients`, `SetupIndexerMonitor`, and `SetupAllIndexerMonitors` were removed from `tcapi/types.go`.
- **Before:** Callers loaded `ccv.Cfg`, built a `tcapi.TestHarness`, then passed `harness` and `cfg` into every `TestCase.Run`.
- **After:** Callers construct `ccv.Lib` directly with `ccv.NewLibFromCCVEnv`, pass that `Lib` into TCAPI case constructors, and call `tc.Run(ctx)`.
- **Why:** The harness duplicated client setup already available from `ccv.Lib`; moving client construction into `Lib` gives test cases one environment abstraction.
- **Who is affected:** Any consumer using the old harness type or setup helpers.

### Basic v3 constructor signatures

- **What changed:** Basic v3 case constructors now take `lib ccv.Lib, src uint64, dest uint64` instead of concrete `cciptestinterfaces.CCIP17` source/destination values.
- **Before:** `basic.All(src, dest cciptestinterfaces.CCIP17)` and individual constructors such as `basic.CustomExecutor(src, dest)`.
- **After:** `basic.All(lib, srcSelector, destSelector)` and individual constructors such as `basic.CustomExecutor(lib, srcSelector, destSelector)`.
- **Why:** Cases need `Lib` access for datastore, aggregator clients, indexer monitor, and selector-to-chain lookup during `Run` / `HavePrerequisites`.
- **Who is affected:** Callers that instantiate `basic` package TCAPI cases directly.

### Token-transfer v3 constructor signatures

- **What changed:** Token-transfer v3 case constructors now take `lib ccv.Lib, src uint64, dest uint64` instead of concrete `cciptestinterfaces.CCIP17` source/destination values.
- **Before:** `token_transfer.All(src, dest, combos)`, `token_transfer.All17(src, dest, combos)`, and `TokenTransfer(src, dest, combo, finality, useEOA, name)`.
- **After:** `token_transfer.All(lib, srcSelector, destSelector, combos)`, `token_transfer.All17(lib, srcSelector, destSelector, combos)`, and `TokenTransfer(lib, srcSelector, destSelector, combo, finality, useEOA, name)`.
- **Why:** Same as basic v3 cases: cases now self-resolve chains and services from `ccv.Lib`.
- **Who is affected:** Callers that instantiate `token_transfer` package TCAPI cases directly.

### `GetContractAddress` datastore signature

- **What changed:** `tcapi.GetContractAddress` now accepts `datastore.DataStore` directly.
- **Before:** `GetContractAddress(ccvCfg *ccv.Cfg, chainSelector uint64, ...)`.
- **After:** `GetContractAddress(ds datastore.DataStore, chainSelector uint64, ...)`.
- **Why:** TCAPI code no longer depends on `ccv.Cfg`; callers can obtain the store from `lib.DataStore()` or any CLDF-backed environment.
- **Who is affected:** Callers that pass `*ccv.Cfg` to `tcapi.GetContractAddress`.

## Migration Guide

1. Replace harness setup with direct `ccv.Lib` construction:

```go
// Before
cfg, err := ccv.LoadOutput[ccv.Cfg](envOutPath)
if err != nil {
	return err
}
harness, err := tcapi.NewTestHarness(ctx, envOutPath, cfg, chain_selectors.FamilyEVM)
if err != nil {
	return err
}

// After
lib, err := ccv.NewLibFromCCVEnv(&ccv.Plog, envOutPath)
if err != nil {
	return err
}
```

2. Pass `lib` and chain selectors into TCAPI constructors:

```go
// Before
chains, err := harness.Lib.Chains(ctx)
src, dest := chains[0].CCIP17, chains[1].CCIP17
cases := basic.All(src, dest)

// After
chains, err := lib.Chains(ctx)
src, dest := chains[0].CCIP17, chains[1].CCIP17
cases := basic.All(lib, src.ChainSelector(), dest.ChainSelector())
```

3. Update case execution and prerequisite checks:

```go
// Before
if tc.HavePrerequisites(ctx, cfg) {
	err := tc.Run(ctx, harness, cfg)
}

// After
if tc.HavePrerequisites(ctx) {
	err := tc.Run(ctx)
}
```

4. Replace direct harness client usage with `ccv.Lib` methods:

```go
aggregators, err := lib.AllAggregators()
aggregatorClient := aggregators[common.DefaultCommitteeVerifierQualifier]

indexerMonitor, err := lib.IndexerMonitor()

chainMap, err := lib.ChainsMap(ctx)
testCtx, cleanupFn := tcapi.NewTestingContext(ctx, chainMap, aggregatorClient, indexerMonitor)
defer cleanupFn()
```

5. Update `GetContractAddress` callers:

```go
// Before
addr, err := tcapi.GetContractAddress(cfg, selector, contractType, version, qualifier, name)

// After
ds, err := lib.DataStore()
if err != nil {
	return err
}
addr, err := tcapi.GetContractAddress(ds, selector, contractType, version, qualifier, name)
```

## New Features / Additions

- **`ccv.Lib.IndexerMonitor`** - returns a new `*ccv.IndexerMonitor` for the first available indexer client. See `build/devenv/lib.go:55` and `build/devenv/lib.go:183`.
  - Usage: replace `tcapi.SetupIndexerMonitor(ctx, lib)` or `harness.IndexerMonitor` in e2e tests.
- **`ccv.Lib.AllAggregators`** - returns a map of aggregator qualifier to `*ccv.AggregatorClient`. See `build/devenv/lib.go:63` and `build/devenv/lib.go:136`.
  - Usage: replace `tcapi.SetupAggregatorClients(ctx, cfg)` or `harness.AggregatorClients`.
- **`tcapi.TestCase.HavePrerequisites` on the interface** - makes prerequisite checks part of every TCAPI test case contract. See `build/devenv/tests/e2e/tcapi/types.go:31`.
  - Usage: call before `Run(ctx)` to skip cases when the current env lacks required contracts or services.

## Compatibility & Requirements

- **CLDF-only `Lib`:** `libFromCLDF` now implements `IndexerMonitor` and `AllAggregators`, but both return errors because raw CLDF environments do not carry indexer or aggregator endpoints. TCAPI cases that assert messages still require a CCV-env-backed `Lib` from `NewLibFromCCVEnv`.
- **Chain selection:** Constructors now store selectors, not chain instances. Existing callers that previously passed `chains[0].CCIP17` / `chains[1].CCIP17` should pass `chains[0].CCIP17.ChainSelector()` / `chains[1].CCIP17.ChainSelector()`.
- **Working tree note:** The branch diff includes an e2e composable messaging refactor to use `ccv.NewLibFromCCVEnv` directly. The local working tree also has an uncommitted fix adding `require.NoError(t, err)` after `NewLibFromCCVEnv` in `build/devenv/tests/composable/messaging/evmPOC_test.go`.

## Examples

```go
func TestE2ESmoke_Basic(t *testing.T) {
	ctx := ccv.Plog.WithContext(t.Context())

	lib, err := ccv.NewLibFromCCVEnv(&ccv.Plog, GetSmokeTestConfig())
	require.NoError(t, err)

	chains, err := lib.Chains(ctx)
	require.NoError(t, err)
	src, dest := chains[0].CCIP17, chains[1].CCIP17

	for _, tc := range basic.All(lib, src.ChainSelector(), dest.ChainSelector()) {
		if tc.HavePrerequisites(ctx) {
			t.Run(tc.Name(), func(t *testing.T) {
				require.NoError(t, tc.Run(ccv.Plog.WithContext(t.Context())))
			})
		}
	}
}
```

## References

- Commit: `0a0d87df tcapi: simplify TestCase interface`
- Prior related entry: `changelog/2026-05-15_devenv_lib_implfactory_cldf_clients.md`
