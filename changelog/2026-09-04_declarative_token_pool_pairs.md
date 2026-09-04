# Declarative token pool pairs for test target resolution

## Executive Summary

- Adds a `[[token_pool_pairs]]` TOML section that declares which token pool lanes the tests must run, instead of tests guessing lanes from datastore refs.
- Fixes a real failure mode: pool qualifiers are unique per chain only, so opposite lanes of one pairing share the same qualifier string. Ref-based pairing therefore stitched lanes from opposite directions, and tests sent transfers on tokens that deploy never registered (`UnsupportedToken` on `GetFee`).
- Affects `build/devenv` consumers: `ConfigureAllTokenTransfers` returns the configured pairs, and both devenv writers (phased and monolith) serialize them into the env toml.
- Envs without the section keep the existing catalog + filter fallback, so pre-existing tomls keep working.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
| --- | --- | --- | --- | --- |
| `devenvcommon.NewTokenCombinationFromRefs` | removed | `\bNewTokenCombinationFromRefs\b` | — | [#newtokencombinationfromrefs-removed](#newtokencombinationfromrefs-removed) |
| `ccdeploy.ConfigureAllTokenTransfers` | signature-changed | `ConfigureAllTokenTransfers\(` | `build/devenv/deploy/deploy.go:393` | [#configurealltokentransfers-signature](#configurealltokentransfers-signature) |
| `devenvcommon.TokenCombinationsFromPoolPairs` | added | `TokenCombinationsFromPoolPairs\(` | `build/devenv/common/token_pool_pairs.go:42` | [#new-features--additions](#new-features--additions) |
| `devenvcommon.TokenPoolPair` | added | `devenvcommon\.TokenPoolPair\b` | `build/devenv/common/token_pool_pairs.go:28` | [#new-features--additions](#new-features--additions) |
| `devenvcommon.TokenPoolRefCfg` | added | `devenvcommon\.TokenPoolRefCfg\b` | `build/devenv/common/token_pool_pairs.go:16` | [#new-features--additions](#new-features--additions) |
| `ccv.Cfg.TokenPoolPairs` | added | `TokenPoolPairs\b` | `build/devenv/environment.go:180` | [#new-features--additions](#new-features--additions) |
| `[[token_pool_pairs]]` env toml section | behavior-changed | `token_pool_pairs` | `build/devenv/environment_monolith.go:477` | [#new-features--additions](#new-features--additions) |

## Breaking Changes

### `ConfigureAllTokenTransfers` signature

- **What changed:** the function now returns `([]devenvcommon.TokenPoolPair, error)` instead of `error`.
- **Before:** `func ConfigureAllTokenTransfers(impls, selectors, env, topology) error`.
- **After:** the same arguments plus a `([]devenvcommon.TokenPoolPair, error)` return. A nil-version pool ref in a token transfer config is now a named error, not a silent skip.
- **Why:** deploy must publish the lanes it configured, so tests can resolve test targets from declarations instead of ref inference.
- **Who is affected:** callers inside `build/devenv` only. A repo-wide search found no callers outside devenv.

### `NewTokenCombinationFromRefs` removed

- **What changed:** the helper added for datastore-ref combos in the previous devenv PR is gone from the public surface.
- **Why:** single consumer; the pair reader builds combinations directly, and the helper dropped `ChainSelector`, which made ref-based direction filters fail silently.
- **Who is affected:** code that resolved combos from raw refs. Use `TokenCombinationsFromPoolPairs` with declared pairs instead.

## Migration Guide

1. If you called `ConfigureAllTokenTransfers`, accept the new first return value or discard it with `_`.
2. If you resolved test combinations from datastore refs, declare the lanes in `[[token_pool_pairs]]` and read them with `TokenCombinationsFromPoolPairs`.
3. No action is needed for env toml consumers: the new section is optional, and `ccv.LoadOutput[ccv.Cfg]` decodes it when present.

## New Features / Additions

- **`[[token_pool_pairs]]` section** — one record per directional lane: `local_selector`, `remote_selector`, one pool leg per side (`type`, `version`, `qualifier`), and `ccv_qualifiers`. See `build/devenv/common/token_pool_pairs.go`.
  - Qualifiers are copied verbatim from the `[[addresses]]` entries and matched exactly. No pattern or prefix matching remains in test resolution.
  - Selectors are strings: the values exceed the range of the integers TOML decodes.
  - `ccv_qualifiers` is `["default"]` when either side is version 2.0.0 or above, and `[]` for legacy lanes.
- **Both devenv writers emit the section.** The phased runtime publishes it through the component output map; the monolith path assigns `Cfg.TokenPoolPairs` before the env file store. Deployed (non-devenv) environments do not run devenv deploy, so their env tomls carry hand-written sections, validated by exact-match named errors.
- **Tests resolve test targets from declarations.** One test file now runs against a local devenv and against a deployed environment toml. The token identity per lane still comes from the `[[addresses]]` datastore: the reader derives token refs from pool refs by qualifier.

## Compatibility & Requirements

- **Rollout:** sections are optional. Envs without `[[token_pool_pairs]]` keep the curated catalog plus datastore filter fallback. This covers env tomls generated before this change.
- **Related config-driven deploy work:** declaring one lane (or no lanes for messaging-only runs) also gives deploy a way to deploy only the test targets, instead of the full token mesh.

## Examples

```toml
# Declared lane: exact pool legs per side, selectors as strings.
[[token_pool_pairs]]
local_selector = "14767482510784806043"
remote_selector = "16423721717087811551"
local_pool = { type = "BurnMintTokenPool", version = "2.0.0", qualifier = "TEST (BurnMintTokenPool 1.6.1 [], BurnMintTokenPool 2.0.0 [])::BurnMintTokenPool 2.0.0 []" }
remote_pool = { type = "BurnMintTokenPool", version = "1.6.1", qualifier = "TEST (BurnMintTokenPool 1.6.1 [], BurnMintTokenPool 2.0.0 [])::BurnMintTokenPool 1.6.1 []" }
ccv_qualifiers = ["default"]
```

## Long-term direction

- The declaration lives in the ccv-owned env toml because the CLD datastore refs alone do not carry pairing intent. Token metadata is inconsistent across chains, and qualifiers collide for opposite lanes, so automated discovery from refs is not sound.
- Long term, CLD primitives can carry this data natively: a token-expansion changeset can persist the lane pairing in the deployment datastore as a first-class record. Every `deployment.Environment` has a datastore, so test configs become portable to environments with no devenv toml. The toml section then stays the devenv serialization of that record.

## References

- PR: <https://github.com/smartcontractkit/chainlink-ccv/pull/1405>
- Prior devenv helper PR: <https://github.com/smartcontractkit/chainlink-ccv/pull/1398>
- Consumer PR (tests read the declared pairs): <https://github.com/smartcontractkit/chainlink-ccip-solana/pull/414>
- Builds on the phased runtime entry: `2026-05-07_phased_devenv_runtime.md`
