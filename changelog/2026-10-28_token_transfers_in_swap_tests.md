# Send token transfers in the upgrade and rollback e2e tests

## Executive Summary

- `TestE2EUpgrade_HappyPath` and `TestE2ERollback_HappyPath` now send a USDC (CCTP) and a Lombard transfer after each step, together with the basic message.
- Before this change, no step used the token verifier, so its swap was not checked.
- Test change only. No runtime behavior changes.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `upgradeEnv.tokenPath` | added | `tokenPath` | `build/devenv/tests/e2e/upgrade_rolling_test.go` | [#token-transfers](#token-transfers) |
| `usdcEOACase`, `lombardEOACase` | added | `(usdc\|lombard)EOACase` | `build/devenv/tests/e2e/smoke_token_verification_test.go` | [#shared-cases](#shared-cases) |

## Breaking Changes

*No breaking changes.*

## New Features / Additions

### Token transfers

- After each step, the tests send one USDC transfer and one Lombard transfer between the first two EVM chains. Each transfer is a subtest (`USDC`, `Lombard`).
- The USDC transfer uses only the CCTP token verifier. The Lombard transfer uses the Lombard token verifier and the default committee verifier.
- The tests make new aggregator and indexer clients for each step, because a swap restarts these services.
- If the environment has no USDC or Lombard token, or fewer than two EVM chains, the test logs it and does not send that transfer.

### Shared cases

- `usdcEOACase` and `lombardEOACase` return the "EOA receiver with chain finality" cases. `TestE2ESmoke_TokenVerification` and the swap tests use them. The smoke test cases do not change.

## Compatibility & Requirements

- Each step sends three messages instead of one, so the tests take longer. Monitor the CI timeout of 30m.
