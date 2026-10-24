# Shared chain-agnostic JD node registration

## Executive Summary

- Adds `deployment/registration`, a reusable JD identity-registration package for CSA key resolution, conflict-safe registration, label reconciliation, and connection waiting.
- Migrates normal devenv verifier, executor, Chainlink-node, monolith, phased, and migration registration paths to the shared implementation.
- Keeps chain-family concerns outside the package: there are no chain selectors, OCR bundles, signing/transmitter operations, or EVM/Solana/Canton imports.
- Leaves CLD environment state and deliberate CL-to-standalone key adoption outside this change.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `registration.CSAKeyProvider` | added | `CSAKeyProvider` | `deployment/registration/key_provider.go:26` | [#shared-registration-package](#shared-registration-package) |
| `registration.InfoServerCSAKeyProvider` | added | `InfoServerCSAKeyProvider` | `deployment/registration/key_provider.go:41` | [#bootstrap-key-providers](#bootstrap-key-providers) |
| `registration.FetchPublicKeys` | added | `FetchPublicKeys\(` | `deployment/registration/key_provider.go:55` | [#bootstrap-key-providers](#bootstrap-key-providers) |
| `registration.DefaultCSAKeyName`, `registration.GetKeysEndpoint` | added | `registration\.(DefaultCSAKeyName|GetKeysEndpoint)` | `deployment/registration/api.go:4` | [#bootstrap-key-providers](#bootstrap-key-providers) |
| `registration.NodeSpec` | added | `registration\.NodeSpec` | `deployment/registration/types.go:20` | [#shared-registration-package](#shared-registration-package) |
| `registration.Register` | added | `registration\.Register\(` | `deployment/registration/register.go:23` | [#shared-registration-package](#shared-registration-package) |
| `registration.RegisterAndWait` | added | `RegisterAndWait\(` | `deployment/registration/register.go:102` | [#shared-registration-package](#shared-registration-package) |
| `registration.WaitForConnection` | added | `WaitForConnection\(` | `deployment/registration/connection.go:12` | [#shared-registration-package](#shared-registration-package) |
| `jobs.DevenvNodeSpec` | added | `DevenvNodeSpec\(` | `build/devenv/jobs/bootstrap_registration.go:33` | [#devenv-adapters](#devenv-adapters) |
| `jobs.CSAKeyProvider` | behavior-changed | `jobs\.CSAKeyProvider` | `build/devenv/jobs/bootstrap_registration.go:27` | [#devenv-adapters](#devenv-adapters) |

## Shared registration package

`deployment/registration` accepts a narrow JD client interface already satisfied by the framework's `offchain.Client`. `NodeSpec` supplies the node name, product, environment, bootstrap/plugin type, and caller labels. `Result` reports the JD node ID, registered/existing status, and whether labels were reconciled.

`Register`:

- Resolves and validates a 32-byte hex-encoded Ed25519 CSA public key.
- Handles direct JD `NotFound` responses and the production `Internal` response wrapping `code = NotFound`.
- Returns an existing matching node without creating a duplicate and reconciles `AlreadyExists` races by re-reading the CSA record.
- Reconciles missing or changed managed/caller labels without changing the node name, CSA key, or unrelated labels.
- Rejects same-name/different-key and same-key/different-name conflicts without mutating JD, including legacy unlabeled or differently scoped records.
- Registers missing nodes with deterministic `product`, `environment`, and `type=bootstrap|plugin` labels plus sorted caller labels.
- Validates returned identities and labels, rejecting malformed input, non-NotFound JD failures, and invalid JD responses.

`RegisterAndWait` combines registration with a bounded connection wait and preserves the registration result when the wait fails. `WaitForConnection` is also available independently for CL nodes whose JD connection is configured after registration.

## Bootstrap key providers

`StaticCSAKeyProvider` adapts an already resolved public key. `InfoServerCSAKeyProvider` resolves the CSA key through the bootstrap info server. `FetchPublicKeys` returns raw public-key bytes by requested key name and does not interpret chain-specific key types.

The HTTP implementation uses caller context, an injectable client, URL/status/JSON validation, a default timeout, and a bounded response body. It never requests or logs private key material.

The registration package exports matching `DefaultCSAKeyName` and `GetKeysEndpoint` constants so deployment-module consumers do not need a newer root module. Existing `bootstrap` constants remain unchanged, and a devenv contract test keeps the two API declarations synchronized without introducing a module dependency cycle or the full bootstrap runtime dependency graph.

## Devenv adapters

Existing exported devenv registration entry points remain available as thin adapters. `jobs.CSAKeyProvider` and `jobs.BootstrapCSAKeyProvider` alias the shared provider types. `jobs.DevenvNodeSpec` centralizes normal devenv metadata: `product=ccv`, `environment=devenv`, and `type=plugin`.

Normal registration is now idempotent and label-aware across:

- Standalone verifier and executor registration in monolith and phased environments.
- Chainlink-node registration.
- New standalone executor registration during CL-to-standalone migration.
- Shared JD connection waits.

`services.FetchBootstrapKeys` retains its API and chain-specific output derivations but delegates HTTP retrieval to `registration.FetchPublicKeys`.

The deliberate `AdoptJDIdentity` verifier CSA handoff is unchanged. It is a migration-specific key adoption, not normal idempotent registration.

## Breaking Changes

No breaking changes.

Existing devenv APIs remain, but normal registration behavior is stronger: matching existing records return their ID instead of producing an `AlreadyExists` error, label drift can be reconciled, and identity conflicts fail explicitly.

## Migration Guide

For a CLD or provisioning adapter:

1. Pass the authenticated framework JD client to `registration.Register` or `registration.RegisterAndWait`.
2. Translate environment input into `registration.NodeSpec`; use `StaticCSAKeyProvider` for a manual `csa_key` input or `InfoServerCSAKeyProvider` when the bootstrap endpoint is available.
3. Map `Result.Status` and `Result.NodeID` to the adapter's output. `Result.LabelsReconciled` distinguishes a label update from an unchanged rerun.
4. Keep environment-specific node-state persistence in the adapter. This package does not read or write CLD `nodes.json` and does not embed registration in verifier/executor job-management changesets.
5. Use `Register` without a wait when a CL node still needs its JD connection configured; use `RegisterAndWait` for standalone processes that connect immediately.

## Compatibility & Requirements

- Uses the existing `chainlink-protos/job-distributor` and `chainlink-common/keystore` dependencies; no new third-party library is introduced.
- `deployment/go.mod` moves `chainlink-common/keystore` from indirect to direct.
- Unit coverage includes providers, registration, idempotency, conflicts, label updates, production error mapping, invalid responses, and connection deadlines.
- `TestE2ESmoke_Basic` checks real-JD registration, HTTP key resolution, labels, connectivity, idempotent reruns, and conflict rejection alongside the existing message smoke coverage. `ccv test smoke-jd-registration` selects the same assertions directly; CL-only and no-JD profiles skip only when no standalone services are declared.

## References

- Jira: CCIP-12490, Automate nodes public key registration in JD.
- Operational example: chainlink-deployments PR #20610.
