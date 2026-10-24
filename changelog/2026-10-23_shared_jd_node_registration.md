# Shared chain-agnostic JD node registration

## Executive Summary

- Adds `deployment/registration`, a reusable JD identity-registration package for CSA key resolution, conflict-safe registration, label reconciliation, connection waiting, and deployment-framework operations/changesets.
- Supports sequential batch registration and JD-backed `nodes.json` snapshots through the same changesets used by deployment adapters.
- Migrates normal devenv verifier, executor, Chainlink-node, monolith, phased, and migration registration paths to the shared implementation.
- Keeps chain-family concerns outside the package: there are no chain selectors, OCR bundles, signing/transmitter operations, or EVM/Solana/Canton imports.
- Leaves deliberate CL-to-standalone key adoption and runtime-specific output serialization outside this change.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `registration.CSAKeyProvider` | added | `CSAKeyProvider` | `deployment/registration/key_provider.go:24` | [#bootstrap-key-providers](#bootstrap-key-providers) |
| `registration.InfoServerCSAKeyProvider` | added | `InfoServerCSAKeyProvider` | `deployment/registration/key_provider.go:40` | [#bootstrap-key-providers](#bootstrap-key-providers) |
| `registration.FetchPublicKeys` | added | `FetchPublicKeys\(` | `deployment/registration/key_provider.go:54` | [#bootstrap-key-providers](#bootstrap-key-providers) |
| `registration.DefaultCSAKeyName`, `registration.GetKeysEndpoint` | added | `registration\.(DefaultCSAKeyName|GetKeysEndpoint)` | `deployment/registration/api.go:4` | [#bootstrap-key-providers](#bootstrap-key-providers) |
| `registration.NodeSpec` | added | `registration\.NodeSpec` | `deployment/registration/types.go:25` | [#shared-registration-package](#shared-registration-package) |
| `registration.Register` | added | `registration\.Register\(` | `deployment/registration/register.go:25` | [#shared-registration-package](#shared-registration-package) |
| `registration.RegisterAndWait` | added | `RegisterAndWait\(` | `deployment/registration/register.go:133` | [#shared-registration-package](#shared-registration-package) |
| `registration.WaitForConnection` | added | `WaitForConnection\(` | `deployment/registration/connection.go:12` | [#shared-registration-package](#shared-registration-package) |
| `registration.IsJDNotFound` | added | `IsJDNotFound\(` | `deployment/registration/register.go:299` | [#shared-registration-package](#shared-registration-package) |
| `registration.RegisterNodeWithJD` | added | `RegisterNodeWithJD` | `deployment/registration/register_node_operation.go:32` | [#framework-operations-and-changesets](#framework-operations-and-changesets) |
| `registration.SaveNodesJSON` | added | `SaveNodesJSON` | `deployment/registration/save_nodes_operation.go:31` | [#framework-operations-and-changesets](#framework-operations-and-changesets) |
| `registration.CsRegisterNodesWithJD` | added | `CsRegisterNodesWithJD` | `deployment/registration/register_nodes_changeset.go:14` | [#framework-operations-and-changesets](#framework-operations-and-changesets) |
| `registration.CsSaveNodesWithJD` | added | `CsSaveNodesWithJD` | `deployment/registration/save_nodes_changeset.go:13` | [#framework-operations-and-changesets](#framework-operations-and-changesets) |
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

`RegisterAndWait` combines registration with a bounded connection wait and preserves the registration result when the wait fails. `WaitForConnection` is also available independently for CL nodes whose JD connection is configured after registration. `IsJDNotFound` exposes the direct and production-wrapped error classification for other JD operations.

## Framework operations and changesets

`RegisterNodeWithJD` adapts the shared registrar to the deployment-framework operation API while preserving `node_id` and `was_registered` output fields. `SaveNodesJSON` lists the full JD product/environment and writes its IDs and names to `nodes.json`, refusing to overwrite state with an empty result.

`CsRegisterNodesWithJD` owns input validation, sequential per-node operations, forced execution, and aggregate failure handling. Every input node is attempted even after a failure, but any failure prevents the state save. A completely successful batch saves the full JD environment exactly once. `CsSaveNodesWithJD` exposes the same snapshot as a standalone changeset.

Operation IDs, versions, YAML/JSON input fields, and report output schemas remain compatible. Zero-value changesets resolve the framework domain normally; an optional `*domain.Domain` supports isolated tests and devenv. The caller owns runtime-specific output structures and any subsequent Git persistence.

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

The devenv smoke suite exercises the shared changesets against real JD using a zero-chain framework environment and temporary domain directory. It covers synthetic bootstrap/plugin creation, operation reports, `nodes.json`, idempotent reruns, label reconciliation, conflict handling, and the no-save-on-failure rule. The registration flow is VM-agnostic; VM-specific key provisioning remains outside its scope.

## Breaking Changes

No breaking API changes. Existing operation and changeset names, YAML/JSON fields, and operation report shapes are preserved.

Existing registration behavior is stronger: matching records return their ID instead of producing an `AlreadyExists` error, label drift can be reconciled, and identity conflicts fail explicitly. A partial batch failure still prevents the `nodes.json` refresh.

## Migration Guide

Deployment-framework consumers can alias the shared changeset/input and operation types rather than maintaining duplicate registration implementations. Zero-value changesets retain normal domain resolution, so existing pipeline registry construction and YAML inputs remain unchanged.

Direct integrations can pass an authenticated JD client to `Register` or `RegisterAndWait`, using `StaticCSAKeyProvider` for a resolved `csa_key` or `InfoServerCSAKeyProvider` when the bootstrap endpoint is available. Use `Register` without a wait when a CL node still needs its JD connection configured; use `RegisterAndWait` for standalone processes that connect immediately.

The shared changesets write generic `nodes.json` state through the framework domain. Environment-specific node maps, TOML serialization, and Git persistence remain the caller's responsibility.

## Compatibility & Requirements

- Uses the existing JD, keystore, and deployment-framework dependencies; no new third-party library is directly imported. Framework domain support adds its existing transitive module metadata.
- `deployment/go.mod` moves `chainlink-common/keystore` from indirect to direct.
- Unit coverage includes providers, registration, operations, changesets, idempotency, conflicts, label updates, production error mapping, invalid responses, connection deadlines, full-environment saves, and no-save-on-failure behavior.
- `TestE2ESmoke_Basic` checks real-JD registration, HTTP key resolution, labels, connectivity, idempotent reruns, conflict rejection, shared operation reports, and temporary `nodes.json` output alongside the existing message smoke coverage. `ccv test smoke-jd-registration` selects the same assertions directly; CL-only and no-JD profiles skip only when no standalone services are declared.
