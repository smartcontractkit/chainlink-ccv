# Unified verifier binary (committee + token in one process)

## Executive Summary

- Adds a unified verifier binary (`cmd/verifier/unified`) that runs committee (ECDSA-signing, aggregator sink) and token (CCTP/Lombard attestation, Postgres VerifierResults API sink) verifiers in one process, selected purely by app config via `[[verifiers]]` entries.
- The committee verifier stack construction is extracted from `cmd/verifier/servicefactory.go` into a reusable `startCommitteeVerifier` in `cmd/verifier/committeestack.go`; the legacy committee factory is re-expressed in terms of it with unchanged behavior.
- Affects `cmd/verifier` (new unified factory/config/binary) and `verifier/pkg/vsecrets` (new secrets-path constants). The existing committee and token binaries are untouched in behavior.
- No breaking changes; purely additive. New config schema `UnifiedConfig` with `[[verifiers]]` entries of type `committee`, `cctp`, or `lombard`.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `vsecrets.VerifierSecretsPathEnv` | added | `VerifierSecretsPathEnv` | `verifier/pkg/vsecrets/vsecrets.go:36` | [#new-secrets-path-constants](#new-secrets-path-constants) |
| `vsecrets.DefaultVerifierSecretsPath` | added | `DefaultVerifierSecretsPath` | `verifier/pkg/vsecrets/vsecrets.go:37` | [#new-secrets-path-constants](#new-secrets-path-constants) |
| `verifier.UnifiedConfig` (`cmd/verifier`) | added | `UnifiedConfig` | `cmd/verifier/unifiedconfig.go:40` | [#unified-config-schema](#unified-config-schema) |
| `verifier.Entry` (`cmd/verifier`) | added | `Entry` | `cmd/verifier/unifiedconfig.go:56` | [#unified-config-schema](#unified-config-schema) |
| `verifier.CommitteeEntryConfig.ToCommitConfig` | added | `ToCommitConfig\(` | `cmd/verifier/unifiedconfig.go:151` | [#unified-config-schema](#unified-config-schema) |
| `verifier.NewUnifiedVerifierServiceFactory` (`cmd/verifier`) | added | `NewUnifiedVerifierServiceFactory` | `cmd/verifier/unifiedfactory.go:46` | [#unified-factory](#unified-factory) |
| `verifier.startCommitteeVerifier` (`cmd/verifier`) | added | `startCommitteeVerifier\(` | `cmd/verifier/committeestack.go:59` | [#committee-stack-extraction](#committee-stack-extraction) |

## Breaking Changes

No breaking changes.

## New Features / Additions

### New secrets path constants

- `vsecrets.VerifierSecretsPathEnv` = `VERIFIER_SECRETS_PATH`, `vsecrets.DefaultVerifierSecretsPath` = `/etc/verifier/secrets.toml`. Path resolution only; the secrets file schema (`[db].url`, `[[aggregators]]`, `[policy_hook]`) is unchanged. This is a path env var, not a credential, consistent with repo convention.

### Unified config schema

`UnifiedConfig` (cmd/verifier/unifiedconfig.go) carries the service-level shared fields (`pyroscope_url`, `http_listen_port`, `disable_finality_checkers`, `[monitoring]`, and the embedded `chainaccess.CommitteeConfig` on-ramp/RMN addresses) plus `[[verifiers]]` entries:

- `type = "committee"` — decodes into `CommitteeEntryConfig` (same TOML tags as `commit.Config`: `aggregator_address` legacy field, `aggregators`, `signer_address`, `committee_verifier_addresses`, `default_executor_on_ramp_addresses`, `message_disablement_rules_*`, `policy_hook`). `CommitteeEntryConfig.ToCommitConfig(shared UnifiedConfig)` derives a full `commit.Config`, reusing `commit.Config.Validate()` and `ResolvedAggregators()` unchanged.
- `type = "cctp"` / `type = "lombard"` — dispatched via the existing `cctp.TryParsing` / `lombard.TryParsing`, requiring `version` (`2.0` / `1.0`), exactly as `token.VerifierConfig` does.

`UnifiedConfig.Validate()` enforces: at least one entry, unique `verifier_id`, **at most one committee entry** (one process has a single ECDSA signing key), unknown types rejected, `http_listen_port` in 0..65535, and each committee entry's derived `commit.Config` passing `Validate()`.

### Unified factory

`NewUnifiedVerifierServiceFactory` (cmd/verifier/unifiedfactory.go) implements `bootstrap.ServiceFactory` + `bootstrap.ServiceFactoryValidator`:

- Requires `deps.Keystore` only when a committee entry is configured.
- Loads secrets from `VERIFIER_SECRETS_PATH` (default `/etc/verifier/secrets.toml`).
- Builds base source readers once, shared across all entries, via `buildSourceReaders` (the concurrent per-chain skip pattern both legacy factories use; keeps the accessors map for `cctpCodecsFor`). Committee entries wrap each base reader with `instrumentSourceReader` per entry; token entries use base readers directly.
- Connects Postgres once (`ConnectToPostgresDB`); the connection is shared between chain status (all entries) and token storage.
- Committee entry: `startCommitteeVerifier` (shared with the legacy factory). Token entries: existing `createCCTPCoordinator` / `createLombardCoordinator` with the token factory's per-entry skip-on-failure semantics (`startupSkips.Skip`, continue; fail only when zero coordinators started). Committee entry failure is fatal, mirroring the committee factory.
- HTTP on `http_listen_port` (default 8100): token entries present → `tokenapi.NewHTTPAPI` (`/health`, `/v1/verifications`) plus `/stats` when a committee writer exists; committee-only → the committee-style router (`/`, `/health`, `/stats`).
- Admin console via `startAdminConsole` with the committee entry's first aggregator when present, else `("", false)`.

### New binary `cmd/verifier/unified`

`main.go` mirrors the committee binary: `ccv` CLI branch with the unified secrets path, then `bootstrap.Run("EVMVerifier", NewUnifiedVerifierServiceFactory(), bootstrap.WithKey(commit.DefaultECDSASigningKeyName, "signing", keystore.ECDSA_S256))`. The ECDSA key is always declared — unused when no committee entry is configured. Build with the existing `verifier/Dockerfile` via `VERIFIER_TYPE=unified` (no Dockerfile change needed).

Chain-agnosticism follows the existing multi-repo pattern: the factory and config are family-agnostic (chain resolution goes through the `chainaccess` registry by the family declared in the chain config), and each chain family instantiates its own binary in its own repo — a `main.go` that blank-imports its accessor driver and calls the exported `cmd.NewUnifiedVerifierServiceFactory()`, exactly as `chainlink-ccip-solana/cmd/committeeverifier` and `chainlink-canton/cmd/committeeverifier` do for the committee factory today. The in-repo unified binary is the EVM instantiation: it imports the EVM register package and is named `EVMVerifier` (matching `EVMCommitteeVerifier`); there is deliberately no single all-families registration point in this repo. (The committee flavor itself remains ECDSA/secp256k1 with hex-parsed `committee_verifier_addresses` — a pre-existing property of the flavor, shared with the legacy binary.)

### Committee stack extraction

`startCommitteeVerifier` (cmd/verifier/committeestack.go) covers the whole committee stack: verifier address maps, aggregator resolution + HMAC, signer creation + `commit.ValidateSignerAddress`, chain status manager, `commit.NewCommitVerifier`, policy gate, fan-out writer + observed writer, heartbeat fan-out, message-rules pollers, coordinator creation + `Start`. It returns a `committeeStack` (coordinator, fanOutWriter, heartbeatClient, chainStatusDB, resolvedAggregators). `committeeVerifierDeps.db` selects DB ownership: nil = connect from secrets and own it (legacy binary), non-nil = caller's shared connection (unified factory). The legacy `factory.Start` keeps its own secrets-path constants, reader loop, HTTP server, and admin console, and delegates everything else to the extracted function.

## Compatibility & Requirements

- Both JD and local app-config bootstrap modes work unchanged (`app_config_mode`); committee entries require a keystore, token-only configs run keystore-less in local mode.
- Existing `cmd/verifier/committee` and `cmd/verifier/token` binaries are behaviorally unchanged.

## Examples

```toml
http_listen_port = 8100

[on_ramp_addresses]
"5009297550715157269" = "0xOnRamp"

[[verifiers]]
type = "committee"
verifier_id = "committee-1"
signer_address = "auto"
[verifiers.committee_verifier_addresses]
"5009297550715157269" = "0xCommitteeVerifier"
[[verifiers.aggregators]]
address = "localhost:50051"
secret_name = "agg1"

[[verifiers]]
type = "cctp"
verifier_id = "usdc-cctp"
version = "2.0"
attestation_api = "https://iris-api.circle.com"
[verifiers.verifier_resolver_addresses]
"5009297550715157269" = "0xResolver"
```
