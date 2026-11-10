# Admin job-spec and transmitter-balance visibility

## Executive Summary

- Adds `/job` to verifier and executor admin consoles, showing the active job envelope and raw application TOML.
- Adds an executor-only `/transmitter-keys` page with public transmitter addresses, native-token balances, exact base units, and per-chain lookup failures.
- Keeps executor consoles read-only; verifier search, recovery, reschedule, and action-log behavior is unchanged.
- Uses the existing optional admin console config and service secrets files; no database migration or new credential channel is introduced.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `admin.Deps` | behavior-changed | `admin\.Deps\{` | `verifier/pkg/admin/server.go:33` | [#console-modes](#console-modes) |
| `admin.SecretsPathEnv` / `admin.DefaultSecretsPath` | added | `CCV_ADMIN_SECRETS_PATH` | `verifier/pkg/admin/config.go:21` | [#executor-authentication](#executor-authentication) |
| `chainaccess.TransmitterBalanceReader` | added | `TransmitterBalanceReader` | `pkg/chainaccess/interfaces.go:249` | [#balance-capability](#balance-capability) |
| `evm.accessor.TransmitterBalances` | added | `TransmitterBalances\(` | `integration/pkg/accessors/evm/factory.go:415` | [#balance-capability](#balance-capability) |

## Breaking Changes

*No breaking changes.* `TransmitterBalanceReader` is an optional accessor capability; the base `chainaccess.Accessor` interface is unchanged.

## New Features / Additions

### Console modes

`admin.Deps.ReadOnly` creates an executor console without verifier database or mutation routes. Its home page redirects to `/job`; verifier consoles retain their existing routes and redirect to `/search`. Both modes use the same basic-auth, host allowlist, security-header, and static-asset handling. `admin.Deps.JobSpec` supplies a snapshot of the running job, including the raw `AppConfig` rendered as escaped text.

### Executor authentication

The executor reads the same `[admin_ui]` username/password shape as the verifier from `/etc/ccv-admin/secrets.toml` (`CCV_ADMIN_SECRETS_PATH` overrides the path, never the credential). A half-supplied pair fails console startup, and a non-loopback listen address still requires authentication. Keeping this file separate from bootstrap secrets lets older images start with the newly generated environment config during rolling upgrades; they ignore the executor-only admin files.

### Balance capability

EVM destination accessors optionally implement `chainaccess.TransmitterBalanceReader`. The method resolves enabled transmitter addresses through the existing keystore adapter and reads native balances through the existing chain client at request time. The executor queries configured chains concurrently with a per-chain timeout. A failed chain displays its error without hiding successful chains; a partial address failure preserves successful address rows.

The UI formats native-token amounts using the configured decimals and also displays the exact integer base units. It does not expose private key material or provide background alerts. Devenv launches the executor console on the same container port as the verifier console (8105, mapped to an ephemeral host port) and prints its URL and development credentials.

## Compatibility & Requirements

- The console remains disabled unless `/etc/ccv-admin/config.toml` (or `CCV_ADMIN_CONFIG_PATH`) is present. Executor authentication is optional on loopback and read from `/etc/ccv-admin/secrets.toml` (or `CCV_ADMIN_SECRETS_PATH`); bootstrap config and secrets schemas are unchanged.
- Transmitter balances currently have an EVM implementation. Other chain families continue to satisfy `chainaccess.Accessor` without implementing the optional capability and show an unavailable error on the executor page.
- Operators should keep using their telemetry/alerting pipeline for continuous low-balance alerts; this change supplies operator UI inspection only.
