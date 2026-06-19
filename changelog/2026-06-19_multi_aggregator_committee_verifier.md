# Multi-aggregator committee verifier (consolidated job)

## Summary

A committee verifier can now write to **multiple aggregators** from a single job
(fan-out), instead of requiring one job per aggregator. This is fully additive and
**opt-in**: existing single-`aggregator_address` configs and the existing changeset
output are unchanged until a caller explicitly enables the new path. See
`docs/adr/0001-multi-aggregator-committee-verifier.md` for the design and trade-offs.

No breaking changes in this PR. One breaking change (`NewVerificationCoordinator`) is
deliberately deferred to a coordinated follow-up — see *Heads-up* below.

## AI Adapter Index

All rows are **additive** — downstream code keeps compiling and behaving as before
without changes. Adopt these only to enable the consolidated topology.

| Symbol | Kind | Search | Section |
|---|---|---|---|
| `commit.Config.Aggregators` | added | `\bAggregators\b\|\[\[aggregators\]\]` | [#new-aggregators-config](#new-multi-aggregator-config) |
| `commit.AggregatorConnection` | added | `AggregatorConnection\b` | [#new-aggregators-config](#new-multi-aggregator-config) |
| `commit.Config.AggregatorAddress` | deprecated | `\bAggregatorAddress\b\|aggregator_address` | [#new-aggregators-config](#new-multi-aggregator-config) |
| `commit.Config.ResolvedAggregators` | added | `ResolvedAggregators\(` | [#new-aggregators-config](#new-multi-aggregator-config) |
| `commit.AggregatorCredentialEnvVars` | added | `AggregatorCredentialEnvVars\(` | [#new-per-aggregator-credentials](#new-per-aggregator-credentials) |
| `commit.AggregatorConnection.ResolveHMACConfig` | added | `ResolveHMACConfig\(` | [#new-per-aggregator-credentials](#new-per-aggregator-credentials) |
| `changesets.ApplyVerifierConfigInput.ConsolidateAggregators` | added | `ConsolidateAggregators\b` | [#new-consolidateaggregators-flag](#new-consolidateaggregators-changeset-flag) |
| `changesets.AddNOPOffchainInput.ConsolidateAggregators` | added | `ConsolidateAggregators\b` | [#new-consolidateaggregators-flag](#new-consolidateaggregators-changeset-flag) |
| `shared.NewConsolidatedVerifierJobID` | added | `NewConsolidatedVerifierJobID\(` | [#new-consolidateaggregators-flag](#new-consolidateaggregators-changeset-flag) |
| `hmac.ValidateAPIKey` | behavior-changed | `ValidateAPIKey\(` | [#bug-fixes](#bug-fixes) |

---

## New: multi-aggregator config

`commit.Config` gains an `aggregators` list. The legacy `aggregator_address` still works
and is mutually exclusive with the list (setting both is a validation error). When the
list is empty, the legacy field synthesizes a single-aggregator connection, so existing
configs are unchanged.

```toml
# Legacy (still supported):
aggregator_address = "agg:50051"
insecure_aggregator_connection = true

# New consolidated form:
[[aggregators]]
name = "primary"
secret_name = "primary-default-verifier"
address = "agg-1:50051"
insecure_connection = true

[[aggregators]]
name = "secondary"
secret_name = "secondary-default-verifier"
address = "agg-2:50051"
```

Each result is written to **all** aggregators (all-must-ack; idempotent retries),
heartbeats fan out to all, and disablement rules use a fail-safe union across all.

---

## New: per-aggregator credentials

Each aggregator authenticates the verifier with its **own** HMAC credential, referenced
by `AggregatorConnection.SecretName` (distinct from the display `Name`). Secrets are never
stored in config — only the reference is.

- **Standalone binary**: read from `VERIFIER_AGGREGATOR_<SECRETNAME>_API_KEY` /
  `VERIFIER_AGGREGATOR_<SECRETNAME>_SECRET_KEY` (`<SECRETNAME>` upper-cased,
  non-alphanumerics → `_`). A connection without a `secret_name` (legacy single aggregator)
  falls back to the un-suffixed `VERIFIER_AGGREGATOR_API_KEY` / `VERIFIER_AGGREGATOR_SECRET_KEY`.
- Multiple aggregators require a unique, non-empty `secret_name` each.

---

## New: `ConsolidateAggregators` changeset flag

`ApplyVerifierConfig` and `AddNOPOffchain` gain a `ConsolidateAggregators bool`, **default
`false`** (byte-identical one-job-per-aggregator output). When `true`, one consolidated job
per NOP is emitted using the `aggregators` list and an aggregator-name-free `verifier_id`
(`shared.NewConsolidatedVerifierJobID`); each aggregator's `secret_name` is set to the
legacy per-aggregator `verifier_id` so existing operator secrets need no re-provisioning.

```go
changesets.ApplyVerifierConfigInput{
    // ...
    ConsolidateAggregators: true, // opt in; pair with RevokeOrphanedJobs to clean up old jobs
}
```

---

## Bug fixes

- **`protocol/common/hmac`**: `ValidateAPIKey` no longer includes the API key value in its
  error message (callers log this error). Fixes a CodeQL clear-text-logging finding on the
  aggregator-credential path.

---

## Heads-up: deferred breaking change

The Chainlink-node path (`constructors.NewVerificationCoordinator`) still takes a single
`*hmac.ClientConfig` and is unchanged in this PR. A follow-up migrates it to a
`SecretName`-keyed `map[string]*hmac.ClientConfig` (a breaking change), landed in lockstep
with the chainlink-side `ccvcommitteeverifier/delegate.go` migration and devenv
consolidation. Because `SecretName` reuses the existing `secrets.toml` `VerifierID` key,
that migration needs no secret-store schema change.
