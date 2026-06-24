# Multi-aggregator committee verifier — Part 2

## Summary

`NewVerificationCoordinator` now accepts per-aggregator HMAC credentials (keyed by
`AggregatorConnection.SecretName`) instead of a single shared credential. The devenv
cuts over to the consolidated verifier config so standalone verifiers write to all
committee aggregators from a single job.

---

## Breaking change: `NewVerificationCoordinator` credential parameter

The `aggregatorSecret *hmac.ClientConfig` parameter is replaced by a map. Each
aggregator's credential is looked up by `AggregatorConnection.SecretName`; the legacy
single-aggregator config has an empty `SecretName`, so its credential must be stored
under the `""` key.

| What | Before | After |
|------|--------|-------|
| Parameter | `aggregatorSecret *hmac.ClientConfig` | `aggregatorSecrets map[string]*hmac.ClientConfig` |
| Lookup | applied to all aggregators | per-aggregator, keyed by `SecretName` |
| Legacy compat | N/A | empty `SecretName` → key `""` |

Before:
```go
vc, err := constructors.NewVerificationCoordinator(
    lggr, cfg,
    &hmac.ClientConfig{APIKey: key, Secret: secret},
    signerAddr, signer, chains, ds,
)
```

After:
```go
vc, err := constructors.NewVerificationCoordinator(
    lggr, cfg,
    map[string]*hmac.ClientConfig{
        // legacy single-aggregator: key is ""
        "": {APIKey: key, Secret: secret},
        // consolidated multi-aggregator: key is AggregatorConnection.SecretName
        "mycommittee-verifier-1-v1": {APIKey: key1, Secret: secret1},
    },
    signerAddr, signer, chains, ds,
)
```

**Callers** (e.g. `ccvcommitteeverifier/delegate.go` in chainlink) must migrate to
`buildAggregatorSecrets` — which resolves credentials from the secrets TOML by matching
each aggregator's `SecretName` against the stored `VerifierID`.

---

## New: per-aggregator HMAC credentials in devenv

Standalone verifier containers now receive one `VERIFIER_AGGREGATOR_<SECRETNAME>_API_KEY`
/ `_SECRET_KEY` env var pair per aggregator instead of the single legacy default pair.
`SecretName` is computed as `NewVerifierJobID(nop, aggName, scope).GetVerifierID()` —
the same formula the changeset bakes into the verifier config — so no credential
re-provisioning is needed.

The consolidated job spec (`ConsolidateAggregators: true`) is now the default for all
devenv modes (monolith and phased/component). Each standalone verifier node owns one
consolidated spec and writes to every committee aggregator.

---

## Recommended additions

- Unit test for `NewVerificationCoordinator` covering the multi-aggregator secret lookup
  and the missing-secret error path (flagged as a test gap by the graph).
