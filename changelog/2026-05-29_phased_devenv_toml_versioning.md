# Phased devenv: TOML config versioning and env-phased.toml split

## Summary

Adds `version` fields to phased devenv config (top-level and per-component) so mismatched or stale configs fail fast on startup. Splits `env.toml` into a separate `env-phased.toml` for the phased runtime, which has an incompatible config layout.

---

## Breaking change: `env-phased.toml` required for phased mode; nested config layout

Phased mode (`--env-mode phased`) must now be invoked with `env-phased.toml`. The monolith `env.toml` uses a flat layout incompatible with the phased runtime.

| What | Before | After |
|------|--------|-------|
| Phased startup | `ccv up env.toml --env-mode phased` | `ccv up env-phased.toml --env-mode phased` |
| committeeccv config key | top-level `[[aggregator]]` / `[[verifier]]` | `[committeeccv]` section |
| topology config key | top-level `[environment_topology]` | `[protocol_contracts.environment_topology]` |

Before (`env.toml`):
```toml
[[aggregator]]
committee_name = "default"

[environment_topology]
indexer_address = ["http://indexer-1:8100"]
```

After (`env-phased.toml`):
```toml
[committeeccv]
[[committeeccv.aggregator]]
committee_name = "default"

[protocol_contracts.environment_topology]
indexer_address = ["http://indexer-1:8100"]
```

---

## New: top-level and per-component `version` validation

`env-phased.toml` must declare `version = 1` at the top level; each component section that supports versioning must also declare `version = 1`. Missing or mismatched values produce a clear startup error.

```toml
# env-phased.toml
version = 1

[committeeccv]
version = 1
# ...

[protocol_contracts]
version = 1
# ...
```

Error on mismatch:
```
unsupported config version 2; supported version is 1
```

New helper in `devenvruntime`:
```go
// CheckConfigVersion returns an error if got != want.
devenvruntime.CheckConfigVersion(cfg.Version, Version)
```
