# Phased devenv serializes its raw output map; `LoadOutput` is version-aware

## Summary

The phased devenv (`--env-mode phased`) now serializes the raw accumulated
component-output map directly instead of reconstructing a transitional `*Cfg`,
and `LoadOutput[Cfg]` selects its decoder from a `version` marker so existing
readers consume either format unchanged. Components own their output keys, with
runtime-only values hidden behind a `_` prefix.

---

## Breaking change: `NewPhasedEnvironment` return type

It no longer returns the transitional `*Cfg`; it returns the raw accumulated
output map. The `up`/`restart` commands already discarded the value, so the CLI
is unaffected; direct callers must adjust.

| What | Before | After |
|------|--------|-------|
| Signature | `func NewPhasedEnvironment() (*Cfg, error)` | `func NewPhasedEnvironment() (map[string]any, error)` |

Before:
```go
cfg, err := ccv.NewPhasedEnvironment()
```

After:
```go
out, err := ccv.NewPhasedEnvironment() // out is the raw runtime output map
```

---

## Breaking change: phased output file format

The phased output file (e.g. `env-phased-out.toml`) is now a dump of the
component output map (component-native keys such as `aggregators`/`verifiers`,
plus `cldf`, `environment_topology`, public `jd`), not a `Cfg`-shaped document.
Runtime-only keys (prefixed `_`) are stripped. **Do not** strict-decode it as
`Cfg` — read it through `LoadOutput`, which now branches on `version`.

| What | Before | After |
|------|--------|-------|
| Format | `Cfg` TOML (`Store(cfg)`) | raw output map, `_`-keys stripped |
| `version` (phased) | `1` | `1` (re-emitted as public key) |
| `version` (legacy/monolith) | `1` | `0` / absent (dropped from `env.toml`) |
| Loader dispatch | always strict `Cfg` decode | `0`/absent → strict `Cfg`; `1` → lenient phased decode |

---

## Breaking change: `JDInfrastructure` is now serialized

`jd` stays a public output key (kept for future job proposals). To make it
TOML-safe, the live gRPC client is excluded and the data fields are tagged.

| Field | Before | After |
|-------|--------|-------|
| `JDOutput` | (untagged) | `toml:"jd_output"` |
| `NodeIDMap` | (untagged) | `toml:"node_id_map"` |
| `OffchainClient` | (serialized) | `toml:"-"` (skipped) |

---

## New: version-aware `LoadOutput[Cfg]`

A single dispatch point — `NewLibFromCCVEnv` and all direct `LoadOutput[ccv.Cfg]`
callers funnel through it, so no call sites or signatures change. Version `1`
leniently decodes the phased map and derives the aggregator/indexer endpoint maps
from each launched service's `Out`.

```go
in, err := ccv.LoadOutput[ccv.Cfg](outFile) // works for phased and legacy output
```

---

## New: public/private component output keys

Components publish public keys (serialized) or `_`-prefixed runtime-only keys
(stripped on serialize). Reclassified this release:

- `_cldf` → `cldf`, `_topology` → `environment_topology` (now public)
- `shared_tls_certs` → `_shared_tls_certs` (now runtime-only)

---

## Recommended additions

- Follow-ups filed in `.scratch/phased-devenv-cleanup/`: decouple `Lib` from
  `Cfg` (10), typed output-key bus (12, needs go/no-go), and a generic
  `DecodeConfig[T]` helper (14).
