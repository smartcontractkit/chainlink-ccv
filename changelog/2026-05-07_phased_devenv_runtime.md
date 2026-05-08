# Phased devenv runtime (opt-in)

## Executive Summary

- Adds a `build/devenv/runtime` package and a phased startup path alongside the existing monolith.
- Lays scaffolding for the componentization work; subsequent PRs will extract concrete components into the runtime.
- Affects `build/devenv` consumers and the `ccv` CLI; no existing call sites need changes.
- Fully backwards compatible — `ccv up` defaults to legacy mode and `NewEnvironment` is unchanged.
- New `ccv --env-mode` flag added to toggle between legacy and phased environments.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `ccv.NewPhasedEnvironment` | added | `\bNewPhasedEnvironment\b` | `build/devenv/environment_phased.go:41` | [#new-features--additions](#new-features--additions) |
| `devenvruntime` (package) | added | `build/devenv/runtime` | `build/devenv/runtime/` | [#new-features--additions](#new-features--additions) |
| `ccv --env-mode` | added | `--env-mode` | `build/devenv/cli/ccv.go:54` | [#new-features--additions](#new-features--additions) |

## Breaking Changes

*No breaking changes.* `ccv.NewEnvironment` keeps the same signature and behavior; it has been relocated from `environment.go` to `environment_monolith.go` but remains the default path.

## New Features / Additions

- **`ccv.NewPhasedEnvironment`** — alternate entry point that drives startup through the new component runtime. Loads raw TOML, calls `devenvruntime.NewEnvironment`, and extracts the resulting `*Cfg` from the legacy fallback component. Today it produces the same end state as `NewEnvironment`; future PRs will swap pieces of `runPhasedEnvironment` for first-class components.
- **`devenvruntime` package** (`build/devenv/runtime/`) — `Component` + `Phase{1,2,3,4}Component` interfaces, a `Registry` with `Register`/`SetFallback`, and a phase driver that runs registered components in sorted-key order followed by the fallback. All four phases return `(map[string]any, error)`; outputs accumulate across phases. Components register themselves via `func init()` calling `devenvruntime.Register(configKey, factory)` or `devenvruntime.SetFallback(factory)`.
- **`ccv --env-mode {legacy|phased}`** — persistent root flag selecting the entry point used by `ccv up` and `ccv restart`. Default is `legacy`.

```go
// Opt into the phased runtime from a tool/test that previously called ccv.NewEnvironment.
cfg, err := ccv.NewPhasedEnvironment()
```

```sh
ccv --env-mode phased up env.toml
```

## Compatibility & Requirements

- **Feature flags / rollout:** `--env-mode` defaults to `legacy`. CI runs an additional `TestE2ESmoke_Basic_Phased` matrix entry against `--env-mode phased` to keep the new path green.

## References

- Design doc: `design.txt` (DevEnv Ephemeral Environment).
