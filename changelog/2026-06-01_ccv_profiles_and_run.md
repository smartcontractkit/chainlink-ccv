# ccv profiles and one-shot run command

## Summary

Replaces ad-hoc config file combos and `--env-mode` flags with named
`.profile` files that encode a complete environment configuration.
Adds `ccv run` to drive image build → environment startup → go test
in a single command.

---

## Breaking: `ccv up` / `ccv restart` default changed

The bare `ccv up` with no arguments no longer defaults to `env.toml`
in legacy mode. It now loads `standard.profile`, which encodes the
same configuration but requires the profile file to be present in the
working directory.

| What | Before | After |
|------|--------|-------|
| `ccv up` (no args) | loads `env.toml`, legacy mode | loads `standard.profile` |
| `ccv shell` | sets `CTF_CONFIGS=env.toml` | loads `standard.profile` |
| `ccv up env-phased.toml` | still works | still works |

---

## Breaking: `--env-mode` cannot be combined with `--profile`

Passing `--profile` and `--env-mode` together is now a hard error.
The environment type is declared inside the profile file.

Before:
```bash
ccv --env-mode phased up env-phased.toml
```

After:
```bash
ccv up --profile phased.profile
# or shorthand:
ccv up phased.profile
```

---

## New: configuration profiles

A `.profile` file encodes a complete environment: mode, ordered config
files, and optional output path.

```toml
# build/devenv/standard.profile
environment = "legacy"
description = "Standard environment used by most integration tests"
configs     = ["env.toml"]
```

Ten built-in profiles ship in `build/devenv/`:

| Profile | Mode | Config files |
|---------|------|-------------|
| `standard.profile` | legacy | `env.toml` |
| `phased.profile` | phased | `env-phased.toml` |
| `standard.clnode.profile` | legacy | `env.toml`, `env-cl.toml` |
| `standard.clnode.ci.profile` | legacy | `env.toml`, `env-cl.toml`, `env-cl-ci.toml` |
| `phased.clnode.profile` | phased | `env-phased.toml`, `env-cl-phased.toml` |
| `phased.clnode.ci.profile` | phased | `env-phased.toml`, `env-cl-phased.toml`, `env-cl-ci-phased.toml` |
| `standard.one-exec-per-chain.profile` | legacy | `env.toml`, `env-one-exec-per-chain-standalone.toml` |
| `standard.src-auto-mine.profile` | legacy | `env.toml`, `env-src-auto-mine.toml` |
| `standard.ha.clnode.ci.profile` | legacy | `env.toml`, `env-HA.toml`, `env-cl.toml`, `env-cl-ci.toml` |
| `standard.clnode.ci.one-exec-per-chain.profile` | legacy | `env.toml`, `env-cl.toml`, `env-cl-ci.toml`, `env-one-exec-per-chain-cl.toml` |

---

## New: `--profile` / `-p` flag on `up`, `restart`, `shell`

```bash
ccv up --profile phased.clnode.profile
ccv up phased.clnode.profile          # positional *.profile also accepted
ccv up -p standard                    # .profile suffix optional
ccv restart --profile standard.profile
ccv shell --profile phased.profile
```

Shell completion for `up` / `restart` now dynamically lists all
`*.profile` files in the working directory with their descriptions.

---

## New: `--output` / `-o` flag on `up` and `restart`

Overrides where the environment output file is written. Works with
or without `--profile`.

```bash
ccv up --profile phased.profile --output env-out.toml
ccv up env.toml --output my-out.toml
```

The override is passed through via the new `CTF_OUTPUT` env var, which
`Store()` checks before deriving the path from `CTF_CONFIGS`.

---

## New: `ccv run` command

One-shot command for local integration testing.

```bash
ccv run --profile standard --test TestE2ESmoke_Basic
ccv run --profile phased.clnode \
        --test '(TestChaos_A|TestChaos_B)' \
        --timeout 20m
ccv run --profile standard --test TestE2ESmoke_Basic --build=false
```

Flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--profile` / `-p` | required | Profile name or file |
| `--test` / `-t` | required | Go `-run` pattern |
| `--timeout` | `15m` | Passed to `go test -timeout` |
| `--build` | `true` | Run `just build-docker-dev` first |

Output is written to `test-<uuid>-out.toml` (isolated per run);
`SMOKE_TEST_CONFIG` is set automatically so `GetSmokeTestConfig()`
finds it without any test-code changes.

---

## Bug fixes

- **CI**: `TestE2ESmoke_Basic_Phased` (non-existent) corrected to
  `TestE2ESmoke_Basic` in `test-cl-smoke.yaml`. The phased environment
  is selected by the profile, not by a different test function.
- **CI**: `SMOKE_TEST_CONFIG` override removed from both smoke
  workflows; `--output env-out.toml` ensures every run writes to the
  path the test binary already expects by default.
