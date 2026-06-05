# ccv profiles, unified test command, and log flag

## Summary

Replaces ad-hoc config file combos and `--env-mode` flags with named `.profile`
files that encode a complete environment configuration. Extends `ccv test` to
optionally start the environment before running tests, adds `--log <path>` for
OS-level output redirection, and simplifies both CI smoke workflows to use the
unified command.

---

## Breaking: `ccv up` / `ccv restart` default changed

The bare `ccv up` with no arguments no longer defaults to `env.toml` in legacy
mode. It now loads `standard.profile`.

| What | Before | After |
|------|--------|-------|
| `ccv up` (no args) | loads `env.toml`, legacy mode | loads `standard.profile` |
| `ccv shell` | sets `CTF_CONFIGS=env.toml` | loads `standard.profile` |
| `ccv up env-phased.toml` | still works | still works |

---

## Breaking: `--env-mode` cannot be combined with `--profile`

Passing `--profile` and `--env-mode` together is now a hard error. The
environment type is declared inside the profile file.

Before:
```bash
ccv --env-mode phased up env-phased.toml
```

After:
```bash
ccv up --profile phased.profile
```

---

## New: configuration profiles

A `.profile` file encodes a complete environment: mode, ordered config files,
and optional output path.

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

## New: `--profile` / `-p` and `--output` / `-o` flags on `up`, `restart`

```bash
ccv up --profile phased.clnode.profile
ccv up phased.clnode.profile          # positional *.profile also accepted
ccv up -p standard                    # .profile suffix optional
ccv restart --profile standard.profile
ccv shell --profile phased.profile

ccv up --profile phased.profile --output env-out.toml   # override output path
ccv up env.toml --output my-out.toml                    # raw config still works
```

Shell completion for `up` / `restart` now dynamically lists all `*.profile`
files in the working directory with their descriptions.

The `--output` override is passed through via the `CTF_OUTPUT` env var, which
`Store()` checks before deriving the path from `CTF_CONFIGS`.

---

## New: `ccv test` — profile, pattern, build, and log flags

`ccv test` can now start the environment before running tests. Without
`--profile` it runs against a live environment (existing behaviour). With
`--profile` it starts the environment first and writes output to a per-run
file so concurrent runs do not collide.

```bash
# Against a running env (existing behaviour):
ccv test smoke
ccv test --pattern TestE2ESmoke_Basic

# Start env first, then run:
ccv test smoke --profile standard.profile
ccv test --pattern TestE2ESmoke_Basic --profile standard.clnode.profile --timeout 20m

# Skip rebuild if images are current:
ccv test smoke --profile standard.profile --build=false
```

Named suite aliases (positional arg): `smoke`, `smoke-v2`, `smoke-v3`, `load`,
`rpc-latency`, `gas-spikes`, `reorg`, `chaos`, `indexer-load`, `multi_chain_load`.

| Flag | Default | Notes |
|------|---------|-------|
| `--profile` / `-p` | — | Profile to start before running; sets per-run output file |
| `--pattern` / `-r` | — | Raw Go `-run` pattern; mutually exclusive with suite name |
| `--build` | `true` | Build Docker images first (requires `--profile`); pass `--build=false` to skip |
| `--timeout` | `0` (unlimited) | Passed to `go test -timeout` |
| `--log <path>` | — | Write all output to file; terminal shows only progress lines |

---

## New: `--log <path>` flag

Redirects all verbose output — docker build, env startup, CTF framework
subprocesses, zerolog, and go test — to a file. Only concise `[ccv test]`
progress lines appear on the terminal. Uses `dup2` at the OS fd level so
no output escapes regardless of how it is written.

```bash
ccv test --profile standard.clnode.profile \
         --pattern TestE2ESmoke_Basic \
         --timeout 20m \
         --log /tmp/test.log
```

Terminal output:
```
[ccv test] building images...
[ccv test] starting environment (profile: standard.clnode.profile, output: /.../test-abc-out.toml)...
[ccv test] running test TestE2ESmoke_Basic...
[ccv test] PASSED (log: /tmp/test.log)
```

---

## CI workflows simplified

`test-smoke.yaml` and `test-cl-smoke.yaml` replace per-test `config` + `flags`
matrix fields with a single `profile` field and rename `run_cmd` to `pattern`.
The monolithic env-startup step becomes two discrete steps (`Install ccv CLI`,
`Run Observability Stack`) followed by a single `ccv test --build=false` step.

Before:
```yaml
matrix:
  test:
    - name: TestE2ESmoke_Basic
      run_cmd: TestE2ESmoke_Basic
      config: env.toml
      timeout: 15m
      working-directory: build/devenv/tests/e2e

steps:
  - name: Run CCV environment
    run: |
      cd cmd/ccv && go install . && cd -
      ccv u ${{ matrix.test.config }} && ccv obs up -m loki
  - name: Run Test ${{ matrix.test.name }}
    working-directory: ${{ matrix.test.working-directory }}
    run: go test -v -timeout ${{ matrix.test.timeout }} -count=1 -run '${{ matrix.test.run_cmd }}'
```

After:
```yaml
matrix:
  test:
    - name: TestE2ESmoke_Basic
      pattern: TestE2ESmoke_Basic
      profile: standard.profile
      timeout: 15m

steps:
  - name: Install ccv CLI
    run: go install ./cmd/ccv
  - name: Run Observability Stack
    run: ccv obs up -m loki
  - name: Run Test ${{ matrix.test.name }}
    run: ccv test --profile ${{ matrix.test.profile }} --pattern '${{ matrix.test.pattern }}' --timeout ${{ matrix.test.timeout }} --build=false
    env:
      JD_IMAGE: ${{ secrets.JD_IMAGE }}
```

---

## Bug fixes

- **`LoadOutput`**: `filepath.Join(".", "/abs/path")` silently strips the leading
  `/` in Go. `LoadOutput` now checks `filepath.IsAbs` before joining, so an
  absolute path passed via `SMOKE_TEST_CONFIG` is used as-is.

  | Call | Before | After |
  |------|--------|-------|
  | `LoadOutput("env-out.toml")` | `"./env-out.toml"` ✓ | `"./env-out.toml"` ✓ |
  | `LoadOutput("/abs/test-abc-out.toml")` | `"abs/test-abc-out.toml"` ✗ | `"/abs/test-abc-out.toml"` ✓ |

- **CI**: Phased smoke test matrix entry renamed from `TestE2ESmoke_Basic_Phased`
  (non-existent function) to `TestE2ESmoke_Basic`. The phased environment is
  selected by the profile, not a different test function.

- **CI**: `SMOKE_TEST_CONFIG` override removed from both smoke workflows;
  `ccv test` derives the output path from the profile and sets it automatically.
