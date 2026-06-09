---
name: Integration Tests
description: Run local devenv integration/smoke tests, including Chainlink node (-cl) variants
---

## Integration Tests

All commands run from `build/devenv` unless noted otherwise.

### Test matrix (from CI workflows)

**Standalone tests** (`test-smoke.yaml`):
- `TestE2ESmoke_Basic` — profile: `standard.profile`
- `TestE2ESmoke_Basic_OneExecPerChain` — profile: `standard.one-exec-per-chain.profile`
- `TestE2ESmoke_TokenVerification` — profile: `standard.profile`
- `TestE2ESmoke_ExtraArgsV2` — profile: `standard.profile`
- `TestE2ESmoke_ChainStatus` — profile: `standard.profile`
- `TestE2ESmoke_JobQueue` — profile: `standard.profile`
- `TestE2ESmoke_Replay` — profile: `standard.profile`
- `TestE2EReorg` — profile: `standard.src-auto-mine.profile`
- `TestChaos_AggregatorOutageRecovery` — profile: `standard.profile`
- Phased `TestE2ESmoke_Basic` — profile: `phased.profile`

**Chainlink node tests** (`test-cl-smoke.yaml`):
- `TestE2ESmoke_Basic` — profile: `standard.clnode.profile`
- `TestE2ESmoke_Basic_OneExecPerChain` — profile: `standard.one-exec-per-chain.profile` (clnode variant)
- `TestE2ESmoke_TokenVerification` — profile: `standard.clnode.profile`
- `TestE2ESmoke_ExtraArgsV2` — profile: `standard.clnode.profile`
- `TestHA_CrossComponentDown` — profile: `standard.ha.clnode.profile`
- Phased `TestE2ESmoke_Basic` — profile: `phased.clnode.profile`

When the user describes a CI failure, match it to the test name and profile above to know what to run locally.

---

### The preferred way: `ccv test`

`ccv test` handles build, env startup, and test execution in one command. Run from `build/devenv`.

```bash
# Full cycle (build images, start env, run test, all output to log):
ccv test --profile standard.clnode.profile --pattern TestE2ESmoke_Basic --timeout 20m --log /tmp/test.log

# Skip rebuild if images are already up-to-date:
ccv test --profile standard.profile --pattern TestE2ESmoke_Basic --build=false --log /tmp/test.log

# Named suite aliases (no --pattern needed):
ccv test smoke --profile standard.profile --log /tmp/test.log
ccv test load  --profile standard.profile --log /tmp/test.log

# Against an already-running environment (no profile, no build):
ccv test --pattern TestE2ESmoke_Basic --build=false --log /tmp/test.log
```

**Key flags:**

| Flag | Default | Notes |
|------|---------|-------|
| `--profile` | — | Profile file (`.profile`) that selects env config + type |
| `--pattern` | — | Raw Go test pattern; mutually exclusive with suite name |
| `--build` | `true` | Build Docker images first; pass `--build=false` to skip |
| `--timeout` | `0` (unlimited) | Go test timeout |
| `--log <path>` | — | Write ALL output to file; terminal shows only progress lines |

The `--log` flag redirects at the OS fd level — it captures docker build output, env startup, CTF framework subprocess output, and go test output. Always use it when running from Claude Code to avoid token-heavy output.

> ⚠️ Do NOT use CI-only profiles (e.g. `standard.clnode.ci.profile`) locally — they reference CI-specific image tags and paths that fail locally. Use the non-CI variants (`standard.clnode.profile`, `phased.clnode.profile`, etc.).

---

### Manual steps (if not using `ccv test`)

#### 1. Rebuild Docker images

```bash
ccv down
just build-docker-dev
```

#### 2. For Chainlink node (-cl) tests only: update the chainlink repo

The `-cl` environment loads the `chainlink` repo from the directory next to `chainlink-ccv`. It must reference the current commit of this repo.

```bash
COMMIT=$(git -C /path/to/chainlink-ccv rev-parse HEAD)
cd /path/to/chainlink   # must be a sibling of chainlink-ccv
go get github.com/smartcontractkit/chainlink-ccv@$COMMIT
gomods tidy
```

#### 3. Start the environment

```bash
ccv up --profile standard.profile
ccv up --profile standard.clnode.profile    # CL node variant
ccv up --profile phased.profile             # phased runtime
```

Only one environment at a time — overlapping startups collide on Docker resources.

#### 4. Run the tests

```bash
cd build/devenv/tests/e2e
go test -v -timeout 15m -count=1 -run TestE2ESmoke_Basic
```
