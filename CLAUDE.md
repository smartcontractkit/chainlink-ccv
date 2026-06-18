# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Primary Objective

The main focus of work in this repo is **multi-service refactoring** guided by **enforcing layer boundaries**. When suggesting or making changes:

- Prefer solutions that tighten the dependency graph rather than loosen it. The `depguard` rules in `.golangci.yaml` encode the intended layering — treat violations as design signals, not just lint errors.
- `protocol/` is the foundation. Types and abstractions that belong to the protocol layer should live there, not leak into service-specific packages.
- `verifier/` and `executor/` should depend on `protocol/` and `common/` abstractions, not on each other or on `chainlink/v2`.
- When refactoring spans multiple services, look for the right shared abstraction in `common/` or `pkg/` before duplicating logic.
- Prefer changing interfaces and boundaries over working around them with wrappers or adapters.

## Build Commands

This project uses [`just`](https://github.com/casey/just) as a command runner. Run `just --list` to see all targets.

```bash
just install-go-tools   # Install golangci-lint, mockery, protoc-gen-go, buf, etc.
just build              # Build all services (also available per-service: cd aggregator && just build)
just generate           # Run go generate + mockery to regenerate mocks
just mock               # Regenerate mocks only (uses .mockery.yaml)
just fmt                # Format all Go files via golangci-lint
just tidy               # Tidy go.mod across all modules
```

Individual service builds (each service directory has its own Justfile):
```bash
cd aggregator && just build      # Production image: aggregator:latest
cd aggregator && just build-dev  # Dev image with hot-reload: aggregator:dev
```

## Test Commands

```bash
just test                        # All tests: -race -shuffle on -fullpath -v
just test short="-short"         # Unit tests only (skip integration/slow tests)
just test-coverage               # All tests with coverage → coverage.out
just test-coverage short="-short" coverage_file="cov.out"
```

To run a single test:
```bash
go test -v -run TestMyTestName ./path/to/package/...
```

Dev environment tests (requires devenv to be running):
```bash
cd build/devenv/tests/services && go test -v -run TestService
cd build/devenv/tests/e2e && go test -v -run TestE2ESmoke
```

## Lint

```bash
just lint               # Run golangci-lint (v2.6.0, configured in .golangci.yaml)
just lint fix           # Run with --fix to auto-correct issues
just shellcheck         # Lint all .sh files
```

Key `depguard` rules enforced by the linter:
- `protocol/` may only import stdlib + `chainlink-ccv/protocol` (no `chainlink/v2`)
- `executor/` and `verifier/` packages may not import `chainlink/v2`
- Test files must use `stretchr/testify`, not `test-go/testify`

## Code Generation

Protocol buffers: `just generate` (uses `buf`)
Mocks: `just mock` (uses mockery v2, config in `.mockery.yaml`)
OpenAPI client for indexer: generated via `oapi-codegen`

## Architecture

Chainlink CCV is a **modular cross-chain verification and execution system**. Messages created on a source chain are verified offchain, indexed, and then executed on a destination chain.

### Data Flow

```
Source Chain → OnRamp → [Verifiers] → [Indexer] → [Executor] → OffRamp → Destination Chain
```

### Core Services

**`protocol/`** — Pure Go protocol abstractions with no `chainlink/v2` dependency. Contains message types, hashing, signature verification, finality, and chain status primitives. This is the canonical definition of protocol types.

**`verifier/`** — Reads messages from source chains and produces verification results. Multiple implementations:
- Committee (DON-based, default): aggregates from multiple nodes
- Token/USDC: wraps CCTP token transfers
- ZK, Custom: pluggable via build arg `VERIFIER_TYPE=token`

**`aggregator/`** — Aggregates committee verifier results from multiple nodes into a single result. Uses PostgreSQL for storage.

**`indexer/`** — Central query API (REST/OpenAPI) over PostgreSQL. Executors use it to fetch verification results. Exposes `IndexerAPI`; client in `pkg/indexerclient/`.

**`executor/`** — Fetches verified messages from the indexer and executes them on destination chains. Includes leader election (`pkg/leaderelector/`) and a priority message heap (`pkg/message_heap/`).

**`bootstrap/`** — Shared startup logic used by all services: keystore lifecycle, Job Distributor (JD) integration, DB setup, and health-check HTTP server.

**`pricer/`** — Standalone service that updates gas/token prices on-chain. Example of a product-specific binary (PSB).

### Supporting Packages

- `common/` — Shared utilities: JD client, batching, metrics interfaces, committee logic
- `pkg/chainaccess/` — Source/destination chain readers and contract transmitters
- `pkg/indexerclient/` — Generated client for the indexer REST API
- `cli/` — CLI tools for chain status and job queue queries
- `internal/mocks/` — Mockery-generated mocks (do not edit manually)

### Dev Environment (`build/devenv/`)

Full local environment managed by the `ccv` CLI:
```bash
cd build/devenv && just cli     # Build the ccv CLI binary
./ccv --help                    # Manage the full local stack
```

The devenv spins up: 2 Anvil chains, 4 Chainlink nodes, Job Distributor, all services, and an observability stack (Prometheus, Loki, Grafana).

- `environment.go` — Full environment setup (~2000 LOC); start here to understand how services are wired together
- `config.go` / `env.toml` — Environment configuration
- `build/devenv/services/` — Per-service config templates

#### Phased Component Runtime (`build/devenv/runtime/`)

The devenv has a component-based startup path (`--env-mode phased`) that replaces the monolithic `NewEnvironment`. It uses a 4-phase execution model with write-once output keys.

**Config**: phased mode uses the dedicated `build/devenv/env-phased.toml` (run `--env-mode phased up env-phased.toml`), a standalone copy of `env.toml` that omits the monolith-only keys (`cl_nodes_funding_eth`, `cl_nodes_funding_link`, `high_availability`, `[cldf]`). Monolith mode keeps using `env.toml` (+ `env-cl.toml`). Keep the shared sections of the two files in sync until they are formally split.

**Entry point**: `NewEnvironmentPhased` in `build/devenv/environment_phased.go` — calls `devenvruntime.NewEnvironment` with the component registry.

**Runtime package** (`build/devenv/runtime/`):
- `environment.go` — Orchestrates phases 1–4. Within a phase, every component receives `maps.Clone(phaseSnapshot)` of outputs at phase-start (siblings cannot see each other). `mergeNoOverwrite` enforces write-once keys across all phases.
- `component.go` — `Phase1Component` through `Phase4Component` interfaces. Each `RunPhaseN` returns `(map[string]any, []Effect, error)`.
- `effects.go` — `Effect` interface + `FundingEffect`, `JobProposalEffect`, `CLNodeConfigEffect`.
- `registry.go` — `Register(key, factory)` for specific components.

**Critical constraint**: ALL Phase N components receive the same phase-start snapshot clone. A Phase 2 component **cannot** see another Phase 2 component's outputs — only outputs from phases 1 through N-1.

**Blank component imports**: All `_ "...components/..."` blank imports that trigger component `init()` registration belong in `build/devenv/environment.go`, not in any other file. This is because `environment.go` is the devenv entry point; placing blank imports elsewhere either causes linter errors (if the package has no other use) or creates circular imports.

**Components** (`build/devenv/components/`):
- `blockchains/` — Phase 1: deploys Anvil/Geth chains; publishes `"blockchains"`, `"blockchainOutputs"`
- `fake/` — Phase 1: fake services
- `jd/` — Phase 1: starts JD container; publishes `"jd"`
- `protocol_contracts/` — Phase 2: deploys contracts, configures lanes; publishes `"_env"`, `"_topology"`, `"_ds"`, `"_selectors"`, `"_impls"`, `"_cldf"`, `"_time_track"`
- `committeeccv/` — Phase 3: generates HMAC creds, launches verifiers and aggregators, configures lanes, generates committee config; publishes `"aggregators"`, `"verifiers"`, `"shared_tls_certs"`
- `executor/` — Phase 3: launches executor containers, registers with JD, generates job specs; emits `FundingEffect` + `JobProposalEffect`; publishes `"executor"`
- `pricer/` — Phase 3: launches pricer service; emits `FundingEffect`
- `indexer/` — Phase 4: launches indexer containers; reads `"aggregators"` from Phase 3
- `tokenverifier/` — Phase 4: launches token verifier containers

**Effect executor** (`build/devenv/effect_executor.go`): Runs after each phase. Executes `CLNodeConfigEffect` → `FundingEffect` → `JobProposalEffect` in fixed order.

**Current phase output map**:

| Phase | Component | Key | Type |
|-------|-----------|-----|------|
| 1 | blockchains | `"blockchains"` | `[]*blockchain.Input` |
| 1 | blockchains | `"blockchainOutputs"` | `[]*blockchain.Output` |
| 1 | jd | `"jd"` | `*jobs.JDInfrastructure` |
| 2 | protocol_contracts | `"_env"` | `*deployment.Environment` |
| 2 | protocol_contracts | `"_topology"` | `*ccvdeployment.EnvironmentTopology` |
| 2 | protocol_contracts | `"_ds"` | `datastore.MutableDataStore` |
| 3 | committeeccv | `"aggregators"` | `[]*services.AggregatorInput` |
| 3 | committeeccv | `"shared_tls_certs"` | `*services.TLSCertPaths` |
| 3 | executor | `"executor"` | `[]*executorsvc.Input` |

**Remaining extraction order** (tracked in task list):
1. Extract `protocol_contracts` as Phase 3 component (plan finalized)
2. Extract `CommitteeCCV` as full Phase 3 component — bundles aggregators + CL nodes + verifiers; CL nodes are internal, not a separate component
3. Misc cleanups: `runPhase` helper to DRY phases 2–4, `unclaimedKeys` deduplication, generic `decode` helper, `slices.Sorted(maps.Keys(...))` replacement

### Key Conventions

- All services are bootstrapped via the `bootstrap/` package; new services should follow the same pattern.
- Configuration is TOML-based; see `config.example.toml` in each service directory.
- Database migrations use `goose`; migration files live in each service's `migrations/` directory.
- Each service has its own `go.mod` (multi-module repo); `gomods` is used to run commands across all modules.

## Agent skills

### Issue tracker

Issues and PRDs are tracked as local markdown files under `.scratch/<feature-slug>/`, with triage state in a `Status:` line. See `docs/agents/issue-tracker.md`.

### Triage labels

Uses the five canonical triage roles (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`) — default strings, no overrides. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout: `CONTEXT.md` + `docs/adr/` at repo root. See `docs/agents/domain.md`.

<!-- code-review-graph MCP tools -->
## MCP Tools: code-review-graph

**IMPORTANT: This project has a knowledge graph. ALWAYS use the
code-review-graph MCP tools BEFORE using Grep/Glob/Read to explore
the codebase.** The graph is faster, cheaper (fewer tokens), and gives
you structural context (callers, dependents, test coverage) that file
scanning cannot.

### When to use graph tools FIRST

- **Exploring code**: `semantic_search_nodes` or `query_graph` instead of Grep
- **Understanding impact**: `get_impact_radius` instead of manually tracing imports
- **Code review**: `detect_changes` + `get_review_context` instead of reading entire files
- **Finding relationships**: `query_graph` with callers_of/callees_of/imports_of/tests_for
- **Architecture questions**: `get_architecture_overview` + `list_communities`

Fall back to Grep/Glob/Read **only** when the graph doesn't cover what you need.

### Key Tools

| Tool | Use when |
|------|----------|
| `detect_changes` | Reviewing code changes — gives risk-scored analysis |
| `get_review_context` | Need source snippets for review — token-efficient |
| `get_impact_radius` | Understanding blast radius of a change |
| `get_affected_flows` | Finding which execution paths are impacted |
| `query_graph` | Tracing callers, callees, imports, tests, dependencies |
| `semantic_search_nodes` | Finding functions/classes by name or keyword |
| `get_architecture_overview` | Understanding high-level codebase structure |
| `refactor_tool` | Planning renames, finding dead code |

### Workflow

1. The graph auto-updates on file changes (via hooks).
2. Use `detect_changes` for code review.
3. Use `get_affected_flows` to understand impact.
4. Use `query_graph` pattern="tests_for" to check coverage.
