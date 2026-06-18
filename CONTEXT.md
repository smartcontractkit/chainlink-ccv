# Domain Context: Chainlink CCV

## Overview

**Chainlink CCV** (Cross-Chain Verification) is a modular cross-chain verification and execution system. Messages created on a source chain are verified offchain, indexed, and then executed on a destination chain.

## Primary Design Principle

**Enforce layer boundaries** through dependency isolation. The `depguard` rules in `.golangci.yaml` encode the intended layering — treat violations as design signals, not just lint errors.

### Layer Model

```
protocol/ ← foundation (pure Go, no chainlink/v2)
   ↑
   ├─ verifier/, executor/, aggregator/ (can depend on protocol/ + common/)
   ├─ common/ (shared utilities, abstractions)
   ├─ pkg/ (cross-service utilities)
   └─ bootstrap/ (startup logic)
```

**Key rules:**
- `protocol/` may only import stdlib + `chainlink-ccv/protocol` (no `chainlink/v2`)
- `executor/` and `verifier/` packages may not import `chainlink/v2`
- Prefer changing interfaces and boundaries over working around them with wrappers or adapters

## Data Flow

```
Source Chain → OnRamp → [Verifiers] → [Indexer] → [Executor] → OffRamp → Destination Chain
```

## Core Services

### `protocol/`
Pure Go protocol abstractions. Contains message types, hashing, signature verification, finality, and chain status primitives. This is the canonical definition of protocol types — types that belong here should not leak into service-specific packages.

### `verifier/`
Reads messages from source chains and produces verification results. Multiple pluggable implementations:
- **Committee** (DON-based, default): aggregates from multiple nodes
- **Token/USDC**: wraps CCTP token transfers
- **ZK, Custom**: pluggable via build arg `VERIFIER_TYPE=token`

### `aggregator/`
Aggregates committee verifier results from multiple nodes into a single result. Uses PostgreSQL for storage.

### `indexer/`
Central query API (REST/OpenAPI) over PostgreSQL. Executors use it to fetch verification results. Exposes `IndexerAPI`; client in `pkg/indexerclient/`.

### `executor/`
Fetches verified messages from the indexer and executes them on destination chains. Includes leader election (`pkg/leaderelector/`) and a priority message heap (`pkg/message_heap/`).

### `bootstrap/`
Shared startup logic used by all services: keystore lifecycle, Job Distributor (JD) integration, DB setup, and health-check HTTP server. All services should follow the bootstrap pattern for initialization.

### `pricer/`
Standalone service that updates gas/token prices on-chain. Example of a product-specific binary (PSB).

## Supporting Packages

- `common/` — Shared utilities: JD client, batching, metrics interfaces, committee logic
- `pkg/chainaccess/` — Source/destination chain readers and contract transmitters
- `pkg/indexerclient/` — Generated client for the indexer REST API
- `cli/` — CLI tools for chain status and job queue queries
- `internal/mocks/` — Mockery-generated mocks (do not edit manually)

## Dev Environment

### Profile

A TOML file that encodes a complete, valid devenv configuration: the runtime mode (`legacy` or `phased`), an ordered list of config files, an optional output file path, and an optional description. Profiles are the canonical way to invoke `ccv up`; ad-hoc comma-separated config lists are the lower-level primitive profiles build on.

### Phased Component Runtime

The devenv (`build/devenv/`) uses a 4-phase execution model with write-once output keys:

**Phase 1**: Blockchains, Job Distributor
**Phase 2**: Protocol contracts, lanes
**Phase 3**: Committee CCV (verifiers, aggregators), executor, pricer
**Phase 4**: Indexer, token verifier

**Critical constraint**: Within a phase, every component receives the same phase-start snapshot. A Phase N component **cannot** see another Phase N component's outputs — only outputs from phases 1 through N-1.

**Blank component imports**: All `_ "...components/..."` blank imports that trigger component `init()` registration belong in `build/devenv/environment.go`, not elsewhere.

## Key Conventions

- All services are bootstrapped via the `bootstrap/` package
- Configuration is TOML-based; see `config.example.toml` in each service directory
- Database migrations use `goose`; migration files live in each service's `migrations/` directory
- Multi-module repo: each service has its own `go.mod`; use `gomods` to run commands across all modules
- Code generation: Protocol buffers via `buf`, mocks via `mockery` v2

## Refactoring Guidance

When suggesting changes:
1. **Prefer solutions that tighten the dependency graph** rather than loosen it
2. **Look for the right shared abstraction** in `common/` or `pkg/` before duplicating logic across services
3. **Enforce boundaries first, then optimize** — never work around layer violations with adapters
4. **Depguard violations are design signals** — they indicate where boundaries need refinement, not quick workarounds
