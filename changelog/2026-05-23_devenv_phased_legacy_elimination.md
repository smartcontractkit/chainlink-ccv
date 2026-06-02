# Devenv phased runtime: eliminate legacy fallback component

## Summary

The `legacy_component.go` catch-all fallback is gone. All responsibilities have been
redistributed to purpose-built components. `protocol_contracts` moves from Phase 3 → Phase 2;
`committeeccv` moves from Phase 4 → Phase 3 and now owns the full committee setup pipeline.
The phased path becomes the default for all standalone smoke tests in CI.

---

## Breaking change: `legacy_component.go` deleted, legacy output keys removed

The runtime fallback (`SetFallback`) is no longer registered. Components that read
`"_legacy_cfg"`, `"_legacy_setup"`, or `"_aggregators_with_creds"` from `priorOutputs`
will get nothing; those keys are not published by any component.

`effect_executor.go` no longer calls `jobs.AcceptPendingJobs` — there are no CL nodes
in the phased path.

| What | Before | After |
|------|--------|-------|
| `legacy_component.go` | registered as fallback via `SetFallback` | deleted |
| `"_legacy_cfg"` output key | published by Legacy Phase 4 | gone |
| `"_legacy_setup"` output key | published by Legacy Phase 3 | gone |
| `"_aggregators_with_creds"` | published by Legacy Phase 2 | gone |
| `AcceptPendingJobs` | called after each phase (CL node job acceptance) | removed |

---

## Breaking change: CL node support dropped from the phased devenv

The phased startup path (`--env-mode phased`) no longer launches Chainlink nodes,
registers them with JD, or accepts their pending jobs. The `[[nodeset]]` config section
is ignored in phased mode; `Cfg.NodeSets` and `Cfg.ClientLookup` are never populated.

This is intentional: the phased devenv is a standalone-service environment. CL node
support remains fully intact in monolith mode (`--env-mode legacy`, the default for
`TestE2ESmoke_Basic` with `env.toml,env-cl.toml`). `environment_monolith.go` is
unchanged.

| What | Phased (`--env-mode phased`) | Monolith (`--env-mode legacy`) |
|------|------------------------------|-------------------------------|
| CL node containers | not launched | launched via `launchCLNodes` |
| JD node registration | standalone services only | CL nodes + standalone services |
| `AcceptPendingJobs` | removed | still called |
| `Cfg.NodeSets` | always empty | populated from `[[nodeset]]` |
| `Cfg.ClientLookup` | always nil | populated |

Tests that require CL nodes must continue to use the monolith startup path with
`env.toml,env-cl.toml`.

---

## Breaking change: phase numbers shifted for `protocol_contracts` and `committeeccv`

| Component | Before | After |
|-----------|--------|-------|
| `protocol_contracts` | `RunPhase3` | `RunPhase2` |
| `committeeccv` | `RunPhase4` | `RunPhase3` |
| `executor` (job specs) | `runPhasedEnvironmentFinish` in env startup | `RunPhase4` |
| `tokenverifier` | `runPhasedEnvironmentFinish` in env startup | `RunPhase4` (new component) |

Components must implement the correct `RunPhaseN` interface to be scheduled in the right
phase. Implement the wrong one and the runtime will silently skip your component for that
phase.

---

## Breaking change: `NewPhasedEnvironment` no longer reads `_legacy_cfg`

`environment_phased.go` previously pulled the full `*Cfg` from `out["_legacy_cfg"]`
(the legacy component's work product). It now:

1. Calls `Load[Cfg](configs)` to read the TOML baseline.
2. Syncs each service's runtime `Out` fields from the output map before calling `Store(cfg)`.

Any code path that depended on the legacy component producing a ready-to-use `*Cfg`
must instead populate its own outputs under the appropriate output key.

Before:
```go
// environment_phased.go — old
cfg, ok := out[legacyCfgKey].(*Cfg)
```

After:
```go
// environment_phased.go — new
cfg, err = Load[Cfg](configs)
// then explicit Out-field syncs for each service:
if blockchains, ok := out["blockchains"].([]*blockchain.Input); ok { cfg.Blockchains = blockchains }
if executors, ok := out["executor"].([]*executorsvc.Input); ok     { cfg.Executor = executors }
if fake, ok := out["fake"].(*services.FakeInput); ok               { cfg.Fake = fake }
// ... aggregators, verifiers, indexers, tokenverifiers, CLDF
```

---

## New: `committeeccv` Phase 3 owns the full committee setup pipeline

`committeeccv.RunPhase3` now performs everything that was previously split between
Legacy Phase 2 and `runPhasedEnvironmentFinish`:

1. HMAC credential generation per aggregator (`agg.EnsureClientCredentials()`)
2. TLS certificate generation from aggregator container names
3. Standalone verifier container launch
4. Verifier + JD registration and WSRPC connection wait
5. Topology enrichment with verifier signer keys
6. `GenerateAggregatorConfig` changeset per aggregator
7. Standalone aggregator container launch
8. Job spec emission (`JobProposalEffect`) for verifiers and aggregators

Reads from `priorOutputs`: `"blockchainOutputs"`, `"jd"`, `"_env"`, `"_topology"`, `"_selectors"`, `"_ds"`, `"_impls"`, `"_use_legacy_configure_lane"`.

Publishes: `"aggregators"`, `"verifiers"`, `"shared_tls_certs"`.

---

## New: `executor` Phase 4 — job spec generation moved to the component

`executor.RunPhase4` generates executor job specs using deployed contract addresses
(`_env`, `_topology`, `_ds`) and emits `JobProposalEffect` for each standalone executor.
This replaces the `generateExecutorJobSpecs` call in the old `runPhasedEnvironmentFinish`.

---

## New: `tokenverifier` Phase 4 component extracted

`tokenverifier.RunPhase4` decodes `[[token_verifier]]` config, generates token verifier
config via `GenerateTokenVerifierConfig` changeset, and launches token verifier containers.
Previously this was embedded in `runPhasedEnvironmentFinish`.

Reads from `priorOutputs`: `"blockchainOutputs"`, `"jd"`, `"_env"`, `"_ds"`, `"fake"`.

Publishes: `"token_verifier"`.

---

## New: `services/committeeverifier/launch.go` — public launch helpers

`LaunchStandaloneVerifiers` and `RegisterStandaloneVerifiersWithJD` are now exported
from `build/devenv/services/committeeverifier/`. Previously the equivalent logic was
private inside `environment.go`.

```go
// Launch verifiers, then register with JD
err = committeeverifier.LaunchStandaloneVerifiers(verifiers, aggregators, blockchainOutputs, modifiers)
err = committeeverifier.RegisterStandaloneVerifiersWithJD(ctx, verifiers, offchainClient)
```

---

## New: `deploy.EnrichTopologyWithVerifiers` — public topology enrichment

A public wrapper around the previously private `enrichEnvironmentTopology`. Mutates the
topology in-place so that any Phase 4 component reading the same pointer sees updated
signer addresses after `committeeccv.RunPhase3` runs.

```go
deploy.EnrichTopologyWithVerifiers(topology, verifiers)
```

---

## Bug fixes

- **`config.loadRaw`**: overlay configs now deep-merge nested TOML tables instead of
  shallow-replacing them (`maps.Copy` → `deepMergeMaps`). An overlay that sets only
  `environment_topology.executor_pools` no longer clobbers `nop_topology` and other
  sibling keys.

- **`NewPhasedEnvironment`**: executor, fake, and blockchain `Out` fields were not
  synced back into `cfg` before `Store(cfg)`, causing nil pointer panics in tests
  that read `executor.Out.ContainerName`, `fake.Out.ExternalHTTPURL`, and
  `blockchain.Out.*`. All three are now synced.
