# Phased devenv: CL-node support restored as a clean component

## Summary

Restores Chainlink-node ("CL-node") verifier mode in the phased devenv
(`--env-mode phased`) by introducing a dedicated `committeeccv_clnode`
Phase 3 component. The former `clnode` Phase-1 config-vehicle package is
deleted; all CL-node logic is now isolated in one file designed for future
removal when CL nodes leave the devenv.

---

## Breaking change: `[clnode]` config key removed

The `[clnode]` TOML section is no longer recognized. CL-node devenv
configuration moves into `[committeeccv_clnode]`, which embeds both the
committee fields (aggregators, verifiers) and the CL-node fields (node
sets, funding amounts).

| What | Before | After |
|------|--------|-------|
| Config section for node sets | `[clnode]` | `[committeeccv_clnode]` |
| Aggregators in CL-node mode | `[[committeeccv.aggregator]]` | `[[committeeccv_clnode.aggregator]]` |
| CL-mode verifiers | `[[committeeccv.verifier]]` with `mode = "cl"` | `[[committeeccv_clnode.verifier]]` with `mode = "cl"` |
| Disable standalone in CL overlay | (implicit — only one ran) | `[committeeccv]` with `aggregator = []`, `verifier = []` |

Before (`env-cl-phased.toml`):
```toml
[clnode]
version = 1
cl_nodes_funding_eth = 50
[[clnode.node_sets]]
  name = "don"
  nodes = 2
  ...

[[committeeccv.verifier]]
  mode = "cl"
  ...
```

After (`env-cl-phased.toml`):
```toml
# Disable the standalone component (becomes a no-op)
[committeeccv]
version = 1
aggregator = []
verifier = []

# CL-node variant: self-contained, delete when CL nodes leave
[committeeccv_clnode]
version = 1
cl_nodes_funding_eth = 50
[[committeeccv_clnode.node_sets]]
  name = "don"
  nodes = 2
  ...
[[committeeccv_clnode.aggregator]]
  ...
[[committeeccv_clnode.verifier]]
  mode = "cl"
  ...
```

---

## New: `committeeccv_clnode` Phase 3 component

Registered under config key `"committeeccv_clnode"` in
`build/devenv/components/committeeccv/component_clnode.go`. It is a
drop-in replacement for the standalone `committeeccv` component in
CL-node mode: runs all the same Phase 3 steps, plus step 1b which bakes
aggregator HMAC secrets into node specs before boot and launches,
registers, and connects the CL node sets to JD.

The component publishes `"_clnode_clients"` (a `*jobs.NodeSetClientLookup`)
which the effect executor uses to call `AcceptPendingJobs` before
`SyncAndVerifyJobProposals`.

To remove CL nodes from the devenv later: delete `component_clnode.go`
and the `[committeeccv_clnode]` sections from the config overlays.

---

## New: phased CL-node CI test

`test-cl-smoke.yaml` gains a `Phased TestE2ESmoke_Basic` matrix entry
that runs `TestE2ESmoke_Basic_Phased` with:

```
config: env-phased.toml,env-cl-phased.toml,env-cl-ci-phased.toml
flags:  --env-mode phased
```

`env-cl-ci-phased.toml` is updated from `[clnode]` to
`[committeeccv_clnode]` so the CI image override applies to the correct
component.

---

## Internal refactor: `committeeccv` shared helpers

`committeeccv/component.go` extracts `phase3Inputs`, `parsePhase3Inputs`,
`ensureAggregatorCredentials`, and `runPhase3Core` so both components
share the same Phase 3 logic without duplication. No behavioral change to
the standalone path.
