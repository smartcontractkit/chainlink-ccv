# Standalone Beholder chain plugin config events (CHIP Ingress)

## Executive Summary

- Standalone CCV services now emit the same `ChainPluginConfig` beholder event a core node
  relayer emits, so the existing detection of node operators sharing RPC endpoints covers
  standalone deployments (previously CL-mode nodes only).
- The beholder config gains `ChipIngressEndpoint` / `ChipIngressInsecureConnection` (same names
  as the core node's Beholder section); setting the endpoint makes
  `monitoring.SetupBeholder` create the chip ingress (dual-source) emitter, so custom events
  reach both the OTel collector and CHIP Ingress.
- Each EVM chain runtime (`standaloneChain`) owns one
  `monitoring.ChainPluginConfigEmitter`, modeled on chainlink-common's
  `pkg/loop/plugin_relayer_emitter.go`: identical beholder attributes, identical 3-minute emit
  interval, identical endpoint normalization (scheme://host only).
- Affects: `common/monitoring` (config, setup, new emitter), the EVM accessor runtime, the
  module's dependency on `chainlink-protos/node-platform`, and the generated config docs.
- No breaking changes: both new config fields are optional and default to off.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `monitoring.BeholderConfig.ChipIngressEndpoint` | added | `ChipIngressEndpoint` | `common/monitoring/config.go` | [#chip-ingress-config-fields](#chip-ingress-config-fields) |
| `monitoring.BeholderConfig.ChipIngressInsecureConnection` | added | `ChipIngressInsecureConnection` | `common/monitoring/config.go` | [#chip-ingress-config-fields](#chip-ingress-config-fields) |
| `monitoring.SetupBeholder` | behavior-changed | `SetupBeholder` | `common/monitoring/setup.go` | [#chip-ingress-config-fields](#chip-ingress-config-fields) |
| `monitoring.BeholderConfig.Validate` | behavior-changed | `chip_ingress_endpoint requires` | `common/monitoring/config.go` | [#chip-ingress-config-fields](#chip-ingress-config-fields) |
| `monitoring.ChainPluginConfigEmitter` | added | `ChainPluginConfigEmitter` | `common/monitoring/chain_plugin_config_emitter.go` | [#chainpluginconfigemitter](#chainpluginconfigemitter) |
| `monitoring.NewChainPluginConfigEmitter` | added | `NewChainPluginConfigEmitter` | `common/monitoring/chain_plugin_config_emitter.go` | [#chainpluginconfigemitter](#chainpluginconfigemitter) |
| `monitoring.DefaultChainPluginConfigEmitInterval` | added | `DefaultChainPluginConfigEmitInterval` | `common/monitoring/chain_plugin_config_emitter.go` | [#chainpluginconfigemitter](#chainpluginconfigemitter) |
| `evm.standaloneChain.configEmitter` | behavior-changed | `configEmitter` | `integration/pkg/accessors/evm/standalone_chain.go` | [#per-chain-emission-in-the-evm-runtime](#per-chain-emission-in-the-evm-runtime) |
| `github.com/smartcontractkit/chainlink-protos/node-platform` | added | `node-platform` | `go.mod` | [#protos-dependency](#protos-dependency) |

## Breaking Changes

*No breaking changes.* Both config fields are optional; an unset `ChipIngressEndpoint` keeps the
previous behavior (custom events go only to the OTel collector). Strict-decoding deployments that
already carried these keys under `[Monitoring.Beholder]` previously failed on unknown fields;
they now load.

## Migration Guide

To publish chain plugin config events from a standalone service (committee verifier, token
verifier, executor — anything that runs EVM accessors):

1. Set `ChipIngressEndpoint` (and, for a plaintext endpoint,
   `ChipIngressInsecureConnection = true`) under `[Monitoring.Beholder]` in the bootstrap config.
   The OTel exporter must be the gRPC one (`OtelExporterGRPCEndpoint`): the HTTP exporter path
   does not wire chip ingress, and the config now fails validation on that combination.

   ```toml
   [Monitoring.Beholder]
   Enabled = true
   OtelExporterGRPCEndpoint = "otel-collector:4317"
   # ... existing OTel exporter settings ...
   ChipIngressEndpoint = "chip-ingress:9090"
   ```

2. Ensure the service has a CSA (Ed25519) key — it already does in JD mode and in local-postgres
   mode; in local-KMS mode set `ed25519_key_id`. The CSA public key authenticates the beholder
   client and is carried as the event's `csa_public_key`, matching the core node's events. With
   no CSA key the events are still emitted but carry an empty key (a startup warning is logged by
   the emitter constructor).

No code changes are required in services: the EVM accessor runtime starts the emitter
automatically for every chain it serves.

## New Features / Additions

### Chip ingress config fields

- **What changed:** `monitoring.BeholderConfig` gained
  `ChipIngressEndpoint string` (`toml:"ChipIngressEndpoint"`) and
  `ChipIngressInsecureConnection bool` (`toml:"ChipIngressInsecureConnection"`), and
  `monitoring.SetupBeholder` maps them onto `beholder.Config.ChipIngressEmitterEnabled` (set when
  the endpoint is non-empty), `ChipIngressEmitterGRPCEndpoint`, and
  `ChipIngressInsecureConnection` — the same mapping the core node applies to its Telemetry
  config. With the endpoint set, `beholder.NewClient` builds the dual-source emitter (OTel
  collector + CHIP Ingress) with the same CSA auth headers as the OTel exporters.
- **Why:** CHIP Ingress is the transport the shared-RPC-endpoint detection pipeline reads; the
  OTel message emitter alone does not reach it.
- **Validation:** `BeholderConfig.Validate` now rejects `chip_ingress_endpoint` without
  `otel_exporter_grpc_endpoint` — chainlink-common only wires the chip ingress emitter in its
  gRPC beholder client (the HTTP exporter path ignores it), so the combination would otherwise
  silently never publish. This runs wherever the monitoring section is validated (bootstrap
  config load), so a misconfigured service fails at startup rather than emitting nothing.
- **Who is affected:** operators writing bootstrap configs; `aggregator` and `indexer` configs
  alias `monitoring.BeholderConfig` and inherit the fields (neither service emits chain plugin
  configs — they run no chain accessors).

### ChainPluginConfigEmitter

- **What changed:** new `monitoring.ChainPluginConfigEmitter` service
  (`common/monitoring/chain_plugin_config_emitter.go`). Once per
  `DefaultChainPluginConfigEmitInterval` (3 minutes, matching core) it marshals
  `common.v1.ChainPluginConfig{csa_public_key, chain_id, nodes}` and emits it through
  `beholder.GetEmitter()` with attributes `beholder_domain="node-platform"`,
  `beholder_entity="common.v1.ChainPluginConfig"`,
  `beholder_data_schema="/node-platform/common/v1"` — byte-for-byte the core node's event shape.
  Endpoints are normalized to `scheme://host` (no port/userinfo/path) with the same rules as the
  core emitter, so the same RPC endpoint produces the same reported value regardless of which
  mode reported it. An empty `csaPublicKey` argument falls back to
  `beholder.GetClient().Config.AuthPublicKeyHex`.
- **Deliberate deviation from the pinned upstream emitter:** the pinned chainlink-common version
  additionally calls `durableemitter.GlobalEmit`; CCV never initializes a durable emitter, so
  this emitter follows the referenced upstream revision (beholder.txt) and skips that call.
- **Usage:** constructed per chain by the EVM accessor runtime; other chain families (or test
  tooling) can construct it directly with `(lggr, csaPublicKey, chainID, rawNodes)` where
  `rawNodes` maps each node to its `label -> URL` endpoints.

### Per-chain emission in the EVM runtime

- **What changed:** `newStandaloneChain` builds a `ChainPluginConfigEmitter` from the chain's
  `Info` (`ChainID` + `Nodes`, labeled `HTTPURL`/`WSURL` like the core EVM relayer) and starts it
  with the chain's other services; `Close` stops it first. One emitter per accessor runtime, so
  JD job replacement restarts emissions with the new job's chains and local mode emits for the
  chains the mounted config serves.
- **When it emits:** the emitter is unconditional — with Beholder disabled the global emitter is
  a no-op, so nothing is published and no config gating is needed in the accessor.

### Protos dependency

- **What changed:** `github.com/smartcontractkit/chainlink-protos/node-platform` moved from an
  indirect to a direct dependency (`common/v1` provides `ChainPluginConfig`/`Node`). The version
  is unchanged (`v0.0.0-20260709145319-7782fb89eb16`, the one chainlink-common already pins);
  `go.sum` is untouched.

## Compatibility & Requirements

- **Minimum versions:** no dependency bumps; uses `chainlink-common`
  `v0.11.2-0.20260915214759-02f2214d5823` as already pinned.
- **Feature flags / rollout:** off unless `[Monitoring.Beholder].ChipIngressEndpoint` is set.
- **Chain coverage:** EVM only. The shared surface is deliberately chain-agnostic — bootstrap
  config fields, `SetupBeholder` chip-ingress mapping, and `NewChainPluginConfigEmitter` carry no
  family details (no EVM types, no family-specific labels; `rawNodes` labels are family-chosen).
  Solana/Canton accessors live in their own repos, which bootstrap through this module: after
  bumping their chainlink-ccv pin they implement the per-chain adapter (build `rawNodes` from the
  family config, own the emitter lifecycle in the accessor runtime) with no shared-code changes.

## Examples

```go
// Example: a chain-family adapter emitting its chain's plugin config. The family owns only the
// rawNodes construction (label -> endpoint URL per node; labels are family-chosen) and the
// lifecycle (start with the chain's runtime, close with it). Everything else — CSA key fallback,
// normalization, interval, beholder attributes — is shared and identical across families.
emitter := monitoring.NewChainPluginConfigEmitter(lggr, "", chainID, rawNodes)
if err := emitter.Start(ctx); err != nil { /* ... */ }
defer emitter.Close()
```

EVM's adapter is `rawNodeURLs` in `integration/pkg/accessors/evm/standalone_chain.go` (labels
`HTTPURL`/`WSURL`, matching the core EVM relayer); Solana's would use label `URL` (matching the
upstream chainlink-solana LOOP emitter), Canton's its ledger API URL.

## References

- Upstream emitter mirrored here: `chainlink-common/pkg/loop/plugin_relayer_emitter.go`
  (revision `67bf1aaa3e1e8b2e56e398906def473ea6e6ec8d`, per beholder.txt).
- Core node config mapping: chainlink `core/cmd/shell.go` (`Telemetry.ChipIngressEndpoint` →
  `beholder.Config.ChipIngressEmitterGRPCEndpoint`).
- Prior entries this builds on: `2026-06-30_beholder_bootstrap_logging.md`,
  `2026-06-24_monitoring_config_in_bootstrap.md`.
