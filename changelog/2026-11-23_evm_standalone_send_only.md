# EVM standalone supports send-only RPC nodes

## Executive Summary

- Standalone EVM config accepts `send_only = true`, and Chainlink node-config conversion carries `SendOnly` nodes instead of dropping them with a warning.
- The existing chainlink-evm multinode client broadcasts transactions to primary and send-only nodes; no transaction-manager or send-path code changes.
- Send-only nodes no longer trigger HTTP head polling for WebSocket-capable primary nodes. A pool still requires at least one primary node.
- `ccv migrate inspect-config` reports each node's `send_only` role. Affects standalone EVM config, migration conversion and inspection, and the generated EVM config reference.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `evmconfig.BuildChainlinkEVMTOML` | behavior-changed | `BuildChainlinkEVMTOML\(` | `integration/pkg/accessors/evmconfig/chainlink_config.go:127` | [#runtime-conversion](#runtime-conversion) |
| `convertChainlinkNodeConfig` | behavior-changed | `convertChainlinkNodeConfig\(` | `integration/pkg/accessors/evmconfig/clnode_config.go:220` | [#node-config-conversion](#node-config-conversion) |
| `evmconfig.Node.SendOnly` | added | `send_only` | `integration/pkg/accessors/evmconfig/config.go:113` | [#standalone-configuration](#standalone-configuration) |
| `evmconfig.EffectiveNode.SendOnly` | added | `send_only` | `integration/pkg/accessors/evmconfig/effective_config.go:36` | [#inspection](#inspection) |
| `chainaccess.ChainEndpoint.SendOnly` | added | `\.SendOnly` | `pkg/chainaccess/inspection.go:15` | [#inspection](#inspection) |

## Breaking Changes

*No breaking changes.* Conversion warning text changes: the `dropped, SendOnly nodes have no standalone equivalent` warning is gone because the node now survives conversion.

## Migration Guide

1. Operators mounting Chainlink node TOML need no config edit. Re-run `ccv migrate inspect-config`: send-only nodes remain in `nodes` with `send_only: true`, and their old drop warnings are gone.
2. In standalone-format EVM config, set `send_only = true` on each broadcast-only endpoint and retain at least one primary node. Conversion skips an all-send-only pool; standalone-format config rejects it with `must have at least one primary node`.
3. A send-only endpoint must answer `eth_chainId` when multinode dials it and accept transaction broadcasts. It needs no WebSocket endpoint.

## New Features / Additions

### Standalone configuration

```toml
[[chains.16015286601757825753.nodes]]
name = "primary"
http_url = "https://sepolia.example.com"
ws_url = "wss://sepolia.example.com"

[[chains.16015286601757825753.nodes]]
name = "broadcast"
http_url = "https://sepolia-broadcast.example.com"
send_only = true
```

`send_only` defaults to false. Send-only nodes receive transaction broadcasts over HTTP but are never selected for reads or head subscriptions. `ws_url` and `order` are accepted but ignored on these nodes, matching Chainlink behavior. Their lack of `ws_url` does not enable HTTP polling for primary nodes that have WebSocket endpoints.

Verifiers dial send-only nodes but never submit transactions. On Hedera, chainlink-evm submits through one primary RPC, so send-only nodes receive no broadcasts.

### Node config conversion

`convertNodes` retains `SendOnly` and still names unsupported per-node settings individually. The previous whole-node drop, including its combined dropped-settings warning, is removed. An all-send-only pool still cannot serve a chain and is reported as a failed chain during node-config conversion.

### Runtime conversion

`toChainlinkEVMNode` passes `SendOnly` to chainlink-evm's existing `client.NewEvmClient` path. Only primary nodes participate in the fallback that sets `DefaultNewHeadsPollInterval` when no explicit polling interval exists. No TXM or transaction-sender implementation changes were needed.

### Inspection

`EffectiveNode` includes `send_only` for every node in the pre-cutover JSON report, and the runtime `ChainEndpoint` projection carries the same role. RPC URLs remain sanitized or absent from these views.

The generated EVM config reference includes primary and send-only node examples; regenerate it with `just config-docs` after changing node fields or comments.
