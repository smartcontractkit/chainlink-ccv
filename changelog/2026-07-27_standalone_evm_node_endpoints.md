# Standalone EVM nodes take one URL per endpoint

## Summary

The mounted EVM operator config gave every RPC node four URLs: an internal and an external one for
both HTTP and WebSocket. That split comes from CTF, which publishes each devenv chain twice so a
test can reach it from the host and a container can reach it over the Docker network. A NOP running
standalone CCV has one address for an RPC, so the four fields left it unclear which pair the process
would actually dial.

A node now has `name`, `http_url`, and an optional `ws_url`. Choosing between a container-reachable
and a host-facing address is devenv's job and happens where devenv generates config, not at runtime
inside the accessor.

## Config changes

Nodes carry one URL per endpoint:

```toml
[chains.3734403246176062136]
finality_depth = 15
txm_block_time = "2s"

[[chains.3734403246176062136.nodes]]
name = "primary"
http_url = "https://evm-rpc.example.com"
ws_url = "wss://evm-rpc.example.com"
```

`http_url` is required. `ws_url` is optional: a node without one uses HTTP head polling, and a pool
in which any node lacks a WebSocket URL polls for heads so that failover to that node stays valid.
Node order, names, and endpoint validation are unchanged.

`internal_http_url`, `external_http_url`, `internal_ws_url`, and `external_ws_url` are no longer
part of the schema. The config loader is strict, so a file that still sets them fails at startup
with `unknown fields in config` rather than starting a chain with no RPC configured. There is no
compatibility shim: nothing runs standalone EVM in production yet, and devenv regenerates its own
config on every run.

For a hand-written file, set `http_url` to the URL the CCV process itself can reach, set `ws_url`
the same way if the node has a WebSocket endpoint, and delete the four old keys.

## Validation

- Devenv-generated config carries CTF's container-reachable URLs and none of the removed keys.
  Blockchain outputs that publish only a host-facing URL, such as a testnet RPC named in an env
  TOML, fall back to it.
- A config that still uses the removed endpoint keys fails to load and names them.
- Strict decoding still rejects chainlink-evm node options that CCV does not expose.
