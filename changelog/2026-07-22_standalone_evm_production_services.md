# Standalone EVM accessors use production chain services

## Summary

Standalone EVM accessors now run chainlink-evm's production multi-node client,
head tracker, head broadcaster, gas estimator, and transaction manager. The
early standalone-only head tracker and direct keystore transaction sender have
been removed.

The mounted EVM config remains a focused, CCV-owned operator surface. A single
explicit adapter derives chain type from the selector's chain ID and maps RPC
endpoints and operational overrides into chainlink-evm's full configuration,
using upstream defaults for settings CCV does not expose.

## Behavior changes

- Every RPC node in the EVM-local config is registered with the production
  multi-node pool, so reads and transaction broadcasts can move away from an
  unhealthy endpoint. Internal URLs are preferred when present, with external
  URLs supported as a fallback.
- HTTP-only configurations use the production head tracker's polling mode.
  WebSocket subscriptions remain enabled when every configured node provides a
  WebSocket URL; mixed pools use polling so failover to any node remains valid.
- Finality behavior and TXM retry cadence are configurable per chain. A zero or
  omitted `finality_depth` enables finality-tag mode, while a positive value
  selects confirmation-depth mode. `txm_block_time` sets TXM v2's retry cadence
  and is unrelated to the chain's actual block time; it defaults to the
  two-second minimum.
- Each RPC endpoint can carry its own operator-facing name for logs and health
  reports; unnamed endpoints receive a deterministic fallback.
- Client and head-tracker startup is deferred until `GetAccessor`, avoiding RPC
  health checks while the accessor registry itself is being constructed.
- Destination accessors start chainlink-evm TXM v2 after bootstrap injects the
  configured keystore. TXM now owns nonce tracking, fee estimation, retries,
  gas bumping, signing, and multi-node transaction submission. Source-only
  deployments such as the verifier never construct a TXM.
- Accessors own and close their client, head-tracker, broadcaster, mailbox
  monitor, and TXM services. Keystore/TXM startup errors are returned to
  bootstrap instead of being logged and ignored.

## Persistence boundary

Persistence is deliberately out of scope for this change. The standalone
database does not contain chainlink-core's EVM schemas, so the production head
tracker uses its supported in-memory saver and TXM v2 uses its in-memory store.
Consequently, TXM state for pending transactions is not durable across a
process crash.

Durable recovery should be added separately with a CCV-owned EVM database
boundary, migrations, and ORM wiring. Keeping that work separate avoids
silently coupling standalone deployments to chainlink-core's schema lifecycle.

## Validation

- A focused multi-node test places an unavailable RPC before a healthy RPC and
  verifies that the production client reads from the healthy endpoint.
- The EVM-local config mount test verifies that names and all HTTP and
  WebSocket URLs for multiple nodes are preserved in order.
- Devenv's `standard.rpc-failover.profile` puts independently controllable
  primary and secondary RPC proxies in front of each Anvil chain. The CI chaos
  test removes the initially healthy primary and verifies both source head
  tracking and destination transaction submission through the secondary. It
  then restarts the primary and removes the secondary, so the pool must re-dial
  an endpoint it had already marked unusable.
- The proxy schema and lifecycle are owned by the registered EVM local-network
  configurator; the environment only routes opaque family configuration.
