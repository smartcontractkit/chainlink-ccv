# Standalone EVM accessors use production chain services

## Summary

Standalone EVM accessors now run chainlink-evm's production multi-node client,
head tracker, head broadcaster, gas estimator, and transaction manager. The
early standalone-only head tracker and direct keystore transaction sender have
been removed.

The mounted EVM config remains a focused, CCV-owned operator surface. A single
explicit adapter maps its chain type and RPC endpoints into chainlink-evm's full
configuration, using upstream defaults for settings CCV does not expose.

## Behavior changes

- Every RPC node in the EVM-local config is registered with the production
  multi-node pool, so reads and transaction broadcasts can move away from an
  unhealthy endpoint. Internal URLs are preferred when present, with external
  URLs supported as a fallback.
- HTTP-only configurations use the production head tracker's polling mode.
  WebSocket subscriptions remain enabled when every configured node provides a
  WebSocket URL; mixed pools use polling so failover to any node remains valid.
- The production head tracker retains standalone CCV's 15-block finality depth
  instead of inheriting chainlink-evm's deeper generic-chain default.
- Client and head-tracker startup is deferred until `GetAccessor`, avoiding RPC
  health checks while the accessor registry itself is being constructed.
- Destination accessors start chainlink-evm TXM v2 after bootstrap injects the
  configured keystore. TXM now owns nonce tracking, fee estimation, retries,
  gas bumping, signing, and multi-node transaction submission.
- Accessors own and close their client, head-tracker, broadcaster, mailbox
  monitor, and TXM services. Keystore/TXM startup errors are returned to
  bootstrap instead of being logged and ignored.

The standalone database does not contain chainlink-core's EVM head tables, so
the production head tracker uses its supported in-memory saver. TXM v2 also
uses its chainlink-evm in-memory store and does not require those schemas.

## Validation

- Devenv's `standard.rpc-failover.profile` puts independently controllable
  primary and secondary RPC proxies in front of each Anvil chain. The CI chaos
  test removes the initially healthy primary and verifies both source head
  tracking and destination transaction submission through the secondary.
- The EVM-local config mount test verifies that all HTTP and WebSocket URLs for
  multiple nodes are preserved in order.
