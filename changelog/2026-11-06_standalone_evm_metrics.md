# Prometheus metrics on standalone verifier and executor

## Executive Summary

- The verifier and executor application HTTP servers now expose the default Prometheus registry at `/metrics`.
- This exposes chainlink-evm's per-chain TXM, RPC-pool, and head-tracker series, whose OTel counterparts do not all carry a chain attribute.
- Existing Beholder/OTel export is unchanged.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| Verifier and executor `/metrics` endpoint | added | `"/metrics"` | `cmd/verifier/servicefactory.go`, `cmd/executor/service.go` | [#scraping](#scraping) |

## Breaking Changes

*No breaking changes.*

## Scraping

Scrape `/metrics` on the application HTTP port, not the bootstrapper port. The defaults are verifier 8100 and executor 8101; a job's `http_listen_port` overrides them. The application server starts only after its job starts.

The handler serves `prometheus.DefaultGatherer` with OpenMetrics enabled, matching the pricer's existing pattern. This makes per-chain series such as `txm_num_nonce_gaps` and `txm_reached_max_attempts` available for chain-specific alerting. No `/metrics` endpoint is added to the bootstrapper server.

## References

- Related monitoring setup: `common/monitoring/setup.go`
