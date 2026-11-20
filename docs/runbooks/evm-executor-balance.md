# EVM executor balance monitoring

Use this package with CCV v0.22.0 or later. Enable Beholder, keep `BalanceMonitor.Enabled` at its default `true` unless there is an approved opt-out, and scrape the telemetry sidecar's private `:9464/metrics` endpoint. Standalone has no application-port `/metrics` endpoint.

## Assets

`deployment/observability/evm-executor-balance/` contains:

- `dashboard.json`: Grafana balance, sample-age, series-count, and chain-count panels.
- `thresholds.json`: reviewed native-token or fee-token minima sourced from the CCIP funding-balance policy.
- `inventory.example.json`: example public transmitter/chain pairs; replace it with the assigned inventory.
- `generate.go`: fail-closed Prometheus rule generator.
- `alerts.example.yaml`: generated two-chain example in JSON-compatible YAML, which Prometheus rule loading accepts.

The balance is an approximate `float64` in native-token or configured ERC-20 token units. Use `/transmitter-keys` or an RPC balance query for exact base units.

## Generate assigned-inventory alerts

Create one inventory entry for every assigned transmitter account and chain. Accounts are public addresses; never put private keys, passwords, or RPC credentials in this file. Every chain must have an approved threshold in `thresholds.json`. Do not invent a default for a missing chain: update the reviewed funding policy and manifest first.

From the `deployment` directory:

```bash
go run ./observability/evm-executor-balance/generate.go \
  -inventory /path/to/assigned-inventory.json \
  -thresholds observability/evm-executor-balance/thresholds.json \
  -output /path/to/ccv-executor-balance-rules.yaml

promtool check rules /path/to/ccv-executor-balance-rules.yaml
```

Install the generated file in the NOP Prometheus rule loader and import `dashboard.json` into Grafana, selecting the NOP Prometheus datasource. The generator creates three rules per account/chain pair:

| Alert | Condition | Pending period | Severity |
| --- | --- | --- | --- |
| `CCVExecutorBalanceLow` | `node_balance` below that chain's reviewed minimum | 15m | critical |
| `CCVExecutorBalanceAbsent` | no sample for the expected account/chain pair | 10m | critical |
| `CCVExecutorBalanceStale` | newest sample is over 600 seconds old | 5m | warning |

Absent and stale checks are required. Monitor startup failures degrade `/health`, but later key/RPC read failures can be logged without supplying a reliable current value.

## Prometheus filtering and queries

Apply histogram filters in the NOP scrape config, not in the telemetry sidecar. Drop only reviewed, unused histogram buckets and retain buckets needed by other dashboards:

```yaml
metric_relabel_configs:
  - source_labels: [__name__]
    regex: '<unused-histogram-name>_bucket'
    action: drop
```

The balance dashboard and generated alerts use only the plain `node_balance` gauge and `timestamp()`. They do not depend on `_bucket`, `_sum`, `_count`, or `histogram_quantile`, so filtering unused histogram buckets does not break them.

Useful checks are:

```promql
node_balance{chainFamily="EVM"}
count by (chainID, account) (node_balance{chainFamily="EVM"})
time() - timestamp(node_balance{chainFamily="EVM"})
```

## Validate coverage and cardinality

Run the package tests from `deployment`:

```bash
go test ./observability/evm-executor-balance
```

The tests generate rules for a synthetic 51-chain inventory and verify 51 rules in each group, 153 total rule evaluations per 30-second interval, and no histogram dependency. One account on 51 chains produces 51 raw balance series; additional transmitters add one series and three rules per pair. This is generator/cardinality coverage, not a substitute for a live Prometheus load test.

Before cutover and after changing scrape filters:

1. Compare `count by (chainID, account)` with the assigned inventory and confirm all 51 expected pairs where applicable.
2. Confirm each account is the generated executor transmitter, not the old CL account.
3. Compare startup values with `/transmitter-keys` or `eth_getBalance`; use the reviewed token-balance method for fee-token chains.
4. Confirm a new sample arrives after a new head and the sample-age query stays below 600 seconds.
5. Verify low, absent, and stale alerts fire in a non-production test without changing production thresholds.
6. Check Prometheus rule-evaluation duration, scrape duration, and stored-series cardinality under the full assigned inventory.
7. Confirm a monitor construction/startup failure reports degraded health without disabling transmission.
