# Runbook: Message Unexecuted After 15 Minutes

## Scenario

An external message-aware alert fires:

> CCIP message `0xabc...def` has not been executed after 15 minutes.

The executor metrics deliberately do not include `message_id` labels. Before
using this runbook, use Atlas, the indexer, logs, or the message trace viewer
to resolve the message to its `source_chain_name` and `dest_chain_name`. Set the
matching Grafana dashboard variables.

This runbook determines whether executors received the message, whether it is
blocked in scheduling or execution, and whether the problem affects one
executor, an executor pool, a lane, or shared infrastructure.

## 1. Confirm Executor Indexer Connectivity

The executor has no generic process-liveness metric. The indexer heartbeat is
an indirect liveness signal: a fresh heartbeat proves that an executor process
is running and can reach an indexer.

```promql
max by (node_id) (
  time() - executor_indexer_last_heartbeat_timestamp
)
```

```promql
sum by (node_id) (
  increase(executor_indexer_heartbeat_failure_total[15m])
)
```

```promql
sum by (node_id) (
  increase(executor_all_indexers_failed_total[15m])
)
```

A stale heartbeat, heartbeat failures, or all-indexers-failed events indicate
that the executor may not be receiving verified messages. Investigate the
executor process, indexer endpoints, network connectivity, and indexer
failover before continuing.

## 2. Confirm the Executor Observed the Message

```promql
sum by (node_id, stage, outcome, reason) (
  increase(executor_message_transitions_total{
    source_chain_name=~"$source_chain_name",
    dest_chain_name=~"$dest_chain_name"
  }[15m])
)
```

If no executor records `discovery/discovered`, verify that the verifier stored
the result, the indexer exposed it, and the executor is configured for the
destination lane.

If `scheduling/skipped` has reason `not_executor_for_destination`, that node is
not in the executor pool for this destination chain. This is expected for
non-members; investigate the nodes that are pool members.

If `scheduling/skipped` has reason `leader_election_failed`, investigate
executor-pool configuration and leader-election dependencies.

## 3. Check Scheduling and Queue Health

```promql
max by (node_id) (
  executor_messages_pending{
    source_chain_name=~"$source_chain_name",
    dest_chain_name=~"$dest_chain_name"
  }
)
```

```promql
max by (node_id) (
  executor_oldest_pending_message_age_seconds{
    source_chain_name=~"$source_chain_name",
    dest_chain_name=~"$dest_chain_name"
  }
)
```

```promql
max by (node_id) (
  executor_messages_in_flight{
    source_chain_name=~"$source_chain_name",
    dest_chain_name=~"$dest_chain_name"
  }
)
```

Growing pending work or an oldest pending age above 15 minutes indicates a
scheduling or worker-capacity problem. High in-flight work with a stable queue
indicates slow or blocked execution attempts. A backlog isolated to one node
indicates a local executor issue; the same pattern across pool members suggests
a lane or shared dependency issue.

## 4. Diagnose the Execution Decision

```promql
sum by (node_id, outcome, reason) (
  increase(executor_message_transitions_total{
    source_chain_name=~"$source_chain_name",
    dest_chain_name=~"$dest_chain_name",
    stage="execution"
  }[15m])
)
```

| Outcome or reason | Diagnosis | Next action |
| --- | --- | --- |
| `attempted` | A worker began processing the message. | Continue to failure and retry checks. |
| `skipped/remote_chain_cursed` | The destination considers the source lane cursed. | Confirm curse state. |
| `skipped/curse_state_unknown` | Curse state could not be determined. | Investigate curse checker or destination RPC. |
| `skipped/already_executed` | Another executor already completed execution. | Confirm destination-chain execution state; the alert may be stale. |
| `skipped/honest_attempt_exists` | Another honest executor or third party already attempted execution. | Confirm destination-chain execution state and attempt outcome. |
| `skipped/no_verifier_results` | Required verifier results are not available yet. | Return to verifier/indexer triage. |
| `skipped/poller_not_ready` | Destination execution-attempt poller is not ready. | Investigate the destination reader. |
| `succeeded` | The executor transmitted the report successfully. | Confirm destination-chain state; then close or hand off the alert. |

## 5. Diagnose Execution Failures and Retries

```promql
sum by (node_id, retryable, error_class) (
  increase(executor_message_failures_total{
    source_chain_name=~"$source_chain_name",
    dest_chain_name=~"$dest_chain_name",
    stage="execution"
  }[15m])
)
```

```promql
sum by (node_id, reason) (
  increase(executor_message_transitions_total{
    source_chain_name=~"$source_chain_name",
    dest_chain_name=~"$dest_chain_name",
    stage="retry",
    outcome="retry_scheduled"
  }[15m])
)
```

| Error class or retry reason | Diagnosis |
| --- | --- |
| `execution_state_read_failed` | Destination execution-state RPC read failed. |
| `verification_data_read_failed` | Executor could not fetch verifier results or destination quorum data. |
| `quorum_not_met` | Verifier results are present but insufficient for destination quorum. |
| `quorum_impossible` | Destination quorum configuration cannot be satisfied; terminal. |
| `honest_attempt_check_failed` | Destination attempt checker failed. |
| `message_encoding_failed` or `transmitter_rejected` | Terminal report construction or transmitter failure. |
| `transmission_failed` | Destination transmission failed and will retry. |
| `data_not_ready` | Fast retry while prerequisite data or state becomes available. |
| `execution_contended` | Retry after transmission contention, using the executor-pool stagger. |

## 6. Check Destination Reader Failures

```promql
sum by (node_id) (
  increase(executor_destination_reader_critical_failure_total{
    dest_chain_name=~"$dest_chain_name"
  }[15m])
)
```

A non-zero value means the destination reader entered an unrecoverable failure
state. Treat this as an urgent destination-lane incident; executor retries
cannot recover until the reader is restored.

## 7. Determine Incident Scope

```promql
topk(10,
  max by (source_chain_name, dest_chain_name) (
    executor_oldest_pending_message_age_seconds
  )
)
```

If a single executor reports failures while other pool members progress, treat
it as a local node issue. If most pool members share the same failure class,
treat it as a destination-chain, verifier/indexer, or shared infrastructure
incident. If the executor records `succeeded`, verify destination-chain state
before investigating further downstream.

## 8. Remediate or Hand Off

Executor-side problems (queue capacity, destination reader, transmitter) are
resolved in the executor's own infrastructure. When triage points upstream —
`skipped/no_verifier_results`, `quorum_not_met`, or the verifier never stored a
result — return to
[Runbook: Message Unverified After 15 Minutes](./unverified-message-after-15-minutes.md)
and then
[Runbook: Remediating a Stuck or Dropped Message](./remediating-stuck-or-dropped-messages.md)
for verifier-side recovery levers.
