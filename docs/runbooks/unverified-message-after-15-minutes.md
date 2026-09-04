# Runbook: Message Unverified After 15 Minutes

## Scenario

An external message-aware alert fires:

> CCIP message `0xabc...def` has not been verified after 15 minutes.

The verifier metrics deliberately do not include `message_id` labels. Before
using this runbook, use Atlas, the indexer, logs, or the message trace viewer
to resolve the message to its `verifier_id`, `source_chain_name`, and
`dest_chain_name`. Set the matching Grafana dashboard variables.

This runbook determines whether the message is blocked in the verifier, the
responsible pipeline stage, and whether the problem affects one message, one
lane, or shared infrastructure.

## 1. Confirm Verifier Liveness

Check aggregator-side freshness:

```promql
time() - aggregator_heartbeat_verifier_heartbeat_timestamp{
  ccip_env="$ccip_env",
  caller_id=~"$csa_key"
}
```

Here, `$ccip_env` refers to the environment that is being triaged, current values
as of writing are:

- `prod_mainnet`
- `prod_testnet`
- `staging_testnet`

The CSA key is that of the nop. To specify all CSA keys, simply drop the `caller_id`
part of the query to see the freshness for all nops. For example, this would
show the delay for all mainnet nops on aggregator-1:

```promql
time() - aggregator_heartbeat_verifier_heartbeat_timestamp{
  ccip_env="prod_mainnet", 
  app="aggregator-1-mainnet"
}
```

A stale or absent heartbeat indicates that the verifier is not reporting to the
aggregator. Investigate the verifier process, deployment, heartbeat
configuration, and aggregator connectivity before continuing.

## 2. Check Source Reader Health

```promql
max by (node_id, state) (
  verifier_source_reader_state{
    verifier_id=~"$verifier_id",
    source_chain_name=~"$source_chain_name"
  } == 1
)
```

Count committee members in each state:

```promql
sum by (state) (
  max by (node_id, state) (
    verifier_source_reader_state{
      verifier_id=~"$verifier_id",
      source_chain_name=~"$source_chain_name"
    } == 1
  )
)
```

If the state is `running`, continue to step 3. This state is refreshed after a
successful source-reader poll; it is not itself a process-liveness signal. A
stopped verifier emits no replacement state and its last sample eventually
becomes stale.

If the state is `poll_error`, investigate source RPC availability, polling,
and source-reader logs. Check when polling last succeeded:

```promql
max by (node_id) (
  time() - verifier_source_reader_last_successful_poll_timestamp{
    verifier_id=~"$verifier_id",
    source_chain_name=~"$source_chain_name"
  }
)
```

If the state is `disabled`, verify configuration or deliberate operational
disablements. If it is `finality_blocked`, continue to step 3 and investigate
finality progress.

Use the per-node result to distinguish an isolated node failure from a
committee-wide issue. For example, `poll_error` on 10 of 16 members can prevent
a 9-of-16 quorum, while one failing member ordinarily cannot.

## 3. Check Finality Backlog

```promql
verifier_messages_in_flight{
  verifier_id=~"$verifier_id",
  source_chain_name=~"$source_chain_name",
  dest_chain_name=~"$dest_chain_name",
  state="pending_finality"
}
```

```promql
verifier_oldest_message_age_seconds{
  verifier_id=~"$verifier_id",
  source_chain_name=~"$source_chain_name",
  dest_chain_name=~"$dest_chain_name",
  state="pending_finality"
}
```

Growing pending work or an oldest age above 15 minutes indicates a lane-wide
finality blockage. If these values are healthy, the issue may be specific to
the alerted message; retain its trace for later correlation and continue.

## 4. Find the Last Pipeline Stage

```promql
sum by (stage, outcome, reason) (
  increase(verifier_message_transitions_total{
    verifier_id=~"$verifier_id",
    source_chain_name=~"$source_chain_name",
    dest_chain_name=~"$dest_chain_name"
  }[15m])
)
```

Use the latest applicable transition for the alerted message's lane:

| Last transition | Diagnosis | Next action |
| --- | --- | --- |
| No `source_read/discovered` | The verifier did not observe the message. | Verify the source event, reader configuration, polling range, and trace/indexer record. |
| `pending_finality/queued` or `pending_finality/finality_blocked` | The message is waiting for finality. | Investigate source-chain finality and reorg protection. |
| `admission/*` | A policy or publication decision blocked progress. | Continue to step 5. |
| `admission/published` | The message entered verification. | Continue to step 6. |
| `verification/*` | Verification has a result or is retrying. | Continue to step 6. |
| `storage_write/*` | Verification completed and persistence is the remaining stage. | Continue to step 7. |

## 5. Diagnose Admission

```promql
sum by (outcome, reason) (
  increase(verifier_message_transitions_total{
    verifier_id=~"$verifier_id",
    source_chain_name=~"$source_chain_name",
    dest_chain_name=~"$dest_chain_name",
    stage="admission"
  }[15m])
)
```

| Outcome or reason | Diagnosis |
| --- | --- |
| `lane_cursed` / `remote_chain_cursed` | Remote lane is intentionally blocked. Confirm curse state. |
| `curse_state_unknown` | Curse checker or its RPC dependency is unavailable. |
| `message_disabled` | A disablement rule intentionally blocked the message. |
| `rules_state_unknown` | The verifier cannot determine disablement rules. |
| `queue_publish_error` | The verifier could not publish work for verification. Investigate the queue/publisher. |
| `published` | Continue to verification. |

## 6. Diagnose Verification

```promql
sum by (outcome, reason) (
  increase(verifier_message_transitions_total{
    verifier_id=~"$verifier_id",
    source_chain_name=~"$source_chain_name",
    dest_chain_name=~"$dest_chain_name",
    stage="verification"
  }[15m])
)
```

```promql
sum by (retryable, error_class) (
  increase(verifier_message_failures_total{
    verifier_id=~"$verifier_id",
    source_chain_name=~"$source_chain_name",
    dest_chain_name=~"$dest_chain_name",
    stage="verification"
  }[15m])
)
```

`succeeded` means verification completed; continue to step 7. A
`retry_scheduled` transition indicates a transient failure. A
`permanently_failed` transition is terminal. Use `error_class` to distinguish
attestation readiness and retrieval failures, signing failures, and aggregator
deadline, availability, resource-exhaustion, or payload-size failures.

## 7. Diagnose Storage Write

```promql
sum by (outcome, reason) (
  increase(verifier_message_transitions_total{
    verifier_id=~"$verifier_id",
    source_chain_name=~"$source_chain_name",
    dest_chain_name=~"$dest_chain_name",
    stage="storage_write"
  }[15m])
)
```

```promql
sum by (retryable, error_class) (
  increase(verifier_message_failures_total{
    verifier_id=~"$verifier_id",
    source_chain_name=~"$source_chain_name",
    dest_chain_name=~"$dest_chain_name",
    stage="storage_write"
  }[15m])
)
```

`storage_write/succeeded` proves the verifier completed its responsibility.
Hand off to indexer or executor triage. A `retry_scheduled` or
`permanently_failed` outcome indicates a storage/publisher issue. A
`batch_write_failed` reason indicates a batch-level problem affecting multiple
messages.

## 8. Determine Incident Scope

```promql
topk(10,
  max by (verifier_id, source_chain_name, dest_chain_name) (
    verifier_oldest_message_age_seconds
  )
)
```

If multiple messages on the lane have elevated pending age or count, treat it
as a lane or dependency incident. If multiple lanes are affected, investigate
shared infrastructure. If aggregate metrics are healthy, use the alerted
message's trace and logs for message-specific evidence.

## 9. Remediate

Once scope is known, recovery actions — rescheduling a dropped message,
rewinding the source-chain checkpoint, or blocking a class of traffic — are in
[Runbook: Remediating a Stuck or Dropped Message](./remediating-stuck-or-dropped-messages.md).
