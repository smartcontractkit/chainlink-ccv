# Aggregator message status API

## Executive Summary

- This change adds a public gRPC method, `CommitteeVerifier.GetMessageStatus`, to the aggregator. For one message ID, it returns the quorum progress: the verification count, the threshold, the aggregated flag and three timestamps.
- Callers can now see why a message has no verifier result yet, and they do not have to read the result API again and again. The method is on the `CommitteeVerifier` service and not on `Verifier`, because `Verifier` is an interface for all verifier types and this API is specific to the committee verifier.
- Affects `aggregator/pkg/handlers`, `aggregator/pkg/server.go`, `aggregator/pkg/common` (storage interface and errors), `aggregator/pkg/storage` (Postgres and metrics wrapper) and `aggregator/pkg/model` (`QuorumConfig`).
- Adds a method to `common.CommitVerificationStore`. Custom implementations of that interface must add the method. Each deployment must add a rate limit for the new method, because a method with no limit rejects all calls.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `common.CommitVerificationStore.ListCommitVerificationByMessageID` | signature-changed | `CommitVerificationStore\b` | `aggregator/pkg/common/storage.go:24` | [#commitverificationstore-new-method](#commitverificationstore-new-method) |
| Rate limit for `CommitteeVerifier/GetMessageStatus` | behavior-changed | `globalAnonymousLimits\|defaultLimits` | `build/devenv/services/aggregator.template.toml:55` | [#rate-limit-configuration](#rate-limit-configuration) |
| Anonymous auth matcher | behavior-changed | `isVerifierResultAPI\|isAnonymousAPI` | `aggregator/pkg/server.go:383` | [#anonymous-access](#anonymous-access) |
| `committee_verifier.v1.CommitteeVerifier.GetMessageStatus` | added | `GetMessageStatus\b` | `aggregator/pkg/server.go:99` | [#getmessagestatus-api](#getmessagestatus-api) |
| `handlers.MessageStatusReader` | added | `\bMessageStatusReader\b` | `aggregator/pkg/handlers/get_message_status.go:21` | [#handler-and-storage-interface](#handler-and-storage-interface) |
| `handlers.NewGetMessageStatusHandler` | added | `NewGetMessageStatusHandler\(` | `aggregator/pkg/handlers/get_message_status.go:184` | [#handler-and-storage-interface](#handler-and-storage-interface) |
| `postgres.DatabaseStorage.ListCommitVerificationByMessageID` | added | `\.ListCommitVerificationByMessageID\(` | `aggregator/pkg/storage/postgres/database_storage.go:231` | [#postgres-query](#postgres-query) |
| `common.ErrTooManyRecords` | added | `\bErrTooManyRecords\b` | `aggregator/pkg/common/errors.go:11` | [#postgres-query](#postgres-query) |
| `model.QuorumConfig.IsSigner` | added | `\.IsSigner\(` | `aggregator/pkg/model/config.go:116` | [#handler-and-storage-interface](#handler-and-storage-interface) |

## Breaking Changes

### CommitVerificationStore new method

- **What changed:** `common.CommitVerificationStore` has a new method.
- **Before:** The interface had no method that reads records by message ID only.
- **After:** `ListCommitVerificationByMessageID(ctx context.Context, messageID model.MessageID) (map[model.AggregationKey][]*model.CommitVerificationRecord, error)`.
- **Why:** The status API has only the message ID. The existing list method needs an aggregation key.
- **Who is affected:** Code that implements `CommitVerificationStore` outside this repo. `postgres.DatabaseStorage`, `storage.MetricsAwareStorage` and the generated mock implement it.

### Rate limit configuration

- **What changed:** The aggregator has a new gRPC method. The rate limiter rejects a method that has no configured limit.
- **Before:** Not applicable (new method).
- **After:** Calls to `GetMessageStatus` fail until the config has a limit for the method.
- **Why:** The rate limiter has no default limit for each method.
- **Who is affected:** Each aggregator deployment config.

## Migration Guide

1. If you implement `common.CommitVerificationStore`, add `ListCommitVerificationByMessageID`. It must return the latest record for each signer, grouped by aggregation key. It must return `common.ErrTooManyRecords` when the rows are more than the maximum, not a partial result.
2. Regenerate mocks: `just mock`.
3. Add the rate limits to each aggregator config:

```toml
[rateLimiting.defaultLimits]
"/chainlink_ccv.committee_verifier.v1.CommitteeVerifier/GetMessageStatus" = { limit_per_second = 5 }

[rateLimiting.globalAnonymousLimits]
"/chainlink_ccv.committee_verifier.v1.CommitteeVerifier/GetMessageStatus" = { limit_per_second = 50 }
```

4. Bump `github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier` to the version that contains `CommitteeVerifier.GetMessageStatus`.

## New Features / Additions

### GetMessageStatus API

The method and its messages are in `chainlink-protos/chainlink-ccv/committee-verifier/v1/committee-verifier.proto`. The request has one 32-byte `message_id`. Batch requests are not supported.

| Field | Meaning |
|---|---|
| `verification_count` | The number of unique current committee signers that verified the message. It can be more than the threshold. |
| `threshold` | The threshold from the current quorum config. |
| `aggregated` | True when `GetVerifierResultsForMessage` returns a result for the message with the current committee. For message-discovery messages, true when a report exists. |
| `first_verification_at` | Unix milliseconds when the aggregator received the first counted verification. Zero when the count is zero. |
| `latest_verification_at` | Unix milliseconds when the aggregator received the latest counted verification. Zero when the count is zero. |
| `aggregated_at` | Unix milliseconds when the aggregator stored the report. Zero when `aggregated` is false. |

| Condition | gRPC code |
|---|---|
| `message_id` is not 32 bytes | `InvalidArgument` |
| No records, or no quorum config for the source chain | `NotFound` |
| More than 256 verification records for the message | `FailedPrecondition` |
| Storage error | `Internal` |

The handler uses the current config for each call:

- After a committee change, signers that are no longer in the committee are not counted.
- After a committee change, a stored report that the result API rejects gives `aggregated=false`.
- If the message CCV addresses do not include the committee source verifier, the API still returns the count. `aggregated` stays false.

### Handler and storage interface

`handlers.GetMessageStatusHandler` (`aggregator/pkg/handlers/get_message_status.go`) depends only on `handlers.MessageStatusReader`. This interface has two methods: `ListCommitVerificationByMessageID` and `GetBatchAggregatedReportByMessageIDs`.

The handler groups records by aggregation key and selects one key:

- If a report exists, the handler uses the key of the report. `GetBatchAggregatedReportByMessageIDs` returns the latest report across all keys.
- If no report exists, the handler uses the key with the most committee signers.
- If the records have more than one key, the handler logs a warning. If more than one key has a quorum, it logs an error.

`model.QuorumConfig.IsSigner` compares a signer identifier with the configured signer addresses. The comparison does not use case and accepts addresses with or without `0x`.

The handler does no ECDSA signature recovery. The `aggregated` check uses the same checks as `GetVerifierResultsForMessage` (`isReportServable`, `aggregator/pkg/handlers/get_message_status.go:105`).

### Postgres query

`DatabaseStorage.ListCommitVerificationByMessageID` runs one query:

```sql
SELECT DISTINCT ON (aggregation_key, signer_identifier) ...
FROM commit_verification_records
WHERE message_id = $1
ORDER BY aggregation_key, signer_identifier, seq_num DESC
LIMIT $2
```

- The query reads `maxVerificationRecordsPerMessage + 1` rows (`maxVerificationRecordsPerMessage = 256`). If it gets more than 256, it returns `common.ErrTooManyRecords`.
- The existing index `idx_verification_aggregation_key (message_id, aggregation_key, seq_num DESC)` covers the query. No migration is necessary.
- `TestExplainQueryPlans` (`aggregator/pkg/storage/postgres/database_storage_explain_test.go`) seeds 320k records. It requires an index scan with no `Seq Scan`. The plan is in `aggregator/pkg/storage/postgres/testdata/explain_list_commit_verification_by_message_id.txt`.
- The metrics wrapper records the query as `ListCommitVerificationByMessageIDAllKeys`. The existing label `ListCommitVerificationByMessageID` stays on `ListCommitVerificationByAggregationKey`.

### Anonymous access

The anonymous auth interceptor in `aggregator/pkg/server.go` (`isAnonymousAPI`) now matches the `Verifier` service and the full method name `CommitteeVerifier_GetMessageStatus_FullMethodName`. Before, it matched only `Verifier`. Anonymous callers of `GetMessageStatus` get an identity from their IP address, and `globalAnonymousLimits` applies to them. All other `CommitteeVerifier` methods still require HMAC authentication.

## Compatibility & Requirements

- **Dependency bumps:** `chainlink-protos/chainlink-ccv/committee-verifier` must contain `CommitteeVerifier.GetMessageStatus` and `GetMessageStatusResponse` with fields 1 to 7.
- **Database:** No migration.

## Examples

```go
client := committeepb.NewCommitteeVerifierClient(conn)
resp, err := client.GetMessageStatus(ctx, &committeepb.GetMessageStatusRequest{MessageId: messageID[:]})
if err != nil {
	return err
}
fmt.Printf("%d/%d aggregated=%t\n", resp.GetVerificationCount(), resp.GetThreshold(), resp.GetAggregated())
```

## References

- Tests: `aggregator/pkg/handlers/get_message_status_test.go`, `aggregator/tests/message_status_api_test.go`, `build/devenv/tests/services/aggregator_test.go` (`GetMessageStatus supports anonymous authentication`).
