# Batch write now actually batches the DB insert

`BatchWriteCommitteeVerifierNodeResult` used to fan out N goroutines that each ran
the full single-item write path — one DB insert and one aggregation trigger per
item. It didn't actually batch anything.

Now it does a single multi-row insert for the whole batch, and triggers the
aggregation check once per unique `(messageID, aggregationKey)` instead of once
per item.

One behavior change: a DB insert failure now fails every valid item in the batch,
not just one. The insert is idempotent, so a client just retries the batch.

PR: https://github.com/smartcontractkit/chainlink-ccv/pull/1542
