# Aggregator Migration Tool

`migrate_commit_verification_records.py` copies aggregator `commit_verification_records`
from one Postgres database to another.

The destination row identity is regenerated:

- `id` is not copied.
- `seq_num` is not copied.
- Duplicate records for `unique_verification`
  `(message_id, signer_identifier, aggregation_key)` are skipped.

By default, migrated rows get a fresh `created_at = NOW()` in the destination so
aggregator orphan recovery can pick them up under the default `orphanRecovery.maxAge`.
Use `--preserve-created-at` only when you intentionally want source timestamps.

## Requirements

Python 3 with `psycopg3`:

```bash
python3 -m pip install 'psycopg[binary]'
```

## Usage

```bash
tools/migrate_aggregator/migrate_commit_verification_records.py \
  --source-url "$SOURCE_DATABASE_URL" \
  --dest-url "$DEST_DATABASE_URL"
```

Connection URLs can also be supplied through environment variables:

```bash
SOURCE_DATABASE_URL='postgres://...' \
DEST_DATABASE_URL='postgres://...' \
tools/migrate_aggregator/migrate_commit_verification_records.py
```

Dry run:

```bash
tools/migrate_aggregator/migrate_commit_verification_records.py \
  --source-url "$SOURCE_DATABASE_URL" \
  --dest-url "$DEST_DATABASE_URL" \
  --dry-run
```

## Performance

The tool exports source rows with Postgres `COPY` into local batch files, loads
those files into a destination temp table with `COPY`, then does one set-based
insert into `commit_verification_records`.

Default batching is 50 local files:

```bash
--copy-batches 50
```

Increase or decrease this if one file is too large or too many small files add
overhead. The batch split is based on source `id` ranges.

## Aggregator Recovery

This tool only migrates `commit_verification_records`.

Indexer discovery reads `commit_aggregated_reports`, not raw verification rows.
After migration, run the aggregator with orphan recovery enabled so it can scan
the migrated verification records and create aggregated reports.

Relevant aggregator behavior:

- orphan recovery scans `(message_id, aggregation_key)` pairs that have
  verification records and no matching aggregated report.
- it only scans records newer than `orphanRecovery.maxAge`.
- default migration timestamps are fresh to make these records recoverable.

## Indexer Cursor

The indexer stores its aggregator discovery cursor in:

```sql
indexer.discovery_state(discovery_location, last_sequence_number)
```

`discovery_location` is the aggregator address. If the indexer database is fresh,
no manual cursor change is needed; it will initialize from config `Since`.

If reusing an existing indexer database with a fresh/rebuilt aggregator database,
reset the cursor before starting the indexer:

```sql
UPDATE indexer.discovery_state
SET last_sequence_number = 0
WHERE discovery_location = '<aggregator-address>';
```

If this is a temporary failover and you will later switch back to the original
aggregator database, save the old cursor first:

```sql
SELECT discovery_location, last_sequence_number
FROM indexer.discovery_state
WHERE discovery_location = '<aggregator-address>';
```

When switching back, stop the indexer and restore that saved cursor.

Alternatively, you can advance the fresh aggregator's aggregated-report sequence
instead of resetting the indexer cursor:

```sql
ALTER SEQUENCE commit_aggregated_reports_seq_num_seq RESTART WITH <next_sequence>;
```

Use `commit_aggregated_reports_seq_num_seq` for indexer discovery. Do not use
`commit_verification_records_seq_num_seq` for this purpose.
