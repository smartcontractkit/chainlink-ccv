# Storage Package

The storage package provides the PostgreSQL storage backend implementation for the indexer.

## Overview

This package implements the `IndexerStorage` interface defined in `indexer/pkg/common`.

## Storage Interface

All storage implementations satisfy the `IndexerStorage` interface, which consists of:

### IndexerStorageReader

#### `GetCCVData(ctx context.Context, messageID protocol.Bytes32) ([]protocol.VerifierResult, error)`

Performs a fast lookup of all known verifications by message ID.

#### `QueryCCVData(ctx context.Context, start, end int64, sourceChainSelectors, destChainSelectors []protocol.ChainSelector, limit, offset uint64) (map[string][]protocol.VerifierResult, error)`

Performs a filtered query across multiple dimensions with pagination support. Typically used for discovery queries (Get all messages across these chains between these timestamps)

**Parameters**:
  - `start`, `end`: Unix timestamp range for filtering (inclusive)
  - `sourceChainSelectors`: Filter by source chain(s) (empty = no filter)
  - `destChainSelectors`: Filter by destination chain(s) (empty = no filter)
  - `limit`: Maximum number of results to return
  - `offset`: Number of results to skip (for pagination)

### IndexerStorageWriter

#### `InsertCCVData(ctx context.Context, ccvData protocol.VerifierResult) error`

Inserts a new verification into storage.

All backends will detect and reject duplicate entries based on `(messageID, sourceVerifierAddress, destVerifierAddress)` tuple. If this happens the backend will return `ErrDuplicateCCVData`

## PostgresStorage

Persistent storage backed by PostgreSQL database.

### Database Schema

```sql
CREATE TABLE indexer.verifier_results (
    message_id TEXT NOT NULL,
    source_verifier_address TEXT NOT NULL,
    dest_verifier_address TEXT NOT NULL,
    timestamp BIGINT NOT NULL,
    source_chain_selector DECIMAL(20,0) NOT NULL,
    dest_chain_selector DECIMAL(20,0) NOT NULL,
    nonce DECIMAL(20,0) NOT NULL,
    ccv_data BYTEA,
    blob_data BYTEA,
    message JSONB,
    receipt_blobs JSONB,
    PRIMARY KEY (message_id, source_verifier_address, dest_verifier_address)
);

-- Indexes for efficient querying
CREATE INDEX idx_timestamp ON indexer.verifier_results(timestamp);
CREATE INDEX idx_source_chain ON indexer.verifier_results(source_chain_selector);
CREATE INDEX idx_dest_chain ON indexer.verifier_results(dest_chain_selector);
```

## Error Handling

### Common Errors

- `ErrCCVDataNotFound`: Returned when `GetCCVData` or `QueryCCVData` finds no matching data
- `ErrDuplicateCCVData`: Returned when `InsertCCVData` detects a duplicate entry
- Query errors: Database connection issues, timeout, etc.

## Monitoring & Metrics

The storage implementation integrates with `IndexerMonitoring` to track:

- `StorageWriteDuration`: Time to insert data
- `StorageQueryDuration`: Time to query data
- `VerificationRecordsCounter`: Total number of CCV data entries
- `UniqueMessagesCounter`: Number of unique message IDs
- `StorageInsertErrorsCounter`: Write failures

## Thread Safety

PostgresStorage uses `sync.RWMutex` + database connection pool for thread safety.

## See Also

- `indexer/pkg/common/storage.go` - Storage interface definition
- `protocol/common_types.go` - CCVData structure
- `indexer/migrations/` - PostgreSQL schema migrations
