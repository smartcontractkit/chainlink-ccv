# Storage Package

The storage package provides multiple storage backend implementations for the indexer, along with a flexible sink pattern for chaining storage operations.

## Overview

This package implements the `IndexerStorage` interface defined in `indexer/pkg/common`, which provides all storage operations used within the indexer.

There are currently only 2 storage types with a `Sink` to chain together multiple storage backends for different scenarios.

- **In-Memory Storage** - Fast, memory-based storage with optional TTL and size-based eviction
- **PostgreSQL Storage** - Persistent database storage

> Note: All Storage backends have identical behaviour and query patterns

## Storage Interface

All storage implementations satisfy the `IndexerStorage` interface, which consists of:

### IndexerStorageReader

#### `GetCCVData(ctx context.Context, messageID protocol.Bytes32) ([]protocol.CCVData, error)`

Performs a fast lookup of all known verifications by message ID.

#### `QueryCCVData(ctx context.Context, start, end int64, sourceChainSelectors, destChainSelectors []protocol.ChainSelector, limit, offset uint64) (map[string][]protocol.CCVData, error)`

Performs a filtered query across multiple dimensions with pagination support. Typically used for discovery queries (Get all messages across these chains between these timestamps)

**Parameters**:
  - `start`, `end`: Unix timestamp range for filtering (inclusive)
  - `sourceChainSelectors`: Filter by source chain(s) (empty = no filter)
  - `destChainSelectors`: Filter by destination chain(s) (empty = no filter)
  - `limit`: Maximum number of results to return
  - `offset`: Number of results to skip (for pagination)

### IndexerStorageWriter

#### `InsertCCVData(ctx context.Context, ccvData protocol.CCVData) error`

Inserts a new verification into storage.

All backends will detect and rejects duplicate entries based on `(messageID, sourceVerifierAddress, destVerifierAddress)` tuple. If this happens the backend will return `ErrDuplicateCCVData`

## Storage Implementations

### 1. InMemoryStorage

High-performance in-memory storage optimized for query speed over memory constraints.

As the storage was designed to be a fast in-memory 'cache' we may store the same data in multiple slices if needed. To avoid a memory build-up over time, the backend implements an eviction process using both `TTL` and a size based approach to ensure we never hit limits.

> Note: Be careful when enabling eviction if this is the storage backend you are using.

#### Configuration

```go
type InMemoryStorageConfig struct {
    // TTL is the time-to-live for items. Items older than this will be evicted.
    // Set to 0 to disable TTL-based eviction.
    TTL time.Duration
    
    // MaxSize is the maximum number of items to keep in storage.
    // When exceeded, oldest items will be evicted.
    // Set to 0 to disable size-based eviction.
    MaxSize int
    
    // CleanupInterval is how often to run the background cleanup goroutine.
    // Defaults to 1 minute if not set and TTL is enabled.
    CleanupInterval time.Duration
}
```

#### Usage Example

```go
// Simple in-memory storage with no eviction
storage := NewInMemoryStorage(lggr, monitoring)

// With TTL-based eviction (keep data for 24 hours)
storage := NewInMemoryStorageWithConfig(lggr, monitoring, InMemoryStorageConfig{
    TTL: 24 * time.Hour,
    CleanupInterval: 10 * time.Minute,
})

// With size-based eviction (keep at most 100,000 items)
storage := NewInMemoryStorageWithConfig(lggr, monitoring, InMemoryStorageConfig{
    MaxSize: 100000,
    CleanupInterval: 5 * time.Minute,
})

// With both TTL and size limits
storage := NewInMemoryStorageWithConfig(lggr, monitoring, InMemoryStorageConfig{
    TTL: 24 * time.Hour,
    MaxSize: 100000,
    CleanupInterval: 10 * time.Minute,
})

// Don't forget to close when done (stops background cleanup)
defer storage.Close()
```

#### Eviction Behavior

When eviction is enabled:

1. **TTL-based**: Items with timestamp older than `now - TTL` are removed
2. **Size-based**: If storage exceeds `MaxSize`, oldest items are removed first
3. **Combined**: TTL removal happens first, then size-based removal if still over limit
4. **Cleanup Frequency**: Background goroutine runs at `CleanupInterval`

Eviction removes items from all indexes (byMessageID, byTimestamp, bySourceChain, byDestChain, uniqueKeys) and rebuilds chain indexes after removal.

### 2. PostgresStorage

Persistent storage backed by PostgreSQL database.

#### Database Schema

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

### 3. Sink

The `Sink` orchestrates multiple backends together to allow you to tailor the implementation to your needs.

Each backend is read in order and returns the first successful result. However on the write side all storages are written to, ensuring consistency (however partial failures are allowed)

Debug logs are provided to properly understand storage selection when troubleshooting.

`Sink` also implements read conditions allowing for more performant read operations (i.e if the data you're searching for will not be in the cache at all)

#### Read Behavior

For reads (GetCCVData, QueryCCVData):
1. Check each storage's read condition
2. Try eligible storages in order
3. Return first successful result
4. Return last error if all fail

#### Write Behavior

For writes (InsertCCVData):
1. Write to all storages in order
2. Treat duplicates as successes (data already exists)
3. Continue on errors, collect all failures
4. Return error if no storages succeeded
5. Return partial failure error if some succeeded

#### Usage Example

```go
// Simple sink with multiple storages (all read from)
sink, err := NewSinkSimple(lggr, storage1, storage2, storage3)

// Advanced sink with read conditions
sink, err := NewSink(lggr,
    // Hot storage: in-memory, read only recent data (last 24 hours)
    WithCondition{
        Storage:   inMemoryStorage,
        Condition: RecentRead(24 * time.Hour),
    },
    // Warm storage: PostgreSQL for recent history (last 30 days)
    WithCondition{
        Storage:   postgresStorage,
        Condition: TimeRangeRead(
            ptr(time.Now().AddDate(0, 0, -30).UnixMilli()),
            nil, // no upper bound
        ),
    },
    // Cold storage: Archive storage (older than 30 days), could be in S3
    WithCondition{
        Storage:   archiveStorage,
        Condition: TimeRangeRead(
            nil, // no lower bound
            ptr(time.Now().AddDate(0, 0, -30).UnixMilli()),
        ),
    },
)
defer sink.Close()

// Reads will automatically use the appropriate storage based on query time range
data, err := sink.QueryCCVData(ctx, start, end, sources, dests, limit, offset)

// Writes go to all storages
err = sink.InsertCCVData(ctx, ccvData)
```

## Read Conditions

Read conditions control when a storage backend is eligible for read operations.

### Condition Types

#### `AlwaysRead()`

Storage is always eligible for reads.

```go
Condition: AlwaysRead()
```

**Use Case**: Default behavior, single storage system, or when you always want to check this storage.

#### `NeverRead()`

Storage is never read from (write-only).

```go
Condition: NeverRead()
```

**Use Case**: Backup storage, audit log, or storage that's being migrated from.

#### `TimeRangeRead(startUnix, endUnix *int64)`

Storage is only read when query time range overlaps with the specified range.

```go
// Storage for data from Jan 1, 2024 onwards
Condition: TimeRangeRead(ptr(1704067200), nil)

// Storage for data from 2023 only
Condition: TimeRangeRead(ptr(1672531200), ptr(1704067200))

// Storage for data up to Jan 1, 2024 (archive)
Condition: TimeRangeRead(nil, ptr(1704067200))
```

**Use Case**: Time-based data partitioning, separating hot/warm/cold storage by age.

**Overlap Logic**: Storage is eligible if the query range `[queryStart, queryEnd]` overlaps with storage range `[startUnix, endUnix]`. `nil` values indicate no bound on that side.

#### `RecentRead(duration time.Duration)`

Storage is only read for recent data (within duration from now).

```go
// Only read last 24 hours
Condition: RecentRead(24 * time.Hour)

// Only read last week
Condition: RecentRead(7 * 24 * time.Hour)
```

**Use Case**: Hot cache for recent data, time-based tiering where boundary moves with time.

**Difference from TimeRangeRead**: The time boundary is relative to "now" rather than a fixed timestamp, making it suitable for rolling windows of recent data.

### Condition Evaluation for Non-Time-Based Queries

For `GetCCVData` (which doesn't have a time range), conditions behave as follows:
- `AlwaysRead`: Eligible ✓
- `NeverRead`: Not eligible ✗
- `TimeRangeRead`: Eligible ✓ (can't determine time range, so try it)
- `RecentRead`: Eligible ✓ (can't determine time range, so try it)

## Architecture Patterns

### Hot/Warm/Cold Storage Pattern

Optimize for cost and performance by tiering storage:

```go
// Hot: In-memory, last 24 hours, fast reads
hotStorage := NewInMemoryStorageWithConfig(lggr, monitoring, InMemoryStorageConfig{
    TTL: 24 * time.Hour,
    MaxSize: 50000,
})

// Warm: PostgreSQL, last 30 days, indexed queries
warmStorage, _ := NewPostgresStorage(ctx, lggr, monitoring, warmDBURI, "postgres", pg.DBConfig{})

// Cold: Archive PostgreSQL, older than 30 days, rarely accessed
coldStorage, _ := NewPostgresStorage(ctx, lggr, monitoring, coldDBURI, "postgres", pg.DBConfig{})

now := time.Now().UnixMilli()
thirtyDaysAgo := time.Now().AddDate(0, 0, -30).UnixMilli()

sink, _ := NewStorageSink(lggr,
    WithCondition{
        Storage:   hotStorage,
        Condition: RecentRead(24 * time.Hour),
    },
    WithCondition{
        Storage:   warmStorage,
        Condition: TimeRangeRead(&thirtyDaysAgo, nil),
    },
    WithCondition{
        Storage:   coldStorage,
        Condition: TimeRangeRead(nil, &thirtyDaysAgo),
    },
)
```

**Benefits**:
- Fast reads for recent data (hot cache)
- Cost-effective storage for historical data
- Automatic routing based on query time range
- Writes go to all tiers (redundancy + availability)

### Cache-Aside Pattern

Use in-memory storage as a cache layer:

```go
// Cache: Recent data in memory
cache := NewInMemoryStorageWithConfig(lggr, monitoring, InMemoryStorageConfig{
    TTL: 1 * time.Hour,
    MaxSize: 10000,
})

// Primary: PostgreSQL for persistence
database, _ := NewPostgresStorage(ctx, lggr, monitoring, dbURI, "postgres", pg.DBConfig{})

sink, _ := NewSinkSimple(lggr, cache, database)
```

**Benefits**:
- Read path: Check cache first, fall back to database
- Write path: Populates both cache and database
- Cache automatically evicts old data
- No manual cache invalidation needed

### Migration Pattern

Migrate from one storage to another without downtime:

```go
// Old storage (read-only during migration)
oldStorage := existingStorage

// New storage (write-to, read-from after verification)
newStorage, _ := NewPostgresStorage(ctx, lggr, monitoring, newDBURI, "postgres", pg.DBConfig{})

// During migration: write to both, read from old
sink, _ := NewStorageSink(lggr,
    WithCondition{
        Storage:   oldStorage,
        Condition: AlwaysRead(),
    },
    WithCondition{
        Storage:   newStorage,
        Condition: NeverRead(), // Populate but don't read yet
    },
)

// After migration: read from new, old becomes backup
sink, _ = NewStorageSink(lggr,
    WithCondition{
        Storage:   newStorage,
        Condition: AlwaysRead(),
    },
    WithCondition{
        Storage:   oldStorage,
        Condition: NeverRead(), // Keep as backup
    },
)
```

## Error Handling

### Common Errors

- `ErrCCVDataNotFound`: Returned when `GetCCVData` or `QueryCCVData` finds no matching data
- `ErrDuplicateCCVData`: Returned when `InsertCCVData` detects a duplicate entry
- Query errors: Database connection issues, timeout, etc.
- Partial write failures: Some storages succeeded, others failed (Sink only)

### Handling Duplicates

Duplicate errors are expected in certain scenarios:
- Syncing/backfilling data from multiple sources
- Restarting services that re-process recent events
- Network retries that cause double-writes

The Sink treats duplicates as successes during writes since the data is already present.

## Monitoring & Metrics

All storage implementations integrate with `IndexerMonitoring` to track:

- `StorageWriteDuration`: Time to insert data
- `StorageQueryDuration`: Time to query data
- `VerificationRecordsCounter`: Total number of CCV data entries
- `UniqueMessagesCounter`: Number of unique message IDs
- `StorageInsertErrorsCounter`: Write failures (PostgreSQL only)

## Thread Safety

All storage implementations are thread-safe:

- **InMemoryStorage**: Uses `sync.RWMutex` for concurrent read/write access
- **PostgresStorage**: Uses `sync.RWMutex` + database connection pool
- **Sink**: Thread-safety inherited from underlying storages

## Best Practices

1. **Close storages when done**: Call `Close()` to stop background goroutines and release resources
2. **Use read conditions wisely**: Improper conditions can cause reads to fail
3. **Monitor metrics**: Track query/write durations to identify performance issues
4. **Set appropriate eviction policies**: Balance memory usage with data availability
5. **Test with realistic data volumes**: Performance characteristics change with scale
6. **Use sink for redundancy**: Write to multiple storages for durability
7. **Configure cleanup intervals**: More frequent = less memory, but higher CPU usage

## Troubleshooting

### Queries returning no results

1. Check read conditions - storage may not be eligible for the query time range
2. Verify data was written successfully (check write errors)
3. Check if data was evicted (TTL/size limits)
4. Look at debug logs to see which storages were tried

### High memory usage (InMemoryStorage)

1. Enable size-based eviction with `MaxSize`
2. Enable TTL-based eviction to remove old data
3. Reduce `CleanupInterval` for more frequent cleanup
4. Consider moving to PostgreSQL or tiered storage

### Slow queries

1. Check metrics to identify bottleneck (storage layer vs. network)
2. For InMemoryStorage: Memory access is fast, slowness likely elsewhere
3. For PostgresStorage: Ensure indexes exist on queried columns
4. For Sink: Check which storages are being queried (debug logs)

### Write failures

1. Check for duplicate errors (expected, not a problem)
2. For PostgresStorage: Verify database connectivity and schema
3. For Sink: Check partial failure messages to identify failing storage
4. Review metrics for error rates

### Background cleanup not working

1. Verify TTL or MaxSize is > 0
2. Check that `Close()` wasn't called (stops cleanup goroutine)
3. Look for cleanup log messages to confirm it's running
4. Ensure CleanupInterval is reasonable (not too long)

### Example 1: Tiered Storage with Eviction

```go
package main

import (
    "context"
    "time"
    "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/storage"
)

func main() {
    // Hot cache: Last 1 hour in memory
    cache := storage.NewInMemoryStorageWithConfig(lggr, monitoring, storage.InMemoryStorageConfig{
        TTL:             1 * time.Hour,
        MaxSize:         50000,
        CleanupInterval: 5 * time.Minute,
    })
    
    // Persistent Storage
    db, _ := storage.NewPostgresStorage(ctx, lggr, monitoring, dbURI, "postgres", pg.DBConfig{})
    
    // Create sink with time-based routing
    sink, _ := storage.NewStorageSink(lggr,
        storage.WithCondition{
            Storage:   cache,
            Condition: storage.RecentRead(1 * time.Hour),
        },
        storage.WithCondition{
            Storage:   db,
            Condition: storage.AlwaysRead(),
        },
    )
    defer sink.Close()
    
    // Writes go to both cache and database
    _ = sink.InsertCCVData(ctx, ccvData)
    
    // Reads use cache for recent queries, database for older queries
    recent, _ := sink.QueryCCVData(ctx, time.Now().UnixMilli()-3600, time.Now().UnixMilli(), nil, nil, 100, 0)
    historical, _ := sink.QueryCCVData(ctx, oldStart, oldEnd, nil, nil, 100, 0)
}
```

### Example 3: Backup Pattern

```go
package main

import (
    "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/storage"
)

func main() {
    // Primary storage
    primary, _ := storage.NewPostgresStorage(ctx, lggr, monitoring, primaryURI, "postgres", pg.DBConfig{})
    
    // Backup storage (write-only from API perspective)
    backup, _ := storage.NewPostgresStorage(ctx, lggr, monitoring, backupURI, "postgres", pg.DBConfig{})
    
    sink, _ := storage.NewStorageSink(lggr,
        storage.WithCondition{
            Storage:   primary,
            Condition: storage.AlwaysRead(),
        },
        storage.WithCondition{
            Storage:   backup,
            Condition: storage.NeverRead(), // Write-only backup
        },
    )
    defer sink.Close()
    
    // Reads go to primary only
    data, _ := sink.GetCCVData(ctx, messageID)
    
    // Writes go to both primary and backup
    _ = sink.InsertCCVData(ctx, ccvData)
}
```

## See Also

- `indexer/pkg/common/storage.go` - Storage interface definition
- `protocol/common_types.go` - CCVData structure
- `indexer/migrations/` - PostgreSQL schema migrations

