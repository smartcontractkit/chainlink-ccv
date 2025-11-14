package storage

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// TestStorageSink_ReadFromFirstStorage tests that data is read from the first storage when available.
func TestStorageSink_ReadFromFirstStorage(t *testing.T) {
	ctx := context.Background()
	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()

	// Create two storages: in-memory and another in-memory
	memStorage1 := NewInMemoryStorage(lggr, mon)
	memStorage2 := NewInMemoryStorage(lggr, mon)

	// Create storage sink with memStorage1 first
	chain, err := NewSinkSimple(lggr, memStorage1, memStorage2)
	require.NoError(t, err)

	// Create test data
	testData := protocol.CCVData{
		MessageID:             protocol.Bytes32{0x01},
		SourceVerifierAddress: protocol.UnknownAddress{0x02},
		DestVerifierAddress:   protocol.UnknownAddress{0x03},
		Timestamp:             time.UnixMilli(1000),
		SourceChainSelector:   protocol.ChainSelector(1),
		DestChainSelector:     protocol.ChainSelector(2),
		Nonce:                 protocol.Nonce(1),
	}

	// Insert into first storage only
	err = memStorage1.InsertCCVData(ctx, testData)
	require.NoError(t, err)

	// Read from chain should return data from first storage
	result, err := chain.GetCCVData(ctx, testData.MessageID)
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, testData.MessageID, result[0].MessageID)
}

func TestStorageSink_ReadFromSecondStorageOnMiss(t *testing.T) {
	ctx := context.Background()
	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()

	// Create two storages
	memStorage1 := NewInMemoryStorage(lggr, mon)
	memStorage2 := NewInMemoryStorage(lggr, mon)

	// Create storage sink
	chain, err := NewSinkSimple(lggr, memStorage1, memStorage2)
	require.NoError(t, err)

	// Create test data
	testData := protocol.CCVData{
		MessageID:             protocol.Bytes32{0x01},
		SourceVerifierAddress: protocol.UnknownAddress{0x02},
		DestVerifierAddress:   protocol.UnknownAddress{0x03},
		Timestamp:             time.UnixMilli(1000),
		SourceChainSelector:   protocol.ChainSelector(1),
		DestChainSelector:     protocol.ChainSelector(2),
		Nonce:                 protocol.Nonce(1),
	}

	// Insert into second storage only
	err = memStorage2.InsertCCVData(ctx, testData)
	require.NoError(t, err)

	// Read from chain should find data in second storage
	result, err := chain.GetCCVData(ctx, testData.MessageID)
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, testData.MessageID, result[0].MessageID)
}

func TestStorageSink_ReadNotFound(t *testing.T) {
	ctx := context.Background()
	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()

	// Create two storages
	memStorage1 := NewInMemoryStorage(lggr, mon)
	memStorage2 := NewInMemoryStorage(lggr, mon)

	// Create storage sink
	chain, err := NewSinkSimple(lggr, memStorage1, memStorage2)
	require.NoError(t, err)

	// Try to read non-existent data
	result, err := chain.GetCCVData(ctx, protocol.Bytes32{0x99})
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, ErrCCVDataNotFound, err)
}

func TestStorageSink_WriteToAllStorages(t *testing.T) {
	ctx := context.Background()
	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()

	// Create two storages
	memStorage1 := NewInMemoryStorage(lggr, mon)
	memStorage2 := NewInMemoryStorage(lggr, mon)

	// Create storage sink
	chain, err := NewSinkSimple(lggr, memStorage1, memStorage2)
	require.NoError(t, err)

	// Create test data
	testData := protocol.CCVData{
		MessageID:             protocol.Bytes32{0x01},
		SourceVerifierAddress: protocol.UnknownAddress{0x02},
		DestVerifierAddress:   protocol.UnknownAddress{0x03},
		Timestamp:             time.UnixMilli(1000),
		SourceChainSelector:   protocol.ChainSelector(1),
		DestChainSelector:     protocol.ChainSelector(2),
		Nonce:                 protocol.Nonce(1),
	}

	// Write through chain
	err = chain.InsertCCVData(ctx, testData)
	require.NoError(t, err)

	// Verify data exists in both storages
	result1, err := memStorage1.GetCCVData(ctx, testData.MessageID)
	require.NoError(t, err)
	assert.Len(t, result1, 1)

	result2, err := memStorage2.GetCCVData(ctx, testData.MessageID)
	require.NoError(t, err)
	assert.Len(t, result2, 1)
}

func TestStorageSink_QueryFromFirstStorage(t *testing.T) {
	ctx := context.Background()
	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()

	// Create two storages
	memStorage1 := NewInMemoryStorage(lggr, mon)
	memStorage2 := NewInMemoryStorage(lggr, mon)

	// Create storage sink
	chain, err := NewSinkSimple(lggr, memStorage1, memStorage2)
	require.NoError(t, err)

	// Create test data
	testData := protocol.CCVData{
		MessageID:             protocol.Bytes32{0x01},
		SourceVerifierAddress: protocol.UnknownAddress{0x02},
		DestVerifierAddress:   protocol.UnknownAddress{0x03},
		Timestamp:             time.UnixMilli(1000),
		SourceChainSelector:   protocol.ChainSelector(1),
		DestChainSelector:     protocol.ChainSelector(2),
		Nonce:                 protocol.Nonce(1),
	}

	// Insert into first storage
	err = memStorage1.InsertCCVData(ctx, testData)
	require.NoError(t, err)

	// Query from chain
	results, err := chain.QueryCCVData(ctx, time.UnixMilli(900), time.UnixMilli(1100), nil, nil, 10, 0)
	require.NoError(t, err)
	assert.Len(t, results, 1)
}

func TestStorageSink_WriteDuplicateHandling(t *testing.T) {
	ctx := context.Background()
	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()

	// Create two storages
	memStorage1 := NewInMemoryStorage(lggr, mon)
	memStorage2 := NewInMemoryStorage(lggr, mon)

	// Create storage sink
	chain, err := NewSinkSimple(lggr, memStorage1, memStorage2)
	require.NoError(t, err)

	// Create test data
	testData := protocol.CCVData{
		MessageID:             protocol.Bytes32{0x01},
		SourceVerifierAddress: protocol.UnknownAddress{0x02},
		DestVerifierAddress:   protocol.UnknownAddress{0x03},
		Timestamp:             time.UnixMilli(1000),
		SourceChainSelector:   protocol.ChainSelector(1),
		DestChainSelector:     protocol.ChainSelector(2),
		Nonce:                 protocol.Nonce(1),
	}

	// Write first time
	err = chain.InsertCCVData(ctx, testData)
	require.NoError(t, err)

	// Write again (should handle duplicates gracefully)
	err = chain.InsertCCVData(ctx, testData)
	require.NoError(t, err, "Duplicate writes should succeed as data already exists")
}

func TestStorageSink_NoStoragesError(t *testing.T) {
	lggr := logger.Test(t)

	// Try to create chain with no storages
	_, err := NewSinkSimple(lggr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one storage is required")
}

// TestStorageSink_TimeRangeCondition_RecentDataOnly tests reading from storage with time-based conditions.
func TestStorageSink_TimeRangeCondition_RecentDataOnly(t *testing.T) {
	ctx := context.Background()
	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()

	// Create two storages: hot (recent) and cold (historical)
	hotStorage := NewInMemoryStorage(lggr, mon)
	coldStorage := NewInMemoryStorage(lggr, mon)

	// Configure hot storage to only read data from last 1000 seconds (e.g., recent data)
	// Configure cold storage to always read (historical data)
	now := int64(10000)
	recentStart := now - 1000

	chain, err := NewSink(lggr,
		WithCondition{
			Storage:   hotStorage,
			Condition: TimeRangeRead(&recentStart, nil), // Only read recent data (after recentStart)
		},
		WithCondition{
			Storage:   coldStorage,
			Condition: AlwaysRead(), // Always read from cold storage
		},
	)
	require.NoError(t, err)

	// Create recent test data (timestamp within hot storage range)
	recentData := protocol.CCVData{
		MessageID:             protocol.Bytes32{0x01},
		SourceVerifierAddress: protocol.UnknownAddress{0x02},
		DestVerifierAddress:   protocol.UnknownAddress{0x03},
		Timestamp:             time.UnixMilli(9500), // Recent
		SourceChainSelector:   protocol.ChainSelector(1),
		DestChainSelector:     protocol.ChainSelector(2),
		Nonce:                 protocol.Nonce(1),
	}

	// Create old test data (timestamp before hot storage range)
	oldData := protocol.CCVData{
		MessageID:             protocol.Bytes32{0x02},
		SourceVerifierAddress: protocol.UnknownAddress{0x02},
		DestVerifierAddress:   protocol.UnknownAddress{0x03},
		Timestamp:             time.UnixMilli(8000), // Old
		SourceChainSelector:   protocol.ChainSelector(1),
		DestChainSelector:     protocol.ChainSelector(2),
		Nonce:                 protocol.Nonce(2),
	}

	// Insert recent data into hot storage
	err = hotStorage.InsertCCVData(ctx, recentData)
	require.NoError(t, err)

	// Insert old data into cold storage
	err = coldStorage.InsertCCVData(ctx, oldData)
	require.NoError(t, err)

	// Query for recent data - should use hot storage
	results, err := chain.QueryCCVData(ctx, time.UnixMilli(9000), time.UnixMilli(10000), nil, nil, 10, 0)
	require.NoError(t, err)
	assert.Len(t, results, 1, "Should find recent data in hot storage")

	// Query for old data - should skip hot storage and use cold storage
	results, err = chain.QueryCCVData(ctx, time.UnixMilli(7000), time.UnixMilli(8500), nil, nil, 10, 0)
	require.NoError(t, err)
	assert.Len(t, results, 1, "Should find old data in cold storage")
}

// TestStorageSink_TimeRangeCondition_HotAndCold tests a hot/cold storage architecture.
func TestStorageSink_TimeRangeCondition_HotAndCold(t *testing.T) {
	ctx := context.Background()
	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()

	// Create storages
	hotStorage := NewInMemoryStorage(lggr, mon)
	coldStorage := NewInMemoryStorage(lggr, mon)

	// Hot storage: only for last 7 days (604800 seconds)
	// Cold storage: for everything older than 7 days
	now := int64(1000000)
	hotStart := now - 604800
	coldEnd := hotStart

	chain, err := NewSink(lggr,
		WithCondition{
			Storage:   hotStorage,
			Condition: TimeRangeRead(&hotStart, nil), // Recent data (last 7 days)
		},
		WithCondition{
			Storage:   coldStorage,
			Condition: TimeRangeRead(nil, &coldEnd), // Historical data (older than 7 days)
		},
	)
	require.NoError(t, err)

	// Insert recent data into hot storage
	recentData := protocol.CCVData{
		MessageID:             protocol.Bytes32{0x01},
		SourceVerifierAddress: protocol.UnknownAddress{0x02},
		DestVerifierAddress:   protocol.UnknownAddress{0x03},
		Timestamp:             time.UnixMilli(now - 100), // Very recent
		SourceChainSelector:   protocol.ChainSelector(1),
		DestChainSelector:     protocol.ChainSelector(2),
		Nonce:                 protocol.Nonce(1),
	}
	err = hotStorage.InsertCCVData(ctx, recentData)
	require.NoError(t, err)

	// Insert old data into cold storage
	oldData := protocol.CCVData{
		MessageID:             protocol.Bytes32{0x02},
		SourceVerifierAddress: protocol.UnknownAddress{0x02},
		DestVerifierAddress:   protocol.UnknownAddress{0x03},
		Timestamp:             time.UnixMilli(now - 700000), // Very old
		SourceChainSelector:   protocol.ChainSelector(1),
		DestChainSelector:     protocol.ChainSelector(2),
		Nonce:                 protocol.Nonce(2),
	}
	err = coldStorage.InsertCCVData(ctx, oldData)
	require.NoError(t, err)

	// Query recent time range - should only check hot storage
	results, err := chain.QueryCCVData(ctx, time.UnixMilli(now-200), time.UnixMilli(now), nil, nil, 10, 0)
	require.NoError(t, err)
	assert.Len(t, results, 1, "Should find data in hot storage")

	// Query old time range - should only check cold storage
	results, err = chain.QueryCCVData(ctx, time.UnixMilli(now-800000), time.UnixMilli(now-650000), nil, nil, 10, 0)
	require.NoError(t, err)
	assert.Len(t, results, 1, "Should find data in cold storage")
}

// TestStorageSink_NeverReadCondition tests write-only storage.
func TestStorageSink_NeverReadCondition(t *testing.T) {
	ctx := context.Background()
	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()

	// Create two storages
	readWriteStorage := NewInMemoryStorage(lggr, mon)
	writeOnlyStorage := NewInMemoryStorage(lggr, mon)

	// Configure one as write-only (never read)
	chain, err := NewSink(lggr,
		WithCondition{
			Storage:   writeOnlyStorage,
			Condition: NeverRead(), // Never read from this storage
		},
		WithCondition{
			Storage:   readWriteStorage,
			Condition: AlwaysRead(),
		},
	)
	require.NoError(t, err)

	// Create test data
	testData := protocol.CCVData{
		MessageID:             protocol.Bytes32{0x01},
		SourceVerifierAddress: protocol.UnknownAddress{0x02},
		DestVerifierAddress:   protocol.UnknownAddress{0x03},
		Timestamp:             time.UnixMilli(1000),
		SourceChainSelector:   protocol.ChainSelector(1),
		DestChainSelector:     protocol.ChainSelector(2),
		Nonce:                 protocol.Nonce(1),
	}

	// Write through sink (should write to both)
	err = chain.InsertCCVData(ctx, testData)
	require.NoError(t, err)

	// Verify data was written to both storages
	_, err = writeOnlyStorage.GetCCVData(ctx, testData.MessageID)
	require.NoError(t, err, "Data should exist in write-only storage")

	_, err = readWriteStorage.GetCCVData(ctx, testData.MessageID)
	require.NoError(t, err, "Data should exist in read-write storage")

	// Read through sink - should only read from readWriteStorage (skip writeOnlyStorage)
	result, err := chain.GetCCVData(ctx, testData.MessageID)
	require.NoError(t, err)
	assert.Len(t, result, 1, "Should find data in read-write storage")
}

// TestStorageSink_RecentReadCondition tests reading from storage with duration-based conditions.
func TestStorageSink_RecentReadCondition(t *testing.T) {
	ctx := context.Background()
	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()

	// Create two storages: hot (recent) and cold (historical)
	hotStorage := NewInMemoryStorage(lggr, mon)
	coldStorage := NewInMemoryStorage(lggr, mon)

	// Configure hot storage to only read data from last 1 hour
	// Configure cold storage to always read (historical data)
	chain, err := NewSink(lggr,
		WithCondition{
			Storage:   hotStorage,
			Condition: RecentRead(time.Hour), // Only read data from last hour
		},
		WithCondition{
			Storage:   coldStorage,
			Condition: AlwaysRead(), // Always read from cold storage
		},
	)
	require.NoError(t, err)

	// Create recent test data (within the last hour)
	now := time.Now().UnixMilli() // Get current time in milliseconds
	recentData := protocol.CCVData{
		MessageID:             protocol.Bytes32{0x01},
		SourceVerifierAddress: protocol.UnknownAddress{0x02},
		DestVerifierAddress:   protocol.UnknownAddress{0x03},
		Timestamp:             time.UnixMilli(now - 30*60*1000), // 30 minutes ago
		SourceChainSelector:   protocol.ChainSelector(1),
		DestChainSelector:     protocol.ChainSelector(2),
		Nonce:                 protocol.Nonce(1),
	}

	// Create old test data (older than 1 hour)
	oldData := protocol.CCVData{
		MessageID:             protocol.Bytes32{0x02},
		SourceVerifierAddress: protocol.UnknownAddress{0x02},
		DestVerifierAddress:   protocol.UnknownAddress{0x03},
		Timestamp:             time.UnixMilli(now - 2*60*60*1000), // 2 hours ago
		SourceChainSelector:   protocol.ChainSelector(1),
		DestChainSelector:     protocol.ChainSelector(2),
		Nonce:                 protocol.Nonce(2),
	}

	// Insert recent data into hot storage
	err = hotStorage.InsertCCVData(ctx, recentData)
	require.NoError(t, err)

	// Insert old data into cold storage
	err = coldStorage.InsertCCVData(ctx, oldData)
	require.NoError(t, err)

	// Query for recent data (last 45 minutes) - should use hot storage
	queryStart := now - 45*60*1000 // 45 minutes ago in milliseconds
	queryEnd := now                // Current time in milliseconds
	results, err := chain.QueryCCVData(ctx, time.UnixMilli(queryStart), time.UnixMilli(queryEnd), nil, nil, 10, 0)
	require.NoError(t, err)
	assert.Len(t, results, 1, "Should find recent data in hot storage")

	// Query for old data (2-3 hours ago) - should skip hot storage and use cold storage
	queryStart = now - 3*60*60*1000 // 3 hours ago in milliseconds
	queryEnd = now - 90*60*1000     // 90 minutes ago in milliseconds
	results, err = chain.QueryCCVData(ctx, time.UnixMilli(queryStart), time.UnixMilli(queryEnd), nil, nil, 10, 0)
	require.NoError(t, err)
	assert.Len(t, results, 1, "Should find old data in cold storage")
}

// TestStorageSink_RecentReadCondition_ShortDuration tests with very short durations (e.g., 1 minute).
func TestStorageSink_RecentReadCondition_ShortDuration(t *testing.T) {
	ctx := context.Background()
	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()

	// Create storages
	veryHotStorage := NewInMemoryStorage(lggr, mon)
	warmStorage := NewInMemoryStorage(lggr, mon)

	// Very hot storage: only for last 1 minute
	// Warm storage: for everything else
	chain, err := NewSink(lggr,
		WithCondition{
			Storage:   veryHotStorage,
			Condition: RecentRead(time.Minute), // Only last minute
		},
		WithCondition{
			Storage:   warmStorage,
			Condition: AlwaysRead(),
		},
	)
	require.NoError(t, err)

	now := time.Now().UnixMilli() // Get current time in milliseconds

	// Insert very recent data (30 seconds ago) into very hot storage
	veryRecentData := protocol.CCVData{
		MessageID:             protocol.Bytes32{0x01},
		SourceVerifierAddress: protocol.UnknownAddress{0x02},
		DestVerifierAddress:   protocol.UnknownAddress{0x03},
		Timestamp:             time.UnixMilli(now - 30*1000), // 30 seconds ago
		SourceChainSelector:   protocol.ChainSelector(1),
		DestChainSelector:     protocol.ChainSelector(2),
		Nonce:                 protocol.Nonce(1),
	}
	err = veryHotStorage.InsertCCVData(ctx, veryRecentData)
	require.NoError(t, err)

	// Insert slightly older data (5 minutes ago) into warm storage
	slightlyOldData := protocol.CCVData{
		MessageID:             protocol.Bytes32{0x02},
		SourceVerifierAddress: protocol.UnknownAddress{0x02},
		DestVerifierAddress:   protocol.UnknownAddress{0x03},
		Timestamp:             time.UnixMilli(now - 5*60*1000), // 5 minutes ago
		SourceChainSelector:   protocol.ChainSelector(1),
		DestChainSelector:     protocol.ChainSelector(2),
		Nonce:                 protocol.Nonce(2),
	}
	err = warmStorage.InsertCCVData(ctx, slightlyOldData)
	require.NoError(t, err)

	// Query for very recent data (last 45 seconds) - should use very hot storage
	results, err := chain.QueryCCVData(ctx, time.UnixMilli(now-45*1000), time.UnixMilli(now), nil, nil, 10, 0)
	require.NoError(t, err)
	assert.Len(t, results, 1, "Should find very recent data in very hot storage")

	// Query for slightly old data (5-10 minutes ago) - should skip very hot and use warm storage
	results, err = chain.QueryCCVData(ctx, time.UnixMilli(now-10*60*1000), time.UnixMilli(now-4*60*1000), nil, nil, 10, 0)
	require.NoError(t, err)
	assert.Len(t, results, 1, "Should find slightly old data in warm storage")
}
