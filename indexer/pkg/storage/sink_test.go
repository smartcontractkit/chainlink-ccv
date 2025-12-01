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

const TestDiscoveryLocation string = "test-location"

// TestStorageSink_ReadFromFirstStorage tests that data is read from the first storage when available.
func TestStorageSink_ReadFromFirstStorage(t *testing.T) {
	ctx := context.Background()
	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()

	// Create two storages: in-memory and another in-memory
	memStorage1 := NewInMemoryStorage(lggr, mon)
	memStorage2 := NewInMemoryStorage(lggr, mon)

	// Create storage sink with memStorage1 first
	chain, err := NewSink(lggr, memStorage1, memStorage2)
	require.NoError(t, err)

	testData := createTestCCVData("0x1", 1, protocol.ChainSelector(1), protocol.ChainSelector(2))

	// Insert into first storage only
	err = memStorage1.InsertCCVData(ctx, testData)
	require.NoError(t, err)

	// Read from chain should return data from first storage
	result, err := chain.GetCCVData(ctx, testData.VerifierResult.MessageID)
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, testData.VerifierResult.MessageID, result[0].VerifierResult.MessageID)
}

func TestStorageSink_ReadFromSecondStorageOnMiss(t *testing.T) {
	ctx := context.Background()
	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()

	// Create two storages
	memStorage1 := NewInMemoryStorage(lggr, mon)
	memStorage2 := NewInMemoryStorage(lggr, mon)

	// Create storage sink
	chain, err := NewSink(lggr, memStorage1, memStorage2)
	require.NoError(t, err)

	testData := createTestCCVData("0x1", 1, protocol.ChainSelector(1), protocol.ChainSelector(2))

	// Insert into second storage only
	err = memStorage2.InsertCCVData(ctx, testData)
	require.NoError(t, err)

	// Read from chain should find data in second storage
	result, err := chain.GetCCVData(ctx, testData.VerifierResult.MessageID)
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, testData.VerifierResult.MessageID, result[0].VerifierResult.MessageID)
}

func TestStorageSink_ReadNotFound(t *testing.T) {
	ctx := context.Background()
	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()

	// Create two storages
	memStorage1 := NewInMemoryStorage(lggr, mon)
	memStorage2 := NewInMemoryStorage(lggr, mon)

	// Create storage sink
	chain, err := NewSink(lggr, memStorage1, memStorage2)
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
	chain, err := NewSink(lggr, memStorage1, memStorage2)
	require.NoError(t, err)

	testData := createTestCCVData("0x1", 1, protocol.ChainSelector(1), protocol.ChainSelector(2))

	// Write through chain
	err = chain.InsertCCVData(ctx, testData)
	require.NoError(t, err)

	// Verify data exists in both storages
	result1, err := memStorage1.GetCCVData(ctx, testData.VerifierResult.MessageID)
	require.NoError(t, err)
	assert.Len(t, result1, 1)

	result2, err := memStorage2.GetCCVData(ctx, testData.VerifierResult.MessageID)
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
	chain, err := NewSink(lggr, memStorage1, memStorage2)
	require.NoError(t, err)

	testData := createTestCCVData("0x1", 1, protocol.ChainSelector(1), protocol.ChainSelector(2))

	// Insert into first storage
	err = memStorage1.InsertCCVData(ctx, testData)
	require.NoError(t, err)

	// Query from chain
	results, err := chain.QueryCCVData(ctx, 0, time.Now().UnixMilli(), nil, nil, 10, 0)
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
	chain, err := NewSink(lggr, memStorage1, memStorage2)
	require.NoError(t, err)

	testData := createTestCCVData("0x1", 1, protocol.ChainSelector(1), protocol.ChainSelector(2))

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
	_, err := NewSink(lggr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one storage is required")
}

// Discovery state tests

func TestStorageSink_GetDiscoverySequenceNumberFromFirstStorage(t *testing.T) {
	ctx := context.Background()
	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()

	// Create two storages
	memStorage1 := NewInMemoryStorage(lggr, mon)
	memStorage2 := NewInMemoryStorage(lggr, mon)

	// Create storage sink
	chain, err := NewSink(lggr, memStorage1, memStorage2)
	require.NoError(t, err)

	sequenceNumber := 42

	// Create state in first storage only
	err = memStorage1.CreateDiscoveryState(ctx, TestDiscoveryLocation, sequenceNumber)
	require.NoError(t, err)

	// Read from chain should return data from first storage
	result, err := chain.GetDiscoverySequenceNumber(ctx, TestDiscoveryLocation)
	require.NoError(t, err)
	assert.Equal(t, sequenceNumber, result)
}

func TestStorageSink_GetDiscoverySequenceNumberFromSecondStorage(t *testing.T) {
	ctx := context.Background()
	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()

	// Create two storages
	memStorage1 := NewInMemoryStorage(lggr, mon)
	memStorage2 := NewInMemoryStorage(lggr, mon)

	// Create storage sink
	chain, err := NewSink(lggr, memStorage1, memStorage2)
	require.NoError(t, err)

	sequenceNumber := 42

	// Create state in second storage only
	err = memStorage2.CreateDiscoveryState(ctx, TestDiscoveryLocation, sequenceNumber)
	require.NoError(t, err)

	// Read from chain should find data in second storage
	result, err := chain.GetDiscoverySequenceNumber(ctx, TestDiscoveryLocation)
	require.NoError(t, err)
	assert.Equal(t, sequenceNumber, result)
}

func TestStorageSink_GetDiscoverySequenceNumberNotFound(t *testing.T) {
	ctx := context.Background()
	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()

	// Create two storages
	memStorage1 := NewInMemoryStorage(lggr, mon)
	memStorage2 := NewInMemoryStorage(lggr, mon)

	// Create storage sink
	chain, err := NewSink(lggr, memStorage1, memStorage2)
	require.NoError(t, err)

	// Try to read non-existent discovery state
	_, err = chain.GetDiscoverySequenceNumber(ctx, "non-existent-location")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to find discovery sequence number")
}

func TestStorageSink_CreateDiscoveryStateInAllStorages(t *testing.T) {
	ctx := context.Background()
	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()

	// Create two storages
	memStorage1 := NewInMemoryStorage(lggr, mon)
	memStorage2 := NewInMemoryStorage(lggr, mon)

	// Create storage sink
	chain, err := NewSink(lggr, memStorage1, memStorage2)
	require.NoError(t, err)

	startingSequenceNumber := 10

	// Create through chain
	err = chain.CreateDiscoveryState(ctx, TestDiscoveryLocation, startingSequenceNumber)
	require.NoError(t, err)

	// Verify state exists in both storages
	seq1, err := memStorage1.GetDiscoverySequenceNumber(ctx, TestDiscoveryLocation)
	require.NoError(t, err)
	assert.Equal(t, startingSequenceNumber, seq1)

	seq2, err := memStorage2.GetDiscoverySequenceNumber(ctx, TestDiscoveryLocation)
	require.NoError(t, err)
	assert.Equal(t, startingSequenceNumber, seq2)
}

func TestStorageSink_CreateDiscoveryStateIdempotent(t *testing.T) {
	ctx := context.Background()
	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()

	// Create two storages
	memStorage1 := NewInMemoryStorage(lggr, mon)
	memStorage2 := NewInMemoryStorage(lggr, mon)

	// Create storage sink
	chain, err := NewSink(lggr, memStorage1, memStorage2)
	require.NoError(t, err)

	startingSequenceNumber := 10

	// Create first time
	err = chain.CreateDiscoveryState(ctx, TestDiscoveryLocation, startingSequenceNumber)
	require.NoError(t, err)

	// Create again (should be idempotent)
	err = chain.CreateDiscoveryState(ctx, TestDiscoveryLocation, 20)
	require.NoError(t, err)

	// Verify original value is still there in both storages
	seq1, err := memStorage1.GetDiscoverySequenceNumber(ctx, TestDiscoveryLocation)
	require.NoError(t, err)
	assert.Equal(t, startingSequenceNumber, seq1)

	seq2, err := memStorage2.GetDiscoverySequenceNumber(ctx, TestDiscoveryLocation)
	require.NoError(t, err)
	assert.Equal(t, startingSequenceNumber, seq2)
}

func TestStorageSink_UpdateDiscoverySequenceNumberInAllStorages(t *testing.T) {
	ctx := context.Background()
	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()

	// Create two storages
	memStorage1 := NewInMemoryStorage(lggr, mon)
	memStorage2 := NewInMemoryStorage(lggr, mon)

	// Create storage sink
	chain, err := NewSink(lggr, memStorage1, memStorage2)
	require.NoError(t, err)

	initialSequenceNumber := 10
	newSequenceNumber := 25

	// Create state in both storages first
	err = memStorage1.CreateDiscoveryState(ctx, TestDiscoveryLocation, initialSequenceNumber)
	require.NoError(t, err)
	err = memStorage2.CreateDiscoveryState(ctx, TestDiscoveryLocation, initialSequenceNumber)
	require.NoError(t, err)

	// Update through chain
	err = chain.UpdateDiscoverySequenceNumber(ctx, TestDiscoveryLocation, newSequenceNumber)
	require.NoError(t, err)

	// Verify update in both storages
	seq1, err := memStorage1.GetDiscoverySequenceNumber(ctx, TestDiscoveryLocation)
	require.NoError(t, err)
	assert.Equal(t, newSequenceNumber, seq1)

	seq2, err := memStorage2.GetDiscoverySequenceNumber(ctx, TestDiscoveryLocation)
	require.NoError(t, err)
	assert.Equal(t, newSequenceNumber, seq2)
}
