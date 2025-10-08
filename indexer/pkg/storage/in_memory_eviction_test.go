package storage

import (
	"context"
	"fmt"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestInMemoryStorage_TTLEviction(t *testing.T) {
	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()

	// Create storage with 2 second TTL and fast cleanup interval
	config := InMemoryStorageConfig{
		TTL:             2 * time.Second,
		CleanupInterval: 500 * time.Millisecond,
	}
	storage := NewInMemoryStorageWithConfig(lggr, mon, config).(*InMemoryStorage)
	defer storage.Close()

	ctx := context.Background()

	// Insert some test data
	now := time.Now().Unix()
	testData := []protocol.CCVData{
		createTestCCVDataForEviction("0x001", now-3, 1, 2), // 3 seconds old (should be evicted)
		createTestCCVDataForEviction("0x002", now-1, 1, 2), // 1 second old (should remain)
		createTestCCVDataForEviction("0x003", now, 1, 2),   // just now (should remain)
	}

	for _, data := range testData {
		err := storage.InsertCCVData(ctx, data)
		require.NoError(t, err)
	}

	// Verify all data is present
	storage.mu.RLock()
	count := len(storage.byTimestamp)
	storage.mu.RUnlock()
	assert.Equal(t, 3, count)

	// Wait for cleanup to run (TTL is 2 seconds, cleanup runs every 500ms)
	time.Sleep(1 * time.Second)

	// Check that old data was evicted
	storage.mu.RLock()
	count = len(storage.byTimestamp)
	storage.mu.RUnlock()

	assert.LessOrEqual(t, count, 2, "Expected old data to be evicted")

	// Verify that trying to get the old message returns not found
	_, err := storage.GetCCVData(ctx, testData[0].MessageID)
	assert.ErrorIs(t, err, ErrCCVDataNotFound)

	// Verify recent messages are still present
	data2, err := storage.GetCCVData(ctx, testData[1].MessageID)
	require.NoError(t, err)
	assert.Len(t, data2, 1)
}

func TestInMemoryStorage_SizeBasedEviction(t *testing.T) {
	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()

	// Create storage with max size of 5 items and fast cleanup interval
	config := InMemoryStorageConfig{
		MaxSize:         5,
		CleanupInterval: 500 * time.Millisecond,
	}
	storage := NewInMemoryStorageWithConfig(lggr, mon, config).(*InMemoryStorage)
	defer storage.Close()

	ctx := context.Background()

	// Insert 10 items
	now := time.Now().Unix()
	for i := 0; i < 10; i++ {
		data := createTestCCVDataForEviction(
			fmt.Sprintf("0x%03d", i),
			now+int64(i), // incrementing timestamps
			1,
			2,
		)
		err := storage.InsertCCVData(ctx, data)
		require.NoError(t, err)
	}

	// Verify all 10 items are initially present
	storage.mu.RLock()
	count := len(storage.byTimestamp)
	storage.mu.RUnlock()
	assert.Equal(t, 10, count)

	// Wait for cleanup to run
	time.Sleep(1 * time.Second)

	// Check that storage is at or below max size
	storage.mu.RLock()
	count = len(storage.byTimestamp)
	storage.mu.RUnlock()

	assert.LessOrEqual(t, count, 5, "Expected storage to be trimmed to max size")

	// Verify that the oldest items were evicted (items 0-4)
	for i := 0; i < 5; i++ {
		msgID, _ := protocol.NewBytes32FromString(fmt.Sprintf("0x%064s", fmt.Sprintf("%03d", i)))
		_, err := storage.GetCCVData(ctx, msgID)
		assert.ErrorIs(t, err, ErrCCVDataNotFound, "Expected old item %d to be evicted", i)
	}

	// Verify that the newest items remain (items 5-9)
	for i := 5; i < 10; i++ {
		msgID, _ := protocol.NewBytes32FromString(fmt.Sprintf("0x%064s", fmt.Sprintf("%03d", i)))
		data, err := storage.GetCCVData(ctx, msgID)
		require.NoError(t, err, "Expected recent item %d to remain", i)
		assert.Len(t, data, 1)
	}
}

func TestInMemoryStorage_CombinedTTLAndSizeEviction(t *testing.T) {
	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()

	// Create storage with both TTL (3 seconds) and max size (5 items)
	config := InMemoryStorageConfig{
		TTL:             3 * time.Second,
		MaxSize:         5,
		CleanupInterval: 500 * time.Millisecond,
	}
	storage := NewInMemoryStorageWithConfig(lggr, mon, config).(*InMemoryStorage)
	defer storage.Close()

	ctx := context.Background()

	// Insert 8 items with varying timestamps
	now := time.Now().Unix()
	timestamps := []int64{
		now - 5, // Expired by TTL
		now - 4, // Expired by TTL
		now - 2, // Within TTL but may be evicted by size
		now - 1, // Within TTL but may be evicted by size
		now,     // Within TTL but may be evicted by size
		now + 1, // Within TTL, should remain
		now + 2, // Within TTL, should remain
		now + 3, // Within TTL, should remain
	}

	for i, ts := range timestamps {
		data := createTestCCVDataForEviction(
			fmt.Sprintf("0x%03d", i),
			ts,
			1,
			2,
		)
		err := storage.InsertCCVData(ctx, data)
		require.NoError(t, err)
	}

	// Wait for cleanup to run
	time.Sleep(1 * time.Second)

	// Check that storage is at or below max size
	storage.mu.RLock()
	count := len(storage.byTimestamp)
	storage.mu.RUnlock()

	assert.LessOrEqual(t, count, 5, "Expected storage to respect max size")

	// First two should be evicted due to TTL
	for i := 0; i < 2; i++ {
		msgID, _ := protocol.NewBytes32FromString(fmt.Sprintf("0x%064s", fmt.Sprintf("%03d", i)))
		_, err := storage.GetCCVData(ctx, msgID)
		assert.ErrorIs(t, err, ErrCCVDataNotFound, "Expected expired item %d to be evicted", i)
	}
}

func TestInMemoryStorage_NoEviction(t *testing.T) {
	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()

	// Create storage with no eviction configured
	config := InMemoryStorageConfig{}
	storage := NewInMemoryStorageWithConfig(lggr, mon, config).(*InMemoryStorage)
	defer storage.Close()

	ctx := context.Background()

	// Insert some test data
	now := time.Now().Unix()
	for i := 0; i < 10; i++ {
		data := createTestCCVDataForEviction(
			fmt.Sprintf("0x%03d", i),
			now-int64(i*10), // Old timestamps
			1,
			2,
		)
		err := storage.InsertCCVData(ctx, data)
		require.NoError(t, err)
	}

	// Verify all 10 items remain (no cleanup goroutine running)
	storage.mu.RLock()
	count := len(storage.byTimestamp)
	storage.mu.RUnlock()
	assert.Equal(t, 10, count)

	// Verify no cleanup goroutine is running
	assert.Nil(t, storage.cleanupStop)
	assert.Nil(t, storage.cleanupDone)
}

func TestInMemoryStorage_CleanupStopsOnClose(t *testing.T) {
	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()

	config := InMemoryStorageConfig{
		TTL:             10 * time.Second,
		CleanupInterval: 100 * time.Millisecond,
	}
	storage := NewInMemoryStorageWithConfig(lggr, mon, config).(*InMemoryStorage)

	// Verify cleanup goroutine is running
	assert.NotNil(t, storage.cleanupStop)
	assert.NotNil(t, storage.cleanupDone)

	// Close should stop the cleanup goroutine
	err := storage.Close()
	require.NoError(t, err)

	// Verify cleanupDone channel is closed
	select {
	case <-storage.cleanupDone:
		// Success - channel is closed
	case <-time.After(1 * time.Second):
		t.Fatal("Expected cleanup goroutine to stop")
	}
}

// Helper function to create test CCVData for eviction tests.
func createTestCCVDataForEviction(messageIDHex string, timestamp int64, sourceChain, destChain protocol.ChainSelector) protocol.CCVData {
	// Ensure the messageID is properly padded to 64 hex characters.
	if len(messageIDHex) < 66 { // "0x" + 64 hex chars
		messageIDHex = fmt.Sprintf("0x%064s", messageIDHex[2:])
	}
	messageID, _ := protocol.NewBytes32FromString(messageIDHex)

	// Create a unique message for each CCVData to ensure proper MessageID generation.
	message := protocol.Message{
		Sender:               []byte{0x0d, 0x0e, 0x0f},
		Data:                 []byte{0x10, 0x11, 0x12},
		OnRampAddress:        []byte{0x13, 0x14, 0x15},
		TokenTransfer:        []byte{0x16, 0x17, 0x18},
		OffRampAddress:       []byte{0x19, 0x1a, 0x1b},
		DestBlob:             []byte{0x1c, 0x1d, 0x1e},
		Receiver:             []byte{0x1f, 0x20, 0x21},
		SourceChainSelector:  sourceChain,
		DestChainSelector:    destChain,
		Nonce:                protocol.Nonce(1),
		Finality:             1,
		DestBlobLength:       3,
		TokenTransferLength:  3,
		DataLength:           3,
		ReceiverLength:       3,
		SenderLength:         3,
		Version:              1,
		OffRampAddressLength: 3,
		OnRampAddressLength:  3,
	}

	return protocol.CCVData{
		MessageID:             messageID,
		Timestamp:             timestamp,
		SourceChainSelector:   sourceChain,
		DestChainSelector:     destChain,
		Nonce:                 protocol.Nonce(1),
		SourceVerifierAddress: protocol.UnknownAddress{byte(rand.IntN(256)), byte(rand.IntN(256)), byte(rand.IntN(256))},
		DestVerifierAddress:   protocol.UnknownAddress{byte(rand.IntN(256)), byte(rand.IntN(256)), byte(rand.IntN(256))},
		CCVData:               []byte{0x07, 0x08, 0x09},
		BlobData:              []byte{0x0a, 0x0b, 0x0c},
		ReceiptBlobs:          []protocol.ReceiptWithBlob{},
		Message:               message,
	}
}
