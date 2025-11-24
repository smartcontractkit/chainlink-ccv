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

func TestNewInMemoryStorage(t *testing.T) {
	lggr := logger.Nop()
	storage := NewInMemoryStorage(lggr, monitoring.NewNoopIndexerMonitoring())

	assert.NotNil(t, storage)
	assert.IsType(t, &InMemoryStorage{}, storage)
}

func TestInsertCCVData(t *testing.T) {
	storage := NewInMemoryStorage(logger.Nop(), monitoring.NewNoopIndexerMonitoring())
	ctx := context.Background()

	ccvData := createTestCCVData("0x123", 1000, 1, 2)

	err := storage.InsertCCVData(ctx, ccvData)
	require.NoError(t, err)

	// Verify data was inserted
	retrieved, err := storage.GetCCVData(ctx, ccvData.MessageID)
	require.NoError(t, err)
	require.Len(t, retrieved, 1)
	assert.Equal(t, ccvData, retrieved[0])
}

func TestInsertCCVDataMultiple(t *testing.T) {
	storage := NewInMemoryStorage(logger.Nop(), monitoring.NewNoopIndexerMonitoring())
	ctx := context.Background()

	// Insert multiple CCVData with same messageID
	ccvData1 := createTestCCVData("0x123", 1000, 1, 2)
	ccvData2 := createTestCCVData("0x123", 2000, 1, 2) // Same messageID, different timestamp

	err := storage.InsertCCVData(ctx, ccvData1)
	require.NoError(t, err)

	err = storage.InsertCCVData(ctx, ccvData2)
	require.NoError(t, err)

	// Verify both were inserted
	retrieved, err := storage.GetCCVData(ctx, ccvData1.MessageID)
	require.NoError(t, err)
	require.Len(t, retrieved, 2)
	assert.Contains(t, retrieved, ccvData1)
	assert.Contains(t, retrieved, ccvData2)
}

func TestGetCCVDataNotFound(t *testing.T) {
	storage := NewInMemoryStorage(logger.Nop(), monitoring.NewNoopIndexerMonitoring())
	ctx := context.Background()

	messageID := createTestBytes32("0x999")
	_, err := storage.GetCCVData(ctx, messageID)

	assert.Error(t, err)
	assert.Equal(t, ErrCCVDataNotFound, err)
}

func TestQueryCCVDataTimestampRange(t *testing.T) {
	storage := NewInMemoryStorage(logger.Nop(), monitoring.NewNoopIndexerMonitoring())
	ctx := context.Background()

	// Insert test data with different timestamps
	ccvData1 := createTestCCVData("0x111", 1000, 1, 2)
	ccvData2 := createTestCCVData("0x222", 2000, 1, 2)
	ccvData3 := createTestCCVData("0x333", 3000, 1, 2)
	ccvData4 := createTestCCVData("0x444", 4000, 1, 2)

	for _, data := range []protocol.VerifierResult{ccvData1, ccvData2, ccvData3, ccvData4} {
		err := storage.InsertCCVData(ctx, data)
		require.NoError(t, err)
	}

	// Query for timestamp range 1500-3500
	results, err := storage.QueryCCVData(ctx, 1500, 3500, nil, nil, 100, 0)
	require.NoError(t, err)

	// Should return ccvData2 and ccvData3
	assert.Len(t, results, 2)
	assert.Contains(t, results, "0x0000000000000000000000000000000000000000000000000000000000000222")
	assert.Contains(t, results, "0x0000000000000000000000000000000000000000000000000000000000000333")
}

func TestQueryCCVDataWithSourceChainFilter(t *testing.T) {
	storage := NewInMemoryStorage(logger.Nop(), monitoring.NewNoopIndexerMonitoring())
	ctx := context.Background()

	// Insert test data with different source chains
	ccvData1 := createTestCCVData("0x111", 1000, 1, 2) // source: 1
	ccvData2 := createTestCCVData("0x222", 2000, 2, 2) // source: 2
	ccvData3 := createTestCCVData("0x333", 3000, 1, 2) // source: 1

	for _, data := range []protocol.VerifierResult{ccvData1, ccvData2, ccvData3} {
		err := storage.InsertCCVData(ctx, data)
		require.NoError(t, err)
	}

	// Query for source chain 1
	sourceChains := []protocol.ChainSelector{1}
	results, err := storage.QueryCCVData(ctx, 0, time.Now().UnixMilli(), sourceChains, []protocol.ChainSelector{}, 100, 0)
	require.NoError(t, err)

	// Should return ccvData1 and ccvData3
	assert.Len(t, results, 2)
	assert.Contains(t, results, "0x0000000000000000000000000000000000000000000000000000000000000111")
	assert.Contains(t, results, "0x0000000000000000000000000000000000000000000000000000000000000333")
}

func TestQueryCCVDataWithDestChainFilter(t *testing.T) {
	storage := NewInMemoryStorage(logger.Nop(), monitoring.NewNoopIndexerMonitoring())
	ctx := context.Background()

	// Insert test data with different dest chains
	ccvData1 := createTestCCVData("0x111", 1000, 1, 2) // dest: 2
	ccvData2 := createTestCCVData("0x222", 2000, 1, 3) // dest: 3
	ccvData3 := createTestCCVData("0x333", 3000, 1, 2) // dest: 2

	for _, data := range []protocol.VerifierResult{ccvData1, ccvData2, ccvData3} {
		err := storage.InsertCCVData(ctx, data)
		require.NoError(t, err)
	}

	// Query for dest chain 2
	destChains := []protocol.ChainSelector{2}
	results, err := storage.QueryCCVData(ctx, 0, time.Now().UnixMilli(), []protocol.ChainSelector{}, destChains, 100, 0)
	require.NoError(t, err)

	// Should return ccvData1 and ccvData3
	assert.Len(t, results, 2)
	assert.Contains(t, results, "0x0000000000000000000000000000000000000000000000000000000000000111")
	assert.Contains(t, results, "0x0000000000000000000000000000000000000000000000000000000000000333")
}

func TestQueryCCVDataWithBothChainFilters(t *testing.T) {
	storage := NewInMemoryStorage(logger.Nop(), monitoring.NewNoopIndexerMonitoring())
	ctx := context.Background()

	// Insert test data
	ccvData1 := createTestCCVData("0x111", 1000, 1, 2) // source: 1, dest: 2
	ccvData2 := createTestCCVData("0x222", 2000, 1, 3) // source: 1, dest: 3
	ccvData3 := createTestCCVData("0x333", 3000, 2, 2) // source: 2, dest: 2
	ccvData4 := createTestCCVData("0x444", 4000, 1, 2) // source: 1, dest: 2

	for _, data := range []protocol.VerifierResult{ccvData1, ccvData2, ccvData3, ccvData4} {
		err := storage.InsertCCVData(ctx, data)
		require.NoError(t, err)
	}

	// Query for source chain 1 AND dest chain 2
	sourceChains := []protocol.ChainSelector{1}
	destChains := []protocol.ChainSelector{2}
	results, err := storage.QueryCCVData(ctx, 0, 9999, sourceChains, destChains, 100, 0)
	require.NoError(t, err)

	// Should return ccvData1 and ccvData4
	assert.Len(t, results, 2)
	assert.Contains(t, results, "0x0000000000000000000000000000000000000000000000000000000000000111")
	assert.Contains(t, results, "0x0000000000000000000000000000000000000000000000000000000000000444")
}

func TestQueryCCVDataPagination(t *testing.T) {
	storage := NewInMemoryStorage(logger.Nop(), monitoring.NewNoopIndexerMonitoring())
	ctx := context.Background()

	// Insert 5 test records
	for i := 0; i < 5; i++ {
		ccvData := createTestCCVData(fmt.Sprintf("0x%03d", i), int64(1000+i*100), 1, 2)
		err := storage.InsertCCVData(ctx, ccvData)
		require.NoError(t, err)
	}

	// Test pagination: limit=2, offset=1
	results, err := storage.QueryCCVData(ctx, 0, 9999, nil, nil, 2, 1)
	require.NoError(t, err)

	// Should return 2 records (indices 1 and 2)
	assert.Len(t, results, 2)
}

func TestQueryCCVDataEmptyResult(t *testing.T) {
	storage := NewInMemoryStorage(logger.Nop(), monitoring.NewNoopIndexerMonitoring())
	ctx := context.Background()

	// Query with no data
	results, err := storage.QueryCCVData(ctx, 0, 9999, nil, nil, 100, 0)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestQueryCCVDataNoMatchingTimestamp(t *testing.T) {
	storage := NewInMemoryStorage(logger.Nop(), monitoring.NewNoopIndexerMonitoring())
	ctx := context.Background()

	// Insert data with timestamp 1000
	ccvData := createTestCCVData("0x111", 1000, 1, 2)
	err := storage.InsertCCVData(ctx, ccvData)
	require.NoError(t, err)

	// Query for timestamp range 2000-3000 (no matches)
	results, err := storage.QueryCCVData(ctx, 2000, 3000, nil, nil, 100, 0)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestQueryCCVDataNoMatchingChainSelector(t *testing.T) {
	storage := NewInMemoryStorage(logger.Nop(), monitoring.NewNoopIndexerMonitoring())
	ctx := context.Background()

	// Insert data with source chain 1
	ccvData := createTestCCVData("0x111", 1000, 1, 2)
	err := storage.InsertCCVData(ctx, ccvData)
	require.NoError(t, err)

	// Query for source chain 5 (no matches)
	sourceChains := []protocol.ChainSelector{5}
	results, err := storage.QueryCCVData(ctx, 0, 9999, nil, sourceChains, 100, 0)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestConcurrentAccess(t *testing.T) {
	storage := NewInMemoryStorage(logger.Nop(), monitoring.NewNoopIndexerMonitoring())
	ctx := context.Background()

	// Test concurrent inserts
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(i int) {
			ccvData := createTestCCVData(fmt.Sprintf("0x%03d", i), int64(1000+i), 1, 2)
			err := storage.InsertCCVData(ctx, ccvData)
			assert.NoError(t, err)
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify all data was inserted
	results, err := storage.QueryCCVData(ctx, 0, 9999, nil, nil, 100, 0)
	require.NoError(t, err)
	assert.Len(t, results, 10)
}

// Helper functions

func createTestCCVData(messageIDHex string, timestamp int64, sourceChain, destChain protocol.ChainSelector) protocol.VerifierResult {
	// Ensure the messageID is properly padded to 64 hex characters
	if len(messageIDHex) < 66 { // "0x" + 64 hex chars
		messageIDHex = fmt.Sprintf("0x%064s", messageIDHex[2:])
	}
	messageID, _ := protocol.NewBytes32FromString(messageIDHex)

	// Create a unique message for each CCVData to ensure proper MessageID generation
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
		SequenceNumber:       protocol.SequenceNumber(1),
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

	return protocol.VerifierResult{
		MessageID:              messageID,
		Timestamp:              time.UnixMilli(timestamp),
		Message:                message,
		MessageCCVAddresses:    []protocol.UnknownAddress{{byte(rand.IntN(256)), byte(rand.IntN(256)), byte(rand.IntN(256))}},
		MessageExecutorAddress: protocol.UnknownAddress{byte(rand.IntN(256)), byte(rand.IntN(256)), byte(rand.IntN(256))},
		VerifierDestAddress:    protocol.UnknownAddress{byte(rand.IntN(256)), byte(rand.IntN(256)), byte(rand.IntN(256))},
		VerifierSourceAddress:  protocol.UnknownAddress{byte(rand.IntN(256)), byte(rand.IntN(256)), byte(rand.IntN(256))},
		CCVData:                []byte{0x07, 0x08, 0x09},
	}
}

func createTestBytes32(hex string) protocol.Bytes32 {
	bytes32, _ := protocol.NewBytes32FromString(hex)
	return bytes32
}

// Benchmark tests

func BenchmarkInsertCCVData(b *testing.B) {
	storage := NewInMemoryStorage(logger.Nop(), monitoring.NewNoopIndexerMonitoring())
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ccvData := createTestCCVData(fmt.Sprintf("0x%x", i), int64(1000+i), 1, 2)
		storage.InsertCCVData(ctx, ccvData)
	}
}

func BenchmarkGetCCVData(b *testing.B) {
	storage := NewInMemoryStorage(logger.Nop(), monitoring.NewNoopIndexerMonitoring())
	ctx := context.Background()

	// Pre-populate with data
	ccvData := createTestCCVData("0x123", 1000, 1, 2)
	storage.InsertCCVData(ctx, ccvData)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		storage.GetCCVData(ctx, ccvData.MessageID)
	}
}

func BenchmarkQueryCCVDataTimestampRange(b *testing.B) {
	storage := NewInMemoryStorage(logger.Nop(), monitoring.NewNoopIndexerMonitoring())
	ctx := context.Background()

	// Pre-populate with 1000 records
	for i := 0; i < 1000; i++ {
		ccvData := createTestCCVData(fmt.Sprintf("0x%03d", i), int64(1000+i), 1, 2)
		storage.InsertCCVData(ctx, ccvData)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		storage.QueryCCVData(ctx, 1500, 2500, nil, nil, 100, 0)
	}
}

func BenchmarkQueryCCVDataWithChainFilter(b *testing.B) {
	storage := NewInMemoryStorage(logger.Nop(), monitoring.NewNoopIndexerMonitoring())
	ctx := context.Background()

	// Pre-populate with 1000 records with mixed chain selectors
	for i := 0; i < 1000; i++ {
		sourceChain := protocol.ChainSelector(i % 5)     // 0-4
		destChain := protocol.ChainSelector((i + 1) % 5) // 1-5
		ccvData := createTestCCVData(fmt.Sprintf("0x%03d", i), int64(1000+i), sourceChain, destChain)
		storage.InsertCCVData(ctx, ccvData)
	}

	sourceChains := []protocol.ChainSelector{1, 2}
	destChains := []protocol.ChainSelector{3, 4}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		storage.QueryCCVData(ctx, 0, 9999, destChains, sourceChains, 100, 0)
	}
}

func BenchmarkConcurrentInserts(b *testing.B) {
	storage := NewInMemoryStorage(logger.Nop(), monitoring.NewNoopIndexerMonitoring())
	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			ccvData := createTestCCVData(fmt.Sprintf("0x%x", i), int64(1000+i), 1, 2)
			storage.InsertCCVData(ctx, ccvData)
			i++
		}
	})
}
