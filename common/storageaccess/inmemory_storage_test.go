package storageaccess

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func createTestMessage(seqNum types.SeqNum, sourceChainSelector, destChainSelector types.ChainSelector) types.Message {
	// Create empty token transfer
	tokenTransfer := types.NewEmptyTokenTransfer()

	sender := types.UnknownAddress([]byte("sender_address"))
	receiver := types.UnknownAddress([]byte("receiver_address"))
	onRampAddr := types.UnknownAddress([]byte("onramp_address"))
	offRampAddr := types.UnknownAddress([]byte("offramp_address"))

	return *types.NewMessage(
		sourceChainSelector,
		destChainSelector,
		seqNum,
		onRampAddr,
		offRampAddr,
		0, // finality
		sender,
		receiver,
		[]byte("test data"), // dest blob
		[]byte("test data"), // data
		tokenTransfer,
	)
}

func TestInMemoryOffchainStorage_WriteCCVData(t *testing.T) {
	lggr := logger.Test(t)
	storage := NewInMemoryOffchainStorage(lggr)

	ctx := context.Background()
	verifierAddress := []byte("0x1234")

	// Create test CCV data
	testData := []types.CCVData{
		{
			MessageID:             [32]byte{1, 2, 3},
			SequenceNumber:        100,
			SourceChainSelector:   1,
			DestChainSelector:     2,
			SourceVerifierAddress: verifierAddress,
			DestVerifierAddress:   []byte("0x4567"),
			CCVData:               []byte("signature1"),
			BlobData:              []byte("blob1"),
			Timestamp:             time.Now().Unix(),
			ReceiptBlobs: []types.ReceiptWithBlob{
				{
					Issuer:            verifierAddress,
					DestGasLimit:      200000,
					DestBytesOverhead: 50,
					Blob:              []byte("blob1"),
					ExtraArgs:         []byte{},
				},
			},
			Message: createTestMessage(100, 1, 2),
		},
		{
			MessageID:             [32]byte{4, 5, 6},
			SequenceNumber:        101,
			SourceChainSelector:   1,
			DestChainSelector:     2,
			SourceVerifierAddress: verifierAddress,
			DestVerifierAddress:   []byte("0x4567"),
			CCVData:               []byte("signature2"),
			BlobData:              []byte("blob2"),
			Timestamp:             time.Now().Unix() + 1,
			ReceiptBlobs: []types.ReceiptWithBlob{
				{
					Issuer:            verifierAddress,
					DestGasLimit:      300000,
					DestBytesOverhead: 75,
					Blob:              []byte("blob2"),
					ExtraArgs:         []byte("test"),
				},
			},
			Message: createTestMessage(101, 1, 2),
		},
	}

	// Write data
	err := storage.WriteCCVData(ctx, testData)
	require.NoError(t, err)

	// Retrieve and verify
	storedData, err := storage.GetAllCCVData(verifierAddress)
	require.NoError(t, err)
	require.Len(t, storedData, 2)

	// Verify data is sorted by timestamp
	require.True(t, storedData[0].Timestamp <= storedData[1].Timestamp)

	// Verify content
	require.Equal(t, testData[0].MessageID, storedData[0].MessageID)
	require.Equal(t, testData[1].MessageID, storedData[1].MessageID)
}

func TestInMemoryOffchainStorage_GetCCVDataByTimestamp(t *testing.T) {
	baseTime := time.Now().UnixMicro()
	ctx := t.Context()

	setup := func(
		destChains, sourceChains []types.ChainSelector,
		limit uint64,
		offset uint64,
		startTimestamp int64,
	) *InMemoryOffchainStorage {
		lggr := logger.Test(t)

		// Use fixed time provider for predictable tests
		timeProvider := func() int64 { return baseTime }
		storage := NewInMemoryOffchainStorageWithTimeProvider(
			lggr, timeProvider, destChains, sourceChains, limit, offset, startTimestamp)

		verifierAddress := []byte("0x1234")

		// Create test data with different timestamps by storing at different times
		testData1 := []types.CCVData{
			{
				MessageID:             [32]byte{1},
				SequenceNumber:        100,
				SourceChainSelector:   1,
				DestChainSelector:     2,
				SourceVerifierAddress: verifierAddress,
				DestVerifierAddress:   []byte("0x4567"),
				CCVData:               []byte("sig1"),
				Message:               createTestMessage(100, 1, 2),
			},
		}

		// Store first data at baseTime
		err := storage.WriteCCVData(ctx, testData1)
		require.NoError(t, err)

		// Update time provider for second batch
		timeProvider = func() int64 { return baseTime + 10000000 } // 10 seconds later in microseconds
		storage.timeProvider = timeProvider

		testData2 := []types.CCVData{
			{
				MessageID:             [32]byte{2},
				SequenceNumber:        101,
				SourceChainSelector:   1,
				DestChainSelector:     2,
				SourceVerifierAddress: verifierAddress,
				DestVerifierAddress:   []byte("0x4567"),
				CCVData:               []byte("sig2"),
				Message:               createTestMessage(101, 1, 2),
			},
		}

		err = storage.WriteCCVData(ctx, testData2)
		require.NoError(t, err)

		// Update time provider for third batch
		timeProvider = func() int64 { return baseTime + 20000000 } // 20 seconds later in microseconds
		storage.timeProvider = timeProvider

		testData3 := []types.CCVData{
			{
				MessageID:             [32]byte{3},
				SequenceNumber:        102,
				SourceChainSelector:   1,
				DestChainSelector:     2,
				SourceVerifierAddress: verifierAddress,
				DestVerifierAddress:   []byte("0x4567"),
				CCVData:               []byte("sig3"),
				Message:               createTestMessage(102, 1, 2),
			},
		}

		err = storage.WriteCCVData(ctx, testData3)
		require.NoError(t, err)

		return storage
	}

	tests := []struct {
		name          string
		destChains    []types.ChainSelector
		sourceChains  []types.ChainSelector
		expectedSeqs  []types.SeqNum
		startTime     int64
		limit         int
		offset        int
		expectedCount int
	}{
		{
			name:          "all data",
			startTime:     baseTime - 1,
			destChains:    []types.ChainSelector{2},
			sourceChains:  []types.ChainSelector{1},
			limit:         100,
			offset:        0,
			expectedCount: 3,
			expectedSeqs:  []types.SeqNum{100, 101, 102},
		},
		{
			name:          "middle range",
			startTime:     baseTime + 5000000, // 5 seconds later
			destChains:    []types.ChainSelector{2},
			sourceChains:  []types.ChainSelector{1},
			limit:         100,
			offset:        0,
			expectedCount: 2,
			expectedSeqs:  []types.SeqNum{101, 102},
		},
		{
			name:          "no data in range",
			startTime:     baseTime + 30000000, // 30 seconds later
			destChains:    []types.ChainSelector{2},
			sourceChains:  []types.ChainSelector{1},
			limit:         100,
			offset:        0,
			expectedCount: 0,
			expectedSeqs:  nil,
		},
		{
			name:          "pagination test - first page",
			startTime:     baseTime - 1,
			destChains:    []types.ChainSelector{2},
			sourceChains:  []types.ChainSelector{1},
			limit:         2,
			offset:        0,
			expectedCount: 2,
			expectedSeqs:  []types.SeqNum{100, 101},
		},
		{
			name:          "pagination test - second page",
			startTime:     baseTime - 1,
			destChains:    []types.ChainSelector{2},
			sourceChains:  []types.ChainSelector{1},
			limit:         2,
			offset:        2,
			expectedCount: 1,
			expectedSeqs:  []types.SeqNum{102},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := setup(tt.destChains, tt.sourceChains, uint64(tt.limit), uint64(tt.offset), tt.startTime)
			response, err := storage.ReadCCVData(ctx)
			require.NoError(t, err)
			require.NotNil(t, response)

			require.Equal(t, tt.expectedCount, len(response))

			// Verify sequence numbers match expected by collecting from all destination chains
			var actualSeqs []types.SeqNum
			for _, ccv := range response {
				actualSeqs = append(actualSeqs, ccv.Data.SequenceNumber)
			}

			// Sort actual sequences for comparison
			sort.Slice(actualSeqs, func(i, j int) bool {
				return actualSeqs[i] < actualSeqs[j]
			})

			require.Equal(t, tt.expectedSeqs, actualSeqs)
		})
	}
}

func TestInMemoryOffchainStorage_GetCCVDataByMessageID(t *testing.T) {
	lggr := logger.Test(t)
	storage := NewInMemoryOffchainStorage(lggr)

	ctx := context.Background()
	verifierAddress := []byte("0x1234")

	messageID := [32]byte{1, 2, 3, 4, 5}
	testData := []types.CCVData{
		{
			MessageID:             messageID,
			SequenceNumber:        100,
			SourceChainSelector:   1,
			DestChainSelector:     2,
			SourceVerifierAddress: verifierAddress,
			DestVerifierAddress:   []byte("0x4567"),
			CCVData:               []byte("signature"),
			BlobData:              []byte("blob"),
			Timestamp:             time.Now().Unix(),
			ReceiptBlobs: []types.ReceiptWithBlob{
				{
					Issuer:            verifierAddress,
					DestGasLimit:      150000,
					DestBytesOverhead: 30,
					Blob:              []byte("blob"),
					ExtraArgs:         []byte{},
				},
			},
			Message: createTestMessage(100, 1, 2),
		},
	}

	// Store data
	err := storage.WriteCCVData(ctx, testData)
	require.NoError(t, err)

	// Test finding existing message
	result, err := storage.ReadCCVDataByMessageID(messageID)
	require.NoError(t, err)
	require.Equal(t, types.Bytes32(messageID), result.MessageID)
	require.Equal(t, types.SeqNum(100), result.SequenceNumber)

	// Test finding non-existing message
	nonExistentID := [32]byte{9, 9, 9}
	result, err = storage.ReadCCVDataByMessageID(nonExistentID)
	require.Error(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "CCV data not found")
}

func TestInMemoryOffchainStorage_MultipleVerifiers(t *testing.T) {
	lggr := logger.Test(t)
	storage := NewInMemoryOffchainStorage(lggr)

	ctx := context.Background()
	verifier1 := []byte("0x1111")
	verifier2 := []byte("0x2222")

	// Create data for different verifiers
	data1 := []types.CCVData{
		{
			MessageID:             [32]byte{1},
			SequenceNumber:        100,
			SourceVerifierAddress: verifier1,
			CCVData:               []byte("sig1"),
			Message:               createTestMessage(100, 1, 2),
		},
		{
			MessageID:             [32]byte{2},
			SequenceNumber:        101,
			SourceVerifierAddress: verifier1,
			CCVData:               []byte("sig2"),
			Message:               createTestMessage(101, 1, 2),
		},
	}

	data2 := []types.CCVData{
		{
			MessageID:             [32]byte{3},
			SequenceNumber:        200,
			SourceVerifierAddress: verifier2,
			CCVData:               []byte("sig3"),
			Message:               createTestMessage(200, 1, 2),
		},
	}

	// Write data for both verifiers
	err := storage.WriteCCVData(ctx, data1)
	require.NoError(t, err)

	err = storage.WriteCCVData(ctx, data2)
	require.NoError(t, err)

	// Verify verifier1 data
	result1, err := storage.GetAllCCVData(verifier1)
	require.NoError(t, err)
	require.Len(t, result1, 2)

	// Verify verifier2 data
	result2, err := storage.GetAllCCVData(verifier2)
	require.NoError(t, err)
	require.Len(t, result2, 1)

	// Verify data is separate
	require.Equal(t, types.SeqNum(100), result1[0].SequenceNumber)
	require.Equal(t, types.SeqNum(101), result1[1].SequenceNumber)
	require.Equal(t, types.SeqNum(200), result2[0].SequenceNumber)
}

func TestInMemoryOffchainStorage_Clear(t *testing.T) {
	lggr := logger.Test(t)
	storage := NewInMemoryOffchainStorage(lggr)

	ctx := context.Background()
	verifierAddress := []byte("0x1234")

	// Add some data
	testData := []types.CCVData{
		{
			MessageID:             [32]byte{1, 2, 3},
			SourceVerifierAddress: verifierAddress,
			CCVData:               []byte("signature"),
			Message:               createTestMessage(100, 1, 2),
		},
	}

	err := storage.WriteCCVData(ctx, testData)
	require.NoError(t, err)

	// Verify data exists
	result, err := storage.GetAllCCVData(verifierAddress)
	require.NoError(t, err)
	require.Len(t, result, 1)

	// Clear storage
	storage.Clear()

	// Verify data is gone
	result, err = storage.GetAllCCVData(verifierAddress)
	require.NoError(t, err)
	require.Len(t, result, 0)

	// Verify stats are reset
	stats := storage.GetStats()
	require.Equal(t, 0, stats["totalEntries"])
	require.Equal(t, 0, stats["verifierCount"])
}

func TestInMemoryOffchainStorage_EmptyData(t *testing.T) {
	lggr := logger.Test(t)
	storage := NewInMemoryOffchainStorageWithTimeProvider(
		lggr, DefaultTimeProvider, []types.ChainSelector{2}, []types.ChainSelector{1}, 100, 0, 0)

	ctx := context.Background()

	// Write empty data should not error
	err := storage.WriteCCVData(ctx, []types.CCVData{})
	require.NoError(t, err)

	// Get data for non-existent verifier
	verifierAddress := []byte("0x1234")
	result, err := storage.GetAllCCVData(verifierAddress)
	require.NoError(t, err)
	require.Len(t, result, 0)

	// Get data by timestamp for non-existent verifier
	result2, err := storage.ReadCCVData(ctx)
	require.NoError(t, err)
	require.Equal(t, 0, len(result2))
}

func TestInMemoryOffchainStorage_TimestampHandling(t *testing.T) {
	lggr := logger.Test(t)
	storage := NewInMemoryOffchainStorage(lggr)

	ctx := context.Background()
	verifierAddress := []byte("0x1234")

	// Create data - timestamp will be set by storage layer
	testData := []types.CCVData{
		{
			MessageID:             [32]byte{1},
			SourceVerifierAddress: verifierAddress,
			Message:               createTestMessage(100, 1, 2),
		},
	}

	err := storage.WriteCCVData(ctx, testData)
	require.NoError(t, err)

	// Verify data was stored - timestamp is managed internally by storage entries
	result, err := storage.GetAllCCVData(verifierAddress)
	require.NoError(t, err)
	require.Len(t, result, 1)

	// The storage layer manages timestamps internally, so we just verify data was stored
	require.Equal(t, types.Bytes32([32]byte{1}), result[0].MessageID)
}

func TestInMemoryOffchainStorage_ReaderWriterViews(t *testing.T) {
	lggr := logger.Test(t)
	storage := NewInMemoryOffchainStorageWithTimeProvider(
		lggr, DefaultTimeProvider, []types.ChainSelector{2}, []types.ChainSelector{1}, 100, 0, 0)

	// Create reader and writer views
	reader := CreateReaderOnly(storage)
	writer := CreateWriterOnly(storage)

	ctx := context.Background()
	verifierAddress := []byte("0x1234")

	// Test data
	testData := []types.CCVData{
		{
			MessageID:             [32]byte{1, 2, 3},
			SequenceNumber:        100,
			SourceChainSelector:   1,
			DestChainSelector:     2,
			SourceVerifierAddress: verifierAddress,
			DestVerifierAddress:   []byte("0x4567"),
			CCVData:               []byte("signature1"),
			BlobData:              []byte("blob1"),
			ReceiptBlobs: []types.ReceiptWithBlob{
				{
					Issuer:            verifierAddress,
					DestGasLimit:      250000,
					DestBytesOverhead: 60,
					Blob:              []byte("blob1"),
					ExtraArgs:         []byte("extra"),
				},
			},
			Message: createTestMessage(100, 1, 2),
		},
	}

	// Store data using writer view
	err := writer.WriteCCVData(ctx, testData)
	require.NoError(t, err)

	// Read data using reader view
	response, err := reader.ReadCCVData(
		ctx,
	)
	require.NoError(t, err)
	require.NotNil(t, response)
	require.Equal(t, 1, len(response))

	// Verify all data is present
	require.Len(t, response, 1)
	require.Equal(t, types.ChainSelector(2), response[0].Data.DestChainSelector)
}

func setupReaderWithMessagesfunc(t *testing.T, baseTime int64, numMessages int, limit uint64) *InMemoryOffchainStorage {
	lggr := logger.Test(t)

	// Use fixed time provider for predictable tests
	timeProvider := func() int64 { return baseTime }
	storage := NewInMemoryOffchainStorageWithTimeProvider(
		lggr, timeProvider, []types.ChainSelector{2}, []types.ChainSelector{1}, limit, 0, baseTime-1)

	// create numMessages, each 10 seconds apart
	for i := 0; i < numMessages; i++ {
		storage.timeProvider = func() int64 { return baseTime + (10 * int64(i)) }
		testData1 := []types.CCVData{
			{
				MessageID:             [32]byte{1},
				SequenceNumber:        100,
				SourceChainSelector:   1,
				DestChainSelector:     2,
				SourceVerifierAddress: []byte("0x1234"),
				DestVerifierAddress:   []byte("0x4567"),
				CCVData:               []byte("sig1"),
				Message:               createTestMessage(100, 1, 2),
			},
		}

		// Store first data at baseTime
		err := storage.WriteCCVData(t.Context(), testData1)
		require.NoError(t, err)
	}

	return storage
}

func TestManySequentialReads(t *testing.T) {
	baseTime := time.Now().UnixMicro()
	ctx := t.Context()

	tests := []struct {
		name          string
		numMessages   int
		limit         int
		expectedReads int
	}{
		{
			name:          "10 messages with limit 3",
			numMessages:   10,
			limit:         3,
			expectedReads: 4, // 3 full reads + 1 partial
		},
		{
			name:          "5 messages with limit 2",
			numMessages:   5,
			limit:         2,
			expectedReads: 3, // 2 full reads + 1 partial
		},
		{
			name:          "7 messages with limit 10",
			numMessages:   7,
			limit:         10,
			expectedReads: 1, // all in one read
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := setupReaderWithMessagesfunc(t, baseTime, tt.numMessages, uint64(tt.limit))
			totalRetrieved := 0
			for {
				response, err := storage.ReadCCVData(ctx)
				require.NoError(t, err)
				require.NotNil(t, response)

				totalRetrieved += len(response)

				// If fewer than limit were returned, we've reached the end
				if len(response) < tt.limit {
					break
				}
			}

			require.Equal(t, tt.numMessages, totalRetrieved)
		})
	}
}

func TestEmptyReadsAndReadAfterEmpty(t *testing.T) {
	baseTime := time.Now().UnixMicro()
	ctx := t.Context()

	storage := setupReaderWithMessagesfunc(t, baseTime, 99, 50)
	{
		// Read first 50 messages
		results, err := storage.ReadCCVData(ctx)
		require.NoError(t, err)
		require.Len(t, results, 50)
	}

	{
		// Read remaining 49 messages
		results, err := storage.ReadCCVData(ctx)
		require.NoError(t, err)
		require.Len(t, results, 49)
	}

	{
		// Next read should return empty
		results, err := storage.ReadCCVData(ctx)
		require.NoError(t, err)
		require.Len(t, results, 0)
	}

	{
		// Add 1 more message, it should be returned by the next read.
		seqNum := types.SeqNum(987654321)
		timeProvider := func() int64 { return baseTime + (10 * int64(100)) }
		storage.timeProvider = timeProvider
		testData1 := []types.CCVData{
			{
				MessageID:             [32]byte{1},
				SequenceNumber:        seqNum,
				SourceChainSelector:   1,
				DestChainSelector:     2,
				SourceVerifierAddress: []byte("0x1234"),
				DestVerifierAddress:   []byte("0x4567"),
				CCVData:               []byte("sig1"),
				Message:               createTestMessage(100, 1, 2),
			},
		}
		err := storage.WriteCCVData(t.Context(), testData1)
		require.NoError(t, err)

		// Next read should return the new message
		results, err := storage.ReadCCVData(ctx)
		require.NoError(t, err)
		require.Len(t, results, 1)
		require.Equal(t, seqNum, results[0].Data.SequenceNumber)
	}
}

/*
// I don't think these tests are valid anymore.
func TestInMemoryOffchainStorage_DestinationChainOrganization(t *testing.T) {
	lggr := logger.Test(t)
	storage := NewInMemoryOffchainStorage(lggr)

	ctx := context.Background()
	verifierAddress := []byte("0x1234")

	// Create data for different destination chains
	testData := []common.CCVData{
		{
			MessageID:             [32]byte{1},
			SequenceNumber:        100,
			SourceChainSelector:   1,
			DestChainSelector:     10, // Chain 10
			SourceVerifierAddress: verifierAddress,
			CCVData:               []byte("sig1"),
			Message:               createTestMessage(100, 1, 10),
		},
		{
			MessageID:             [32]byte{2},
			SequenceNumber:        101,
			SourceChainSelector:   1,
			DestChainSelector:     20, // Chain 20
			SourceVerifierAddress: verifierAddress,
			CCVData:               []byte("sig2"),
			Message:               createTestMessage(101, 1, 20),
		},
		{
			MessageID:             [32]byte{3},
			SequenceNumber:        102,
			SourceChainSelector:   1,
			DestChainSelector:     10, // Chain 10 again
			SourceVerifierAddress: verifierAddress,
			CCVData:               []byte("sig3"),
			Message:               createTestMessage(102, 1, 10),
		},
	}

	// Store data
	err := storage.WriteCCVData(ctx, testData)
	require.NoError(t, err)

	// Query for both destination chains
	response, err := storage.GetCCVDataByTimestamp(
		ctx,
		[]types.ChainSelector{10, 20}, // Both dest chains
		0,                                 // start timestamp
		[]types.ChainSelector{1},      // source chain
		100,                               // limit
		0,                                 // offset
	)
	require.NoError(t, err)
	require.NotNil(t, response)
	require.Equal(t, 3, response.TotalCount)

	// Verify data is organized by destination chain
	chain10Data, exists := response.Data[10]
	require.True(t, exists)
	require.Len(t, chain10Data, 2) // Two messages for chain 10

	chain20Data, exists := response.Data[20]
	require.True(t, exists)
	require.Len(t, chain20Data, 1) // One message for chain 20

	// Query for only chain 10
	response, err = storage.GetCCVDataByTimestamp(
		ctx,
		[]types.ChainSelector{10}, // Only chain 10
		0,                             // start timestamp
		[]types.ChainSelector{1},  // source chain
		100,                           // limit
		0,                             // offset
	)
	require.NoError(t, err)
	require.NotNil(t, response)
	require.Equal(t, 2, response.TotalCount)

	// Should only have chain 10 data
	_, exists = response.Data[10]
	require.True(t, exists)
	_, exists = response.Data[20]
	require.False(t, exists)
}
*/
