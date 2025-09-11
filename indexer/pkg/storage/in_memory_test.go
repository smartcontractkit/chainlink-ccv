package storage

import (
	"context"
	"encoding/hex"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

// createTestCCVData creates a test CCVData with the given parameters.
func createTestCCVData(messageID types.Bytes32, timestamp int64, sequenceNumber types.SeqNum) types.CCVData {
	return types.CCVData{
		MessageID:             messageID,
		SequenceNumber:        sequenceNumber,
		SourceChainSelector:   1,
		DestChainSelector:     2,
		SourceVerifierAddress: []byte("0x1234"),
		DestVerifierAddress:   []byte("0x5678"),
		CCVData:               []byte("test_ccv_data"),
		BlobData:              []byte("test_blob_data"),
		Timestamp:             timestamp,
		ReceiptBlobs: []types.ReceiptWithBlob{
			{
				Issuer:            []byte("0x1234"),
				DestGasLimit:      100000,
				DestBytesOverhead: 50,
				Blob:              []byte("test_blob"),
				ExtraArgs:         []byte("extra"),
			},
		},
		Message: types.Message{
			SourceChainSelector: 1,
			DestChainSelector:   2,
			SequenceNumber:      sequenceNumber,
			Sender:              []byte("sender"),
			Receiver:            []byte("receiver"),
			Data:                []byte("test_data"),
		},
	}
}

func TestNewInMemoryStorage(t *testing.T) {
	storage := NewInMemoryStorage()

	// Verify it implements the interface
	var _ common.IndexerStorage = storage

	// Verify it's not nil
	assert.NotNil(t, storage)

	// Verify internal state is initialized
	inMemStorage := storage.(*InMemoryStorage)
	assert.NotNil(t, inMemStorage.ccvData)
}

func TestInMemoryStorage_GetCCVData_Success(t *testing.T) {
	storage := NewInMemoryStorage().(*InMemoryStorage)
	ctx := context.Background()

	messageID := types.Bytes32{1, 2, 3, 4, 5}
	expectedData := []types.CCVData{
		createTestCCVData(messageID, 1000, 100),
		createTestCCVData(messageID, 1001, 101),
	}

	// Store data directly in the map
	storage.ccvData.Store(messageID, expectedData)

	// Retrieve data
	result, err := storage.GetCCVData(ctx, messageID)

	require.NoError(t, err)
	require.Len(t, result, 2)
	assert.Equal(t, expectedData[0], result[0])
	assert.Equal(t, expectedData[1], result[1])
}

func TestInMemoryStorage_GetCCVData_NotFound(t *testing.T) {
	storage := NewInMemoryStorage()
	ctx := context.Background()

	messageID := types.Bytes32{9, 9, 9, 9, 9}

	// Try to retrieve non-existent data
	result, err := storage.GetCCVData(ctx, messageID)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, ErrCCVDataNotFound, err)
}

func TestInMemoryStorage_QueryCCVDataByTimestamp(t *testing.T) {
	storage := NewInMemoryStorage().(*InMemoryStorage)
	ctx := context.Background()

	// Create test data with different timestamps
	messageID1 := types.Bytes32{1, 1, 1, 1, 1}
	messageID2 := types.Bytes32{2, 2, 2, 2, 2}
	messageID3 := types.Bytes32{3, 3, 3, 3, 3}

	data1 := []types.CCVData{createTestCCVData(messageID1, 1000, 100)}
	data2 := []types.CCVData{createTestCCVData(messageID2, 1500, 101)}
	data3 := []types.CCVData{createTestCCVData(messageID3, 2000, 102)}

	// Store data
	storage.ccvData.Store(messageID1, data1)
	storage.ccvData.Store(messageID2, data2)
	storage.ccvData.Store(messageID3, data3)

	tests := []struct {
		name          string
		start         int64
		end           int64
		expectedCount int
		expectedKeys  []string
	}{
		{
			name:          "all data in range",
			start:         500,
			end:           2500,
			expectedCount: 3,
			expectedKeys:  []string{hex.EncodeToString(messageID1[:]), hex.EncodeToString(messageID2[:]), hex.EncodeToString(messageID3[:])},
		},
		{
			name:          "partial range",
			start:         1200,
			end:           1800,
			expectedCount: 1,
			expectedKeys:  []string{hex.EncodeToString(messageID2[:])},
		},
		{
			name:          "no data in range",
			start:         3000,
			end:           4000,
			expectedCount: 0,
			expectedKeys:  []string{},
		},
		{
			name:          "exact timestamp match",
			start:         1500,
			end:           1500,
			expectedCount: 1,
			expectedKeys:  []string{hex.EncodeToString(messageID2[:])},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := storage.QueryCCVDataByTimestamp(ctx, tt.start, tt.end)

			require.NoError(t, err)
			assert.Equal(t, tt.expectedCount, len(result))

			// Verify all expected keys are present
			for _, expectedKey := range tt.expectedKeys {
				_, exists := result[expectedKey]
				assert.True(t, exists, "Expected key %s not found in result", expectedKey)
			}

			// Verify no unexpected keys
			for key := range result {
				found := false
				for _, expectedKey := range tt.expectedKeys {
					if key == expectedKey {
						found = true
						break
					}
				}
				assert.True(t, found, "Unexpected key %s found in result", key)
			}
		})
	}
}

func TestInMemoryStorage_InsertCCVData_NewMessageID(t *testing.T) {
	storage := NewInMemoryStorage()
	ctx := context.Background()

	messageID := types.Bytes32{1, 2, 3, 4, 5}
	ccvData := createTestCCVData(messageID, 1000, 100)

	// Insert new data
	err := storage.InsertCCVData(ctx, ccvData)

	require.NoError(t, err)

	// Verify data was stored
	result, err := storage.GetCCVData(ctx, messageID)
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, ccvData, result[0])
}

func TestInMemoryStorage_InsertCCVData_ExistingMessageID(t *testing.T) {
	storage := NewInMemoryStorage()
	ctx := context.Background()

	messageID := types.Bytes32{1, 2, 3, 4, 5}
	ccvData1 := createTestCCVData(messageID, 1000, 100)
	ccvData2 := createTestCCVData(messageID, 1001, 101)

	// Insert first data
	err := storage.InsertCCVData(ctx, ccvData1)
	require.NoError(t, err)

	// Insert second data with same messageID
	err = storage.InsertCCVData(ctx, ccvData2)
	require.NoError(t, err)

	// Verify both data entries were stored
	result, err := storage.GetCCVData(ctx, messageID)
	require.NoError(t, err)
	require.Len(t, result, 2)
	assert.Equal(t, ccvData1, result[0])
	assert.Equal(t, ccvData2, result[1])
}

func TestInMemoryStorage_InsertCCVData_MultipleAppends(t *testing.T) {
	storage := NewInMemoryStorage()
	ctx := context.Background()

	messageID := types.Bytes32{1, 2, 3, 4, 5}

	// Insert multiple data entries with same messageID
	for i := range 5 {
		ccvData := createTestCCVData(messageID, int64(1000+i), types.SeqNum(100+i))
		err := storage.InsertCCVData(ctx, ccvData)
		require.NoError(t, err)
	}

	// Verify all data entries were stored
	result, err := storage.GetCCVData(ctx, messageID)
	require.NoError(t, err)
	require.Len(t, result, 5)

	// Verify data is in correct order
	for i := range 5 {
		assert.Equal(t, types.SeqNum(100+i), result[i].SequenceNumber)
		assert.Equal(t, int64(1000+i), result[i].Timestamp)
	}
}

func TestInMemoryStorage_ConcurrentAccess(t *testing.T) {
	storage := NewInMemoryStorage().(*InMemoryStorage)
	ctx := context.Background()

	const numGoroutines = 10
	const numOperations = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Test concurrent writes
	for i := range numGoroutines {
		go func(goroutineID int) {
			defer wg.Done()

			for j := 0; j < numOperations; j++ {
				messageID := types.Bytes32{byte(goroutineID), byte(j), 0, 0, 0}
				ccvData := createTestCCVData(messageID, int64(1000+j), types.SeqNum(100+j))

				err := storage.InsertCCVData(ctx, ccvData)
				require.NoError(t, err)
			}
		}(i)
	}

	wg.Wait()

	// Verify all data was stored correctly
	totalExpected := numGoroutines * numOperations
	actualCount := 0

	storage.ccvData.Range(func(key, value any) bool {
		actualCount++
		return true
	})

	assert.Equal(t, totalExpected, actualCount)
}

func TestInMemoryStorage_ConcurrentReadWrite(t *testing.T) {
	storage := NewInMemoryStorage().(*InMemoryStorage)
	ctx := context.Background()

	const numWriters = 5
	const numReaders = 5
	const numOperations = 50

	var wg sync.WaitGroup

	// Start writers
	wg.Add(numWriters)
	for i := 0; i < numWriters; i++ {
		go func(writerID int) {
			defer wg.Done()

			for j := 0; j < numOperations; j++ {
				messageID := types.Bytes32{byte(writerID), byte(j), 0, 0, 0}
				ccvData := createTestCCVData(messageID, int64(1000+j), types.SeqNum(100+j))

				err := storage.InsertCCVData(ctx, ccvData)
				require.NoError(t, err)
			}
		}(i)
	}

	// Start readers
	wg.Add(numReaders)
	for i := 0; i < numReaders; i++ {
		go func(readerID int) {
			defer wg.Done()

			for j := 0; j < numOperations; j++ {
				messageID := types.Bytes32{byte(readerID), byte(j), 0, 0, 0}

				// Try to read - might not exist yet, that's ok
				_, err := storage.GetCCVData(ctx, messageID)
				// Don't assert error here as data might not be written yet
				_ = err

				// Query by timestamp
				_, err = storage.QueryCCVDataByTimestamp(ctx, 0, 2000)
				require.NoError(t, err)
			}
		}(i)
	}

	wg.Wait()
}

func TestInMemoryStorage_DataIntegrity(t *testing.T) {
	storage := NewInMemoryStorage()
	ctx := context.Background()

	// Test that data is not modified after storage
	messageID := types.Bytes32{1, 2, 3, 4, 5}
	originalData := createTestCCVData(messageID, 1000, 100)

	err := storage.InsertCCVData(ctx, originalData)
	require.NoError(t, err)

	// Modify original data
	originalData.CCVData = []byte("modified")
	originalData.Timestamp = 9999

	// Retrieve and verify data wasn't affected
	result, err := storage.GetCCVData(ctx, messageID)
	require.NoError(t, err)
	require.Len(t, result, 1)

	assert.Equal(t, []byte("test_ccv_data"), result[0].CCVData)
	assert.Equal(t, int64(1000), result[0].Timestamp)
}

func TestInMemoryStorage_QueryCCVDataByTimestamp_EmptyStorage(t *testing.T) {
	storage := NewInMemoryStorage()
	ctx := context.Background()

	// Query empty storage
	result, err := storage.QueryCCVDataByTimestamp(ctx, 0, 2000)

	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestInMemoryStorage_QueryCCVDataByTimestamp_KeyFormat(t *testing.T) {
	storage := NewInMemoryStorage()
	ctx := context.Background()

	messageID := types.Bytes32{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0}
	ccvData := createTestCCVData(messageID, 1000, 100)

	err := storage.InsertCCVData(ctx, ccvData)
	require.NoError(t, err)

	result, err := storage.QueryCCVDataByTimestamp(ctx, 0, 2000)
	require.NoError(t, err)
	require.Len(t, result, 1)

	// Verify key format is hex-encoded
	expectedKey := hex.EncodeToString(messageID[:])
	for key := range result {
		assert.Equal(t, expectedKey, key)
	}
}
