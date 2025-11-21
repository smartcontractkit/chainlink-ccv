//go:build race

package storage

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// TestInMemoryStorage_Race_ConcurrentInserts tests that multiple goroutines can insert data concurrently
// without data races when accessing shared storage state.
func TestInMemoryStorage_Race_ConcurrentInserts(t *testing.T) {
	storage := NewInMemoryStorage(logger.Nop(), monitoring.NewNoopIndexerMonitoring())
	ctx := context.Background()

	numGoroutines := 10
	insertsPerGoroutine := 20

	var wg sync.WaitGroup
	for i := range numGoroutines {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := range insertsPerGoroutine {
				messageID := fmt.Sprintf("0x%03d%03d", goroutineID, j)
				ccvData := createTestCCVData(messageID, int64(1000+goroutineID*100+j), protocol.ChainSelector(goroutineID%5), protocol.ChainSelector((goroutineID+1)%5))
				err := storage.InsertCCVData(ctx, ccvData)
				assert.NoError(t, err)
			}
		}(i)
	}

	wg.Wait()

	// Verify all data was inserted correctly
	results, err := storage.QueryCCVData(ctx, 0, 99999, nil, nil, 1000, 0)
	require.NoError(t, err)
	assert.Equal(t, numGoroutines*insertsPerGoroutine, len(results))
}

// TestInMemoryStorage_Race_ConcurrentReads tests that multiple goroutines can read data concurrently
// without data races.
func TestInMemoryStorage_Race_ConcurrentReads(t *testing.T) {
	storage := NewInMemoryStorage(logger.Nop(), monitoring.NewNoopIndexerMonitoring())
	ctx := context.Background()

	// Pre-populate with test data
	numMessages := 50
	for i := range numMessages {
		messageID := fmt.Sprintf("0x%03d", i)
		ccvData := createTestCCVData(messageID, int64(1000+i), 1, 2)
		err := storage.InsertCCVData(ctx, ccvData)
		require.NoError(t, err)
	}

	// Perform concurrent reads
	numGoroutines := 20
	readsPerGoroutine := 10

	var wg sync.WaitGroup
	for i := range numGoroutines {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := range readsPerGoroutine {
				// Read random message
				messageIdx := (goroutineID + j) % numMessages
				messageID := createTestBytes32(fmt.Sprintf("0x%03d", messageIdx))
				data, err := storage.GetCCVData(ctx, messageID)
				if err == nil {
					assert.NotEmpty(t, data)
				}
			}
		}(i)
	}

	wg.Wait()
}

// TestInMemoryStorage_Race_ConcurrentQueries tests that multiple goroutines can query data concurrently
// without data races.
func TestInMemoryStorage_Race_ConcurrentQueries(t *testing.T) {
	storage := NewInMemoryStorage(logger.Nop(), monitoring.NewNoopIndexerMonitoring())
	ctx := context.Background()

	// Pre-populate with test data
	numMessages := 100
	for i := range numMessages {
		messageID := fmt.Sprintf("0x%03d", i)
		ccvData := createTestCCVData(messageID, int64(1000+i*10), protocol.ChainSelector(i%5), protocol.ChainSelector((i+1)%5))
		err := storage.InsertCCVData(ctx, ccvData)
		require.NoError(t, err)
	}

	// Perform concurrent queries with different filters
	numGoroutines := 15
	queriesPerGoroutine := 10

	var wg sync.WaitGroup
	for i := range numGoroutines {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := range queriesPerGoroutine {
				// Query with different timestamp ranges
				start := int64(1000 + (goroutineID+j)*50)
				end := start + 200

				// Vary the filters
				var sourceChains, destChains []protocol.ChainSelector
				if goroutineID%3 == 0 {
					sourceChains = []protocol.ChainSelector{protocol.ChainSelector(goroutineID % 5)}
				}
				if goroutineID%3 == 1 {
					destChains = []protocol.ChainSelector{protocol.ChainSelector((goroutineID + 1) % 5)}
				}

				results, err := storage.QueryCCVData(ctx, start, end, sourceChains, destChains, 50, 0)
				assert.NoError(t, err)
				assert.NotNil(t, results)
			}
		}(i)
	}

	wg.Wait()
}

// TestInMemoryStorage_Race_MixedReadsAndWrites tests concurrent reads and writes to ensure proper mutex handling.
func TestInMemoryStorage_Race_MixedReadsAndWrites(t *testing.T) {
	storage := NewInMemoryStorage(logger.Nop(), monitoring.NewNoopIndexerMonitoring())
	ctx := context.Background()

	// Pre-populate with some initial data
	for i := range 20 {
		messageID := fmt.Sprintf("0x%03d", i)
		ccvData := createTestCCVData(messageID, int64(1000+i), 1, 2)
		err := storage.InsertCCVData(ctx, ccvData)
		require.NoError(t, err)
	}

	numGoroutines := 20
	operationsPerGoroutine := 25

	var wg sync.WaitGroup
	for i := range numGoroutines {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := range operationsPerGoroutine {
				// Alternate between reads and writes
				if (goroutineID+j)%2 == 0 {
					// Write
					messageID := fmt.Sprintf("0x%03d%03d", goroutineID, j)
					ccvData := createTestCCVData(messageID, int64(2000+goroutineID*100+j), protocol.ChainSelector(goroutineID%5), protocol.ChainSelector((goroutineID+1)%5))
					err := storage.InsertCCVData(ctx, ccvData)
					assert.NoError(t, err)
				} else {
					// Read
					results, err := storage.QueryCCVData(ctx, 0, 99999, nil, nil, 10, uint64(goroutineID%5))
					assert.NoError(t, err)
					assert.NotNil(t, results)
				}
			}
		}(i)
	}

	wg.Wait()

	// Verify storage is still consistent
	results, err := storage.QueryCCVData(ctx, 0, 99999, nil, nil, 1000, 0)
	require.NoError(t, err)
	assert.NotEmpty(t, results)
}

// TestInMemoryStorage_Race_HeavyConcurrentLoad tests the storage under heavy concurrent load
// to stress test the mutex and data structure integrity.
func TestInMemoryStorage_Race_HeavyConcurrentLoad(t *testing.T) {
	storage := NewInMemoryStorage(logger.Nop(), monitoring.NewNoopIndexerMonitoring())
	ctx := context.Background()

	numWriters := 10
	numReaders := 15
	writesPerWriter := 50
	readsPerReader := 50

	var wg sync.WaitGroup

	// Start writers
	for i := range numWriters {
		wg.Add(1)
		go func(writerID int) {
			defer wg.Done()
			for j := range writesPerWriter {
				messageID := fmt.Sprintf("0x%03d%03d", writerID, j)
				ccvData := createTestCCVData(messageID, int64(1000+writerID*1000+j), protocol.ChainSelector(writerID%5), protocol.ChainSelector((writerID+1)%5))
				err := storage.InsertCCVData(ctx, ccvData)
				assert.NoError(t, err)
				// Small sleep to allow interleaving
				time.Sleep(time.Microsecond)
			}
		}(i)
	}

	// Start readers
	for i := range numReaders {
		wg.Add(1)
		go func(readerID int) {
			defer wg.Done()
			for j := range readsPerReader {
				// Mix of GetCCVData and QueryCCVData
				if (readerID+j)%2 == 0 {
					// Query
					start := int64(1000 + readerID*50)
					end := start + 5000
					sourceChains := []protocol.ChainSelector{protocol.ChainSelector(readerID % 5)}
					results, err := storage.QueryCCVData(ctx, start, end, sourceChains, nil, 20, 0)
					assert.NoError(t, err)
					assert.NotNil(t, results)
				} else {
					// Get specific message (may not exist yet, that's ok)
					messageIdx := (readerID + j) % numWriters
					messageID := createTestBytes32(fmt.Sprintf("0x%03d000", messageIdx))
					_, _ = storage.GetCCVData(ctx, messageID)
				}
				time.Sleep(time.Microsecond)
			}
		}(i)
	}

	wg.Wait()

	// Final verification
	results, err := storage.QueryCCVData(ctx, 0, 99999, nil, nil, 1000, 0)
	require.NoError(t, err)
	assert.NotEmpty(t, results)
}

// TestInMemoryStorage_Race_SameMessageIDConcurrent tests concurrent inserts of CCVData with the same messageID
// to ensure the append operation is thread-safe.
func TestInMemoryStorage_Race_SameMessageIDConcurrent(t *testing.T) {
	storage := NewInMemoryStorage(logger.Nop(), monitoring.NewNoopIndexerMonitoring())
	ctx := context.Background()

	messageID := "0x123456"
	numGoroutines := 20

	var wg sync.WaitGroup
	for i := range numGoroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// All goroutines insert data with the same messageID but different timestamps
			ccvData := createTestCCVData(messageID, int64(1000+idx), 1, 2)
			err := storage.InsertCCVData(ctx, ccvData)
			assert.NoError(t, err)
		}(i)
	}

	wg.Wait()

	// Verify all inserts were recorded
	// Use the padded version of the messageID to match what createTestCCVData generates
	paddedMessageID := fmt.Sprintf("0x%064s", messageID[2:])
	retrievedData, err := storage.GetCCVData(ctx, createTestBytes32(paddedMessageID))
	require.NoError(t, err)
	assert.Equal(t, numGoroutines, len(retrievedData), "All concurrent inserts should be recorded")
}

// TestInMemoryStorage_Race_TimestampSortingUnderConcurrency tests that the timestamp-sorted slice
// maintains its integrity under concurrent inserts.
func TestInMemoryStorage_Race_TimestampSortingUnderConcurrency(t *testing.T) {
	storage := NewInMemoryStorage(logger.Nop(), monitoring.NewNoopIndexerMonitoring())
	ctx := context.Background()

	numGoroutines := 10
	insertsPerGoroutine := 30

	var wg sync.WaitGroup
	for i := range numGoroutines {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := range insertsPerGoroutine {
				// Insert with varying timestamps to test sorting
				messageID := fmt.Sprintf("0x%03d%03d", goroutineID, j)
				timestamp := int64(1000 + (goroutineID*insertsPerGoroutine+j)*10)
				ccvData := createTestCCVData(messageID, timestamp, 1, 2)
				err := storage.InsertCCVData(ctx, ccvData)
				assert.NoError(t, err)
			}
		}(i)
	}

	wg.Wait()

	// Verify timestamp ordering is maintained
	inMemStorage := storage.(*InMemoryStorage)
	inMemStorage.mu.RLock()
	defer inMemStorage.mu.RUnlock()

	for i := 1; i < len(inMemStorage.verifierResultStorage.byTimestamp); i++ {
		assert.LessOrEqual(t, inMemStorage.verifierResultStorage.byTimestamp[i-1].Metadata.IngestionTimestamp, inMemStorage.verifierResultStorage.byTimestamp[i].Metadata.IngestionTimestamp,
			"Timestamps should be sorted in ascending order")
	}
}

// TestInMemoryStorage_Race_ChainSelectorIndexesUnderConcurrency tests that chain selector indexes
// are updated correctly under concurrent inserts.
func TestInMemoryStorage_Race_ChainSelectorIndexesUnderConcurrency(t *testing.T) {
	storage := NewInMemoryStorage(logger.Nop(), monitoring.NewNoopIndexerMonitoring())
	ctx := context.Background()

	numGoroutines := 15
	insertsPerGoroutine := 20

	var wg sync.WaitGroup
	for i := range numGoroutines {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := range insertsPerGoroutine {
				messageID := fmt.Sprintf("0x%03d%03d", goroutineID, j)
				sourceChain := protocol.ChainSelector(goroutineID % 5)
				destChain := protocol.ChainSelector((goroutineID + 1) % 5)
				ccvData := createTestCCVData(messageID, int64(1000+goroutineID*100+j), sourceChain, destChain)
				err := storage.InsertCCVData(ctx, ccvData)
				assert.NoError(t, err)
			}
		}(i)
	}

	wg.Wait()

	// Verify chain selector queries work correctly
	for chainID := range 5 {
		sourceChains := []protocol.ChainSelector{protocol.ChainSelector(chainID)}
		results, err := storage.QueryCCVData(ctx, 0, 99999, sourceChains, nil, 1000, 0)
		require.NoError(t, err)
		assert.NotEmpty(t, results, "Should find results for chain selector %d", chainID)
	}
}

// TestInMemoryStorage_Race_PaginationUnderConcurrency tests that pagination works correctly
// when queries run concurrently with inserts.
func TestInMemoryStorage_Race_PaginationUnderConcurrency(t *testing.T) {
	storage := NewInMemoryStorage(logger.Nop(), monitoring.NewNoopIndexerMonitoring())
	ctx := context.Background()

	// Pre-populate with some data
	for i := range 50 {
		messageID := fmt.Sprintf("0x%03d", i)
		ccvData := createTestCCVData(messageID, int64(1000+i*10), 1, 2)
		err := storage.InsertCCVData(ctx, ccvData)
		require.NoError(t, err)
	}

	numGoroutines := 20
	var wg sync.WaitGroup

	for i := range numGoroutines {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			if goroutineID%2 == 0 {
				// Writer
				for j := range 10 {
					messageID := fmt.Sprintf("0x%03d%03d", goroutineID, j)
					ccvData := createTestCCVData(messageID, int64(2000+goroutineID*100+j), 1, 2)
					err := storage.InsertCCVData(ctx, ccvData)
					assert.NoError(t, err)
				}
			} else {
				// Reader with pagination
				for j := range 10 {
					limit := uint64(5)
					offset := uint64(j * 5)
					results, err := storage.QueryCCVData(ctx, 0, 99999, nil, nil, limit, offset)
					assert.NoError(t, err)
					assert.NotNil(t, results)
					// Results can vary in size due to concurrent inserts, which is expected
				}
			}
		}(i)
	}

	wg.Wait()
}

// TestInMemoryStorage_Race_ContextCancellation tests that storage operations respect context cancellation
// under concurrent load without causing races.
func TestInMemoryStorage_Race_ContextCancellation(t *testing.T) {
	storage := NewInMemoryStorage(logger.Nop(), monitoring.NewNoopIndexerMonitoring())

	numGoroutines := 10
	var wg sync.WaitGroup

	// Create a context that will be canceled mid-operation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for i := range numGoroutines {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := range 50 {
				messageID := fmt.Sprintf("0x%03d%03d", goroutineID, j)
				ccvData := createTestCCVData(messageID, int64(1000+goroutineID*100+j), 1, 2)
				// Ignore errors since context may be canceled
				_ = storage.InsertCCVData(ctx, ccvData)

				// Small sleep to allow cancellation to happen mid-operation
				if j == 25 && goroutineID == 0 {
					cancel()
				}
			}
		}(i)
	}

	wg.Wait()

	// Verify storage is still in a consistent state
	freshCtx := context.Background()
	results, err := storage.QueryCCVData(freshCtx, 0, 99999, nil, nil, 1000, 0)
	require.NoError(t, err)
	assert.NotNil(t, results)
}
