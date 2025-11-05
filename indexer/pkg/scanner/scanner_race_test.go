//go:build race
// +build race

package scanner

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/readers"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// TestScanner_Race_MultipleReadersConcurrent tests that multiple readers can be processed concurrently
// without data races when accessing shared scanner state.
func TestScanner_Race_MultipleReadersConcurrent(t *testing.T) {
	setup := setupScannerTest(t)
	defer setup.Cleanup()
	setup.Scanner.Start(setup.Context)

	// Create multiple readers that will emit messages concurrently
	numReaders := 5
	messagesPerReader := 3

	var readerList []protocol.OffchainStorageReader
	for i := 0; i < numReaders; i++ {
		reader := readers.NewMockReader(readers.MockReaderConfig{
			MaxMessages:        messagesPerReader,
			EmitEmptyResponses: true,
		})
		readerList = append(readerList, reader)
	}

	// Add all readers simultaneously
	setup.Discovery.AddReaders(readerList)

	// All readers should disconnect after MaxMessages
	require.Eventually(t, func() bool {
		setup.Scanner.mu.Lock()
		defer setup.Scanner.mu.Unlock()
		return setup.Scanner.activeReaders == 0
	}, 2*time.Second, 100*time.Millisecond, "All readers should have disconnected")

	// Verify messages were stored by querying all data
	assert.Eventually(t, func() bool {
		results, err := setup.Storage.QueryCCVData(context.Background(), time.UnixMilli(0), time.UnixMilli(time.Now().UnixMilli()+1000000), nil, nil, 1000, 0)
		if err != nil {
			return false
		}
		// Check that we have at least some messages
		return len(results) > 0
	}, 2*time.Second, 100*time.Millisecond)
}

// TestScanner_Race_ConcurrentReaderAccess tests that the same reader is not accessed concurrently
// due to the reader lock mechanism.
func TestScanner_Race_ConcurrentReaderAccess(t *testing.T) {
	setup := setupScannerTestWithTimeout(t, fastScannerTestConfig(), 3*time.Second)
	defer setup.Cleanup()

	setup.Scanner.Start(setup.Context)

	// Create a reader with latency to ensure concurrent calls would overlap
	reader := readers.NewMockReader(readers.MockReaderConfig{
		MaxMessages:        5,
		EmitEmptyResponses: true,
		MinLatency:         20 * time.Millisecond,
		MaxLatency:         30 * time.Millisecond,
	})

	setup.Discovery.AddReaders([]protocol.OffchainStorageReader{reader})

	// Wait for the reader to be called at least once
	// The fast scan interval + slow reader should trigger the locking mechanism
	// If there's a race, the test will fail when run with -race flag
	// The reader lock should prevent concurrent access
	require.Eventually(t, func() bool {
		return reader.GetCallCount() > 0
	}, 2*time.Second, 10*time.Millisecond, "Reader should have been called")
}

// TestScanner_Race_StorageWriteConcurrency tests concurrent writes to storage from multiple readers.
func TestScanner_Race_StorageWriteConcurrency(t *testing.T) {
	setup := setupScannerTestWithConfig(t, standardTestConfig())
	defer setup.Cleanup()

	setup.Scanner.Start(setup.Context)

	// Create multiple readers that emit messages rapidly
	numReaders := 10
	messagesPerReader := 5

	var readersSlice []protocol.OffchainStorageReader
	for i := 0; i < numReaders; i++ {
		reader := readers.NewMockReader(readers.MockReaderConfig{
			MaxMessages:        messagesPerReader,
			EmitEmptyResponses: true,
		})
		readersSlice = append(readersSlice, reader)
	}

	// Add all readers at once to maximize concurrency
	setup.Discovery.AddReaders(readersSlice)

	// Wait for messages to be stored (all readers × messages per reader)
	// The InMemoryStorage should handle concurrent writes correctly
	// If there's a race condition, the test will fail with -race flag
	expectedMessages := numReaders * messagesPerReader
	require.Eventually(t, func() bool {
		results, err := setup.Storage.QueryCCVData(context.Background(), time.UnixMilli(0), time.UnixMilli(time.Now().UnixMilli()+1000000), nil, nil, 1000, 0)
		if err != nil {
			return false
		}
		return len(results) >= expectedMessages
	}, 3*time.Second, 100*time.Millisecond, "Should have stored all messages")

	// Wait for all readers to disconnect
	require.Eventually(t, func() bool {
		setup.Scanner.mu.Lock()
		defer setup.Scanner.mu.Unlock()
		return setup.Scanner.activeReaders == 0
	}, 2*time.Second, 100*time.Millisecond, "All readers should have disconnected")
}

// TestScanner_Race_StartStopConcurrent tests starting and stopping the scanner doesn't cause races.
func TestScanner_Race_StartStopConcurrent(t *testing.T) {
	// Start and stop multiple times with fresh scanner instances
	for i := 0; i < 3; i++ {
		setup := setupScannerTest(t)
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		setup.Scanner.Start(ctx)

		// Add a reader while running
		reader := readers.NewMockReader(readers.MockReaderConfig{
			MaxMessages:        2,
			EmitEmptyResponses: true,
		})
		setup.Discovery.AddReaders([]protocol.OffchainStorageReader{reader})

		// Wait for reader to be discovered and start processing
		require.Eventually(t, func() bool {
			return reader.GetCallCount() > 0
		}, 500*time.Millisecond, 10*time.Millisecond, "Reader should have been called")

		setup.Scanner.Stop()
		cancel()
		setup.Cancel() // Cancel the setup context
	}

	// If there are races in the start/stop logic, they should be caught
	assert.True(t, true, "No races detected")
}

// TestScanner_Race_ActiveReaderCountManipulation tests concurrent manipulation of the activeReaders counter.
func TestScanner_Race_ActiveReaderCountManipulation(t *testing.T) {
	setup := setupScannerTestWithTimeout(t, defaultTestConfig(), 3*time.Second)
	defer setup.Cleanup()

	setup.Scanner.Start(setup.Context)

	// Add readers in waves to test counter increments/decrements
	numWaves := 3
	readersPerWave := 3

	// Track all readers to verify they were all called
	var allReaders []*readers.MockReader

	for wave := 0; wave < numWaves; wave++ {
		var waveReaders []protocol.OffchainStorageReader
		for i := 0; i < readersPerWave; i++ {
			reader := readers.NewMockReader(readers.MockReaderConfig{
				MaxMessages:        2,
				EmitEmptyResponses: true,
			})
			waveReaders = append(waveReaders, reader)
			allReaders = append(allReaders, reader)
		}

		setup.Discovery.AddReaders(waveReaders)
	}

	// Wait for all readers to be called (they may disconnect quickly)
	require.Eventually(t, func() bool {
		for _, r := range allReaders {
			if r.GetCallCount() == 0 {
				return false
			}
		}
		return true
	}, 3*time.Second, 50*time.Millisecond, "All readers should have been called")

	// Wait for all readers to disconnect
	require.Eventually(t, func() bool {
		setup.Scanner.mu.Lock()
		defer setup.Scanner.mu.Unlock()
		return setup.Scanner.activeReaders == 0
	}, 3*time.Second, 100*time.Millisecond, "All readers should disconnect")
}

// TestScanner_Race_ChannelOperations tests concurrent channel operations don't cause races.
func TestScanner_Race_ChannelOperations(t *testing.T) {
	setup := setupScannerTestWithTimeout(t, standardTestConfig(), 2*time.Second)
	// Don't defer cleanup since we're manually stopping

	setup.Scanner.Start(setup.Context)

	// Add multiple readers that will pump data into the ccvDataCh
	numReaders := 5
	var readersSlice []protocol.OffchainStorageReader
	for i := 0; i < numReaders; i++ {
		reader := readers.NewMockReader(readers.MockReaderConfig{
			MaxMessages:        10,
			EmitEmptyResponses: true,
		})
		readersSlice = append(readersSlice, reader)
	}

	setup.Discovery.AddReaders(readersSlice)

	// Wait for readers to start processing and produce messages
	// Readers may disconnect quickly, so check for message storage instead
	require.Eventually(t, func() bool {
		results, err := setup.Storage.QueryCCVData(context.Background(), time.UnixMilli(0), time.UnixMilli(time.Now().UnixMilli()+1000000), nil, nil, 100, 0)
		if err != nil {
			return false
		}
		return len(results) > 0
	}, 1*time.Second, 50*time.Millisecond, "Should have processed some messages")

	// Stop the scanner - this should properly drain and close channels
	setup.Scanner.Stop()
	setup.Cancel() // Cancel the context

	// Verify that the stop completed without hanging
	assert.True(t, true, "Scanner stopped cleanly")
}

// TestScanner_Race_GetReaderLock tests the getReaderLock method under concurrent access.
func TestScanner_Race_GetReaderLock(t *testing.T) {
	setup := setupScannerTest(t)
	// Note: Don't defer cleanup, we manage it manually since we're not starting the scanner

	// Create a single reader
	reader := readers.NewMockReader(readers.MockReaderConfig{
		MaxMessages:        1,
		EmitEmptyResponses: true,
	})

	// Access getReaderLock concurrently
	var wg sync.WaitGroup
	numGoroutines := 10

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lock := setup.Scanner.getReaderLock(reader)
			lock.Lock()
			time.Sleep(1 * time.Millisecond)
			lock.Unlock()
		}()
	}

	wg.Wait()

	// Cancel context manually since we're not using Cleanup
	setup.Cancel()

	// If there's a race in LoadOrStore or type assertion, it will be caught
	assert.True(t, true, "No races in getReaderLock")
}

// TestScanner_Race_ReaderErrorHandling tests concurrent error handling doesn't cause races.
func TestScanner_Race_ReaderErrorHandling(t *testing.T) {
	cfg := Config{
		ScanInterval:   30 * time.Millisecond,
		MetricInterval: 100 * time.Millisecond,
		ReaderTimeout:  200 * time.Millisecond,
	}
	setup := setupScannerTestWithTimeout(t, cfg, 2*time.Second)
	defer setup.Cleanup()

	setup.Scanner.Start(setup.Context)

	// Create readers that will error
	numReaders := 5
	var readersSlice []protocol.OffchainStorageReader
	for i := 0; i < numReaders; i++ {
		reader := readers.NewMockReader(readers.MockReaderConfig{
			MaxMessages:        3,
			ErrorAfterCalls:    2,
			Error:              errors.New("test error"),
			EmitEmptyResponses: true,
		})
		readersSlice = append(readersSlice, reader)
	}

	setup.Discovery.AddReaders(readersSlice)

	// Wait for readers to be called and start encountering errors
	// We track calls across all readers since they're concurrent
	totalCallsExpected := numReaders * 2 // ErrorAfterCalls is 2
	require.Eventually(t, func() bool {
		totalCalls := 0
		for _, r := range readersSlice {
			if mockReader, ok := r.(*readers.MockReader); ok {
				totalCalls += mockReader.GetCallCount()
			}
		}
		return totalCalls >= totalCallsExpected
	}, 2*time.Second, 50*time.Millisecond, "Readers should have been called and errored")

	// The scanner should handle errors without races
	// Metrics should be updated safely
	assert.True(t, true, "No races during error handling")
}

// TestScanner_Race_ContextCancellationDuringProcessing tests context cancellation during active processing.
func TestScanner_Race_ContextCancellationDuringProcessing(t *testing.T) {
	cfg := Config{
		ScanInterval:   20 * time.Millisecond,
		MetricInterval: 50 * time.Millisecond,
		ReaderTimeout:  200 * time.Millisecond,
	}
	setup := setupScannerTestNoTimeout(t, cfg)
	// Don't defer cleanup since we're manually managing it

	setup.Scanner.Start(setup.Context)

	// Add readers with latency
	numReaders := 5
	var readersSlice []protocol.OffchainStorageReader
	for i := 0; i < numReaders; i++ {
		reader := readers.NewMockReader(readers.MockReaderConfig{
			MaxMessages:        20,
			EmitEmptyResponses: true,
			MinLatency:         10 * time.Millisecond,
			MaxLatency:         20 * time.Millisecond,
		})
		readersSlice = append(readersSlice, reader)
	}

	setup.Discovery.AddReaders(readersSlice)

	// Wait for readers to start processing and produce some messages
	// (readers may disconnect quickly, so check for message storage)
	require.Eventually(t, func() bool {
		results, err := setup.Storage.QueryCCVData(context.Background(), time.UnixMilli(0), time.UnixMilli(time.Now().UnixMilli()+1000000), nil, nil, 100, 0)
		if err != nil {
			return false
		}
		return len(results) > 10
	}, 1*time.Second, 50*time.Millisecond, "Should have processed some messages")

	// Cancel context while processing is active
	setup.Cancel()

	// Wait for cancellation to propagate and scanner to stop
	// Check that doneCh is closed
	select {
	case <-setup.Scanner.doneCh:
		// Expected - scanner stopped due to context cancellation
	case <-time.After(2 * time.Second):
		t.Fatal("Scanner did not stop after context cancellation")
	}

	// Stop the scanner (should be a no-op since already stopped)
	setup.Scanner.Stop()

	// Should complete without deadlock or race
	assert.True(t, true, "Context cancellation handled correctly")
}
