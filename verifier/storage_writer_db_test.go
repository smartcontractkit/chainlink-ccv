package verifier

import (
	"context"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/jobqueue"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"
)

// TestStorageWriterProcessorDB_ProcessBatchesSuccessfully tests successful batch processing.
func TestStorageWriterProcessorDB_ProcessBatchesSuccessfully(t *testing.T) {
	t.Parallel()

	// Shared DB instance for all subtests - unique OwnerIDs prevent collisions
	db := testutil.NewTestDB(t)

	t.Run("processes batches from queue until context cancelled with storage always succeeding", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(t.Context(), tests.WaitTimeout(t))

		lggr := logger.Test(t)
		fakeStorage := NewFakeCCVNodeDataWriter()
		mockChainStatus := &noopChainStatusManager{}
		tracker := NewPendingWritingTracker(lggr)

		// Create result queue
		resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
			db,
			jobqueue.QueueConfig{
				Name:          "verification_results",
				OwnerID:       "test-" + t.Name(),
				RetryDuration: time.Hour,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		processor, err := NewStorageWriterProcessorDB(
			ctx,
			lggr,
			"test-"+t.Name(),
			NoopLatencyTracker{},
			fakeStorage,
			resultQueue,
			CoordinatorConfig{
				StorageBatchSize:  10,
				StorageRetryDelay: 100 * time.Millisecond,
			},
			tracker,
			mockChainStatus,
		)
		require.NoError(t, err)

		// Start processor
		require.NoError(t, processor.Start(ctx))
		defer func() {
			cancel()
			require.NoError(t, processor.Close())
		}()

		// Publish test results
		batch1 := []protocol.VerifierNodeResult{
			createTestVerifierNodeResult(1),
			createTestVerifierNodeResult(2),
		}
		batch2 := []protocol.VerifierNodeResult{
			createTestVerifierNodeResult(3),
			createTestVerifierNodeResult(4),
			createTestVerifierNodeResult(5),
		}

		require.NoError(t, resultQueue.Publish(ctx, batch1...))
		require.NoError(t, resultQueue.Publish(ctx, batch2...))

		// Wait for processing
		require.Eventually(t, func() bool {
			return fakeStorage.GetStoredCount() == 5
		}, tests.WaitTimeout(t), 50*time.Millisecond)

		// Verify all items were stored
		stored := fakeStorage.GetStored()
		allBatches := append(batch1, batch2...)
		for _, item := range allBatches {
			storedItem, exists := stored[item.MessageID]
			require.True(t, exists, "item with MessageID %s should be stored", item.MessageID)
			require.Equal(t, item.Message.SequenceNumber, storedItem.Message.SequenceNumber)
		}
	})

	t.Run("processes multiple batches concurrently", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(t.Context(), tests.WaitTimeout(t))

		lggr := logger.Test(t)
		fakeStorage := NewFakeCCVNodeDataWriter()

		resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
			db,
			jobqueue.QueueConfig{
				Name:          "verification_results",
				OwnerID:       "test-" + t.Name(),
				RetryDuration: time.Hour,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		processor, err := NewStorageWriterProcessorDB(
			ctx,
			lggr,
			"test-"+t.Name(),
			NoopLatencyTracker{},
			fakeStorage,
			resultQueue,
			CoordinatorConfig{
				StorageBatchSize:  5,
				StorageRetryDelay: 100 * time.Millisecond,
			},
			NewPendingWritingTracker(lggr),
			&noopChainStatusManager{},
		)
		require.NoError(t, err)

		require.NoError(t, processor.Start(ctx))
		defer func() {
			cancel()
			require.NoError(t, processor.Close())
		}()

		// Publish many results concurrently
		const numJobs = 50
		var wg sync.WaitGroup
		for i := range numJobs {
			wg.Add(1)
			go func(seq uint64) {
				defer wg.Done()
				result := createTestVerifierNodeResult(seq)
				require.NoError(t, resultQueue.Publish(ctx, result))
			}(uint64(i))
		}
		wg.Wait()

		// Wait for all to be processed
		require.Eventually(t, func() bool {
			return fakeStorage.GetStoredCount() == numJobs
		}, tests.WaitTimeout(t), 100*time.Millisecond)
	})
}

// TestStorageWriterProcessorDB_RetryFailedBatches tests retry logic.
func TestStorageWriterProcessorDB_RetryFailedBatches(t *testing.T) {
	t.Parallel()

	// Shared DB instance for all subtests
	db := testutil.NewTestDB(t)

	t.Run("retries failed batches after delay", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(t.Context(), tests.WaitTimeout(t))

		lggr := logger.Test(t)
		fakeStorage := NewFakeCCVNodeDataWriter()

		resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
			db,
			jobqueue.QueueConfig{
				Name:          "verification_results",
				OwnerID:       "test-" + t.Name(),
				RetryDuration: time.Hour,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		processor, err := NewStorageWriterProcessorDB(
			ctx,
			lggr,
			"test-"+t.Name(),
			NoopLatencyTracker{},
			fakeStorage,
			resultQueue,
			CoordinatorConfig{
				StorageBatchSize:  10,
				StorageRetryDelay: 50 * time.Millisecond,
			},
			NewPendingWritingTracker(lggr),
			&noopChainStatusManager{},
		)
		require.NoError(t, err)

		// Configure storage to fail initially
		fakeStorage.SetError(errors.New("storage error"))

		require.NoError(t, processor.Start(ctx))
		defer func() {
			cancel()
			require.NoError(t, processor.Close())
		}()

		// Publish test results
		batch := []protocol.VerifierNodeResult{
			createTestVerifierNodeResult(1),
			createTestVerifierNodeResult(2),
		}
		require.NoError(t, resultQueue.Publish(ctx, batch...))

		// Wait for initial failure
		time.Sleep(100 * time.Millisecond)

		// Clear error so retry succeeds
		fakeStorage.ClearError()

		// Wait for retry to process
		require.Eventually(t, func() bool {
			return fakeStorage.GetStoredCount() == 2
		}, tests.WaitTimeout(t), 50*time.Millisecond)

		// Verify data was stored after retry
		stored := fakeStorage.GetStored()
		for _, item := range batch {
			storedItem, exists := stored[item.MessageID]
			require.True(t, exists, "item should be stored after retry")
			require.Equal(t, item.Message.SequenceNumber, storedItem.Message.SequenceNumber)
		}
	})

	t.Run("continues processing new batches when retry fails", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(t.Context(), tests.WaitTimeout(t))

		lggr := logger.Test(t)
		fakeStorage := NewFakeCCVNodeDataWriter()

		resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
			db,
			jobqueue.QueueConfig{
				Name:          "verification_results",
				OwnerID:       "test-" + t.Name(),
				RetryDuration: time.Hour,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		processor, err := NewStorageWriterProcessorDB(
			ctx,
			lggr,
			"test-"+t.Name(),
			NoopLatencyTracker{},
			fakeStorage,
			resultQueue,
			CoordinatorConfig{
				StorageBatchSize:  10,
				StorageRetryDelay: 50 * time.Millisecond,
			},
			NewPendingWritingTracker(lggr),
			&noopChainStatusManager{},
		)
		require.NoError(t, err)

		// Configure storage to always fail
		fakeStorage.SetError(errors.New("persistent error"))

		require.NoError(t, processor.Start(ctx))
		defer func() {
			cancel()
			require.NoError(t, processor.Close())
		}()

		// Publish failing batch
		failingBatch := createTestVerifierNodeResult(1)
		require.NoError(t, resultQueue.Publish(ctx, failingBatch))

		// Wait for initial failure
		time.Sleep(100 * time.Millisecond)

		// Clear error for new batch
		fakeStorage.ClearError()

		// Publish success batch
		successBatch := createTestVerifierNodeResult(2)
		require.NoError(t, resultQueue.Publish(ctx, successBatch))

		// Wait for success batch to be processed
		require.Eventually(t, func() bool {
			stored := fakeStorage.GetStored()
			_, exists := stored[successBatch.MessageID]
			return exists
		}, tests.WaitTimeout(t), 50*time.Millisecond)

		// Verify success batch was stored
		stored := fakeStorage.GetStored()
		successItem, exists := stored[successBatch.MessageID]
		require.True(t, exists, "success batch should be stored")
		require.Equal(t, successBatch.Message.SequenceNumber, successItem.Message.SequenceNumber)
	})
}

// TestStorageWriterProcessorDB_CheckpointManagement tests checkpoint functionality.
func TestStorageWriterProcessorDB_CheckpointManagement(t *testing.T) {
	t.Parallel()

	// Shared DB instance for all subtests
	db := testutil.NewTestDB(t)

	t.Run("writes checkpoint after successful storage write", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(t.Context(), tests.WaitTimeout(t))

		lggr := logger.Test(t)
		fakeStorage := NewFakeCCVNodeDataWriter()
		mockChainStatus := mocks.NewMockChainStatusManager(t)
		tracker := NewPendingWritingTracker(lggr)

		chain1 := protocol.ChainSelector(1)
		msg1 := createTrackedMessage(chain1, 100, 100, tracker)

		resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
			db,
			jobqueue.QueueConfig{
				Name:          "verification_results",
				OwnerID:       "test-" + t.Name(),
				RetryDuration: time.Hour,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		processor, err := NewStorageWriterProcessorDB(
			ctx,
			lggr,
			"test-"+t.Name(),
			NoopLatencyTracker{},
			fakeStorage,
			resultQueue,
			CoordinatorConfig{
				StorageBatchSize:  10,
				StorageRetryDelay: 100 * time.Millisecond,
			},
			tracker,
			mockChainStatus,
		)
		require.NoError(t, err)

		var mu sync.Mutex
		callCount := 0
		// Expect checkpoint at 99 (100 - 1)
		mockChainStatus.EXPECT().
			WriteChainStatuses(mock.Anything, mock.MatchedBy(func(statuses []protocol.ChainStatusInfo) bool {
				mu.Lock()
				callCount++
				mu.Unlock()
				return len(statuses) == 1 &&
					statuses[0].ChainSelector == chain1 &&
					statuses[0].FinalizedBlockHeight.Cmp(big.NewInt(99)) == 0
			})).
			Return(nil).
			Once()

		require.NoError(t, processor.Start(ctx))
		defer func() {
			cancel()
			require.NoError(t, processor.Close())
		}()

		require.NoError(t, resultQueue.Publish(ctx, msg1))

		require.Eventually(t, func() bool {
			mu.Lock()
			count := callCount
			mu.Unlock()
			return count == 1 && mockChainStatus.AssertExpectations(t)
		}, tests.WaitTimeout(t), 50*time.Millisecond)
	})

	t.Run("checkpoint advances monotonically", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(t.Context(), tests.WaitTimeout(t))

		lggr := logger.Test(t)
		fakeStorage := NewFakeCCVNodeDataWriter()
		mockChainStatus := mocks.NewMockChainStatusManager(t)
		tracker := NewPendingWritingTracker(lggr)

		chain1 := protocol.ChainSelector(1)
		msg1 := createTrackedMessage(chain1, 100, 100, tracker)
		msg2 := createTrackedMessage(chain1, 105, 105, tracker)
		msg3 := createTrackedMessage(chain1, 110, 110, tracker)

		resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
			db,
			jobqueue.QueueConfig{
				Name:          "verification_results",
				OwnerID:       "test-" + t.Name(),
				RetryDuration: time.Hour,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		processor, err := NewStorageWriterProcessorDB(
			ctx,
			lggr,
			"test-"+t.Name(),
			NoopLatencyTracker{},
			fakeStorage,
			resultQueue,
			CoordinatorConfig{
				StorageBatchSize:  10,
				StorageRetryDelay: 100 * time.Millisecond,
			},
			tracker,
			mockChainStatus,
		)
		require.NoError(t, err)

		var mu sync.Mutex
		callCount := 0
		// Expect checkpoints in order: 104, 109
		mockChainStatus.EXPECT().
			WriteChainStatuses(mock.Anything, mock.Anything).
			RunAndReturn(func(_ context.Context, statuses []protocol.ChainStatusInfo) error {
				mu.Lock()
				callCount++
				currentCount := callCount
				mu.Unlock()
				require.Len(t, statuses, 1)
				require.Equal(t, chain1, statuses[0].ChainSelector)

				expectedCheckpoints := map[int]int64{1: 104, 2: 109}
				require.Equal(t, expectedCheckpoints[currentCount], statuses[0].FinalizedBlockHeight.Int64())
				return nil
			}).
			Times(2)

		require.NoError(t, processor.Start(ctx))
		defer func() {
			cancel()
			require.NoError(t, processor.Close())
		}()

		// Publish messages one by one with delays to ensure separate batch processing
		require.NoError(t, resultQueue.Publish(ctx, msg1))
		// Wait for msg1 to be processed and checkpoint written
		require.Eventually(t, func() bool {
			return fakeStorage.GetStoredCount() >= 1
		}, tests.WaitTimeout(t), 50*time.Millisecond)

		require.NoError(t, resultQueue.Publish(ctx, msg2))
		// Wait for msg2 to be processed and second checkpoint written
		require.Eventually(t, func() bool {
			return fakeStorage.GetStoredCount() >= 2
		}, tests.WaitTimeout(t), 50*time.Millisecond)

		require.NoError(t, resultQueue.Publish(ctx, msg3))
		// Wait for msg3 to be processed
		require.Eventually(t, func() bool {
			return fakeStorage.GetStoredCount() >= 3
		}, tests.WaitTimeout(t), 50*time.Millisecond)

		// Now wait for both checkpoint calls
		require.Eventually(t, func() bool {
			mu.Lock()
			count := callCount
			mu.Unlock()
			return count == 2 && mockChainStatus.AssertExpectations(t)
		}, tests.WaitTimeout(t), 50*time.Millisecond)
	})

	t.Run("multiple chains handled independently", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(t.Context(), tests.WaitTimeout(t))

		lggr := logger.Test(t)
		fakeStorage := NewFakeCCVNodeDataWriter()
		mockChainStatus := mocks.NewMockChainStatusManager(t)
		tracker := NewPendingWritingTracker(lggr)

		chain1 := protocol.ChainSelector(1)
		chain2 := protocol.ChainSelector(2)
		msg1 := createTrackedMessage(chain1, 100, 100, tracker)
		msg2 := createTrackedMessage(chain2, 200, 200, tracker)

		resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
			db,
			jobqueue.QueueConfig{
				Name:          "verification_results",
				OwnerID:       "test-" + t.Name(),
				RetryDuration: time.Hour,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		processor, err := NewStorageWriterProcessorDB(
			ctx,
			lggr,
			"test-"+t.Name(),
			NoopLatencyTracker{},
			fakeStorage,
			resultQueue,
			CoordinatorConfig{
				StorageBatchSize:  10,
				StorageRetryDelay: 100 * time.Millisecond,
			},
			tracker,
			mockChainStatus,
		)
		require.NoError(t, err)

		var mu sync.Mutex
		chain1Written, chain2Written := false, false
		mockChainStatus.EXPECT().
			WriteChainStatuses(mock.Anything, mock.Anything).
			RunAndReturn(func(_ context.Context, statuses []protocol.ChainStatusInfo) error {
				mu.Lock()
				for _, status := range statuses {
					switch status.ChainSelector {
					case chain1:
						assert.Equal(t, int64(99), status.FinalizedBlockHeight.Int64())
						chain1Written = true
					case chain2:
						assert.Equal(t, int64(199), status.FinalizedBlockHeight.Int64())
						chain2Written = true
					}
				}
				mu.Unlock()
				return nil
			}).
			Maybe()

		require.NoError(t, processor.Start(ctx))
		defer func() {
			cancel()
			require.NoError(t, processor.Close())
		}()

		require.NoError(t, resultQueue.Publish(ctx, msg1, msg2))

		require.Eventually(t, func() bool {
			mu.Lock()
			c1 := chain1Written
			c2 := chain2Written
			mu.Unlock()
			return c1 && c2 && mockChainStatus.AssertExpectations(t)
		}, tests.WaitTimeout(t), 50*time.Millisecond)
	})
}

// TestStorageWriterProcessorDB_ContextCancellation tests graceful shutdown.
func TestStorageWriterProcessorDB_ContextCancellation(t *testing.T) {
	t.Parallel()

	t.Run("stops processing when context is cancelled", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())

		lggr := logger.Test(t)
		fakeStorage := NewFakeCCVNodeDataWriter()

		resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
			testutil.NewTestDB(t),
			jobqueue.QueueConfig{
				Name:          "verification_results",
				OwnerID:       "test-" + t.Name(),
				RetryDuration: time.Hour,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		processor, err := NewStorageWriterProcessorDB(
			ctx,
			lggr,
			"test-"+t.Name(),
			NoopLatencyTracker{},
			fakeStorage,
			resultQueue,
			CoordinatorConfig{
				StorageBatchSize:  10,
				StorageRetryDelay: 100 * time.Millisecond,
			},
			NewPendingWritingTracker(lggr),
			&noopChainStatusManager{},
		)
		require.NoError(t, err)

		require.NoError(t, processor.Start(ctx))

		// Cancel context immediately
		cancel()

		// Processor should stop cleanly
		require.NoError(t, processor.Close())
	})
}
