package verifier

import (
	"context"
	"errors"
	"maps"
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
		ctx := t.Context()

		lggr := logger.Test(t)
		fakeStorage := NewFakeCCVNodeDataWriter()
		mockChainStatus := &noopChainStatusManager{}
		tracker := NewPendingWritingTracker(lggr)

		// Create result queue
		resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
			db,
			jobqueue.QueueConfig{
				Name:          StorageWriterJobsTableName,
				OwnerID:       "test-" + t.Name(),
				RetryDuration: time.Hour,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		processor, err := NewStorageWriterProcessor(
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
		t.Cleanup(func() {
			require.NoError(t, processor.Close())
		})

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
		ctx := t.Context()

		lggr := logger.Test(t)
		fakeStorage := NewFakeCCVNodeDataWriter()

		resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
			db,
			jobqueue.QueueConfig{
				Name:          StorageWriterJobsTableName,
				OwnerID:       "test-" + t.Name(),
				RetryDuration: time.Hour,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		processor, err := NewStorageWriterProcessor(
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
		t.Cleanup(func() {
			require.NoError(t, processor.Close())
		})

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

		lggr := logger.Test(t)
		fakeStorage := NewFakeCCVNodeDataWriter()

		resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
			db,
			jobqueue.QueueConfig{
				Name:          StorageWriterJobsTableName,
				OwnerID:       "test-" + t.Name(),
				RetryDuration: time.Hour,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		processor, err := NewStorageWriterProcessor(
			t.Context(),
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

		require.NoError(t, processor.Start(t.Context()))
		t.Cleanup(func() {
			require.NoError(t, processor.Close())
		})

		// Publish test results
		batch := []protocol.VerifierNodeResult{
			createTestVerifierNodeResult(1),
			createTestVerifierNodeResult(2),
		}
		require.NoError(t, resultQueue.Publish(t.Context(), batch...))

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

		lggr := logger.Test(t)
		fakeStorage := NewFakeCCVNodeDataWriter()

		resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
			db,
			jobqueue.QueueConfig{
				Name:          StorageWriterJobsTableName,
				OwnerID:       "test-" + t.Name(),
				RetryDuration: time.Hour,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		processor, err := NewStorageWriterProcessor(
			t.Context(),
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

		require.NoError(t, processor.Start(t.Context()))
		t.Cleanup(func() {
			require.NoError(t, processor.Close())
		})

		// Publish failing batch
		failingBatch := createTestVerifierNodeResult(1)
		require.NoError(t, resultQueue.Publish(t.Context(), failingBatch))

		// Wait for initial failure
		time.Sleep(100 * time.Millisecond)

		// Clear error for new batch
		fakeStorage.ClearError()

		// Publish success batch
		successBatch := createTestVerifierNodeResult(2)
		require.NoError(t, resultQueue.Publish(t.Context(), successBatch))

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

	t.Run("marks job as failed when retry deadline expires", func(t *testing.T) {
		t.Parallel()

		lggr := logger.Test(t)
		fakeStorage := NewFakeCCVNodeDataWriter()

		// Set very short retry deadline
		shortRetryDeadline := 200 * time.Millisecond

		resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
			db,
			jobqueue.QueueConfig{
				Name:          StorageWriterJobsTableName,
				OwnerID:       "test-" + t.Name(),
				RetryDuration: shortRetryDeadline,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		// Configure storage to always fail
		fakeStorage.SetError(errors.New("persistent storage error"))

		processor, err := NewStorageWriterProcessor(
			t.Context(),
			lggr,
			"test-"+t.Name(),
			NoopLatencyTracker{},
			fakeStorage,
			resultQueue,
			CoordinatorConfig{
				StorageBatchSize:  10,
				StorageRetryDelay: 10 * time.Millisecond, // Fast retry to exceed deadline quickly
			},
			NewPendingWritingTracker(lggr),
			&noopChainStatusManager{},
		)
		require.NoError(t, err)

		require.NoError(t, processor.Start(t.Context()))
		t.Cleanup(func() {
			require.NoError(t, processor.Close())
		})

		// Publish test result
		result := createTestVerifierNodeResult(1)
		require.NoError(t, resultQueue.Publish(t.Context(), result))

		// Wait for retry deadline to expire and job to be marked as failed
		require.Eventually(t, func() bool {
			var count int
			err := db.QueryRow(`
				SELECT COUNT(*) FROM ccv_storage_writer_jobs 
				WHERE owner_id = $1 AND status = 'failed'
			`, "test-"+t.Name()).Scan(&count)
			return err == nil && count == 1
		}, tests.WaitTimeout(t), 50*time.Millisecond, "Expected job to be marked as failed after retry deadline")

		// Verify nothing was stored
		require.Equal(t, 0, fakeStorage.GetStoredCount(), "No data should be stored for expired job")
	})
}

// TestStorageWriterProcessorDB_Cleanup tests cleanup of archived results.
func TestStorageWriterProcessorDB_Cleanup(t *testing.T) {
	t.Parallel()

	db := testutil.NewTestDB(t)

	t.Run("cleans up archived results older than retention period", func(t *testing.T) {
		t.Parallel()

		lggr := logger.Test(t)
		fakeStorage := NewFakeCCVNodeDataWriter()

		resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
			db,
			jobqueue.QueueConfig{
				Name:          StorageWriterJobsTableName,
				OwnerID:       "test-" + t.Name(),
				RetryDuration: time.Hour,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		processor, err := NewStorageWriterProcessor(
			t.Context(),
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

		require.NoError(t, processor.Start(t.Context()))
		t.Cleanup(func() {
			require.NoError(t, processor.Close())
		})

		// Publish and process some results
		results := []protocol.VerifierNodeResult{
			createTestVerifierNodeResult(1),
			createTestVerifierNodeResult(2),
			createTestVerifierNodeResult(3),
		}
		require.NoError(t, resultQueue.Publish(t.Context(), results...))

		// Wait for results to be stored and archived
		require.Eventually(t, func() bool {
			return fakeStorage.GetStoredCount() == 3
		}, tests.WaitTimeout(t), 100*time.Millisecond, "Expected 3 results stored")

		// Wait for archive
		require.Eventually(t, func() bool {
			var count int
			err := db.QueryRow(`
				SELECT COUNT(*) FROM ccv_storage_writer_jobs_archive 
				WHERE owner_id = $1
			`, "test-"+t.Name()).Scan(&count)
			return err == nil && count == 3
		}, tests.WaitTimeout(t), 100*time.Millisecond, "Expected 3 results in archive")

		// Manually update completed_at to simulate old archived results
		_, err = db.Exec(`
			UPDATE ccv_storage_writer_jobs_archive 
			SET completed_at = NOW() - INTERVAL '35 days'
			WHERE owner_id = $1
		`, "test-"+t.Name())
		require.NoError(t, err)

		// Run cleanup with 30 day retention
		deleted, err := resultQueue.Cleanup(t.Context(), 30*24*time.Hour)
		require.NoError(t, err)
		require.Equal(t, 3, deleted, "Expected 3 old results to be deleted")

		// Verify archive is empty
		var count int
		err = db.QueryRow(`
			SELECT COUNT(*) FROM ccv_storage_writer_jobs_archive 
			WHERE owner_id = $1
		`, "test-"+t.Name()).Scan(&count)
		require.NoError(t, err)
		require.Equal(t, 0, count, "Archive should be empty after cleanup")
	})
}

// TestStorageWriterProcessorDB_StaleJobRecovery tests recovery of jobs stuck in processing state.
func TestStorageWriterProcessorDB_StaleJobRecovery(t *testing.T) {
	t.Parallel()

	db := testutil.NewTestDB(t)

	t.Run("reclaims jobs stuck in processing state beyond lock duration", func(t *testing.T) {
		t.Parallel()

		lggr := logger.Test(t)
		fakeStorage := NewFakeCCVNodeDataWriter()

		shortLockDuration := 200 * time.Millisecond

		resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
			db,
			jobqueue.QueueConfig{
				Name:          StorageWriterJobsTableName,
				OwnerID:       "test-" + t.Name(),
				RetryDuration: time.Hour,
				LockDuration:  shortLockDuration,
			},
			lggr,
		)
		require.NoError(t, err)

		// Publish result first
		result := createTestVerifierNodeResult(1)
		require.NoError(t, resultQueue.Publish(t.Context(), result))

		// Manually update job to processing state to simulate crashed processor
		_, err = db.Exec(`
			UPDATE ccv_storage_writer_jobs 
			SET status = 'processing', 
			    started_at = NOW() - INTERVAL '5 minutes',
			    attempt_count = 1
			WHERE owner_id = $1
		`, "test-"+t.Name())
		require.NoError(t, err)

		// Verify job is in processing state
		var status string
		err = db.QueryRow(`
			SELECT status FROM ccv_storage_writer_jobs 
			WHERE owner_id = $1
		`, "test-"+t.Name()).Scan(&status)
		require.NoError(t, err)
		require.Equal(t, "processing", status)

		// Now start processor - it should reclaim the stale job
		processor, err := NewStorageWriterProcessor(
			t.Context(),
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

		require.NoError(t, processor.Start(t.Context()))
		t.Cleanup(func() {
			require.NoError(t, processor.Close())
		})

		// Wait for job to be reclaimed and processed
		require.Eventually(t, func() bool {
			return fakeStorage.GetStoredCount() == 1
		}, tests.WaitTimeout(t), 100*time.Millisecond, "Expected stale job to be reclaimed and stored")

		// Verify result was stored
		stored := fakeStorage.GetStored()
		_, exists := stored[result.MessageID]
		require.True(t, exists, "Result should be stored after reclamation")
	})
}

// TestStorageWriterProcessorDB_CheckpointManagement tests checkpoint functionality.
func TestStorageWriterProcessorDB_CheckpointManagement(t *testing.T) {
	t.Parallel()

	// Shared DB instance for all subtests
	db := testutil.NewTestDB(t)

	t.Run("writes checkpoint after successful storage write", func(t *testing.T) {
		t.Parallel()

		lggr := logger.Test(t)
		fakeStorage := NewFakeCCVNodeDataWriter()
		mockChainStatus := mocks.NewMockChainStatusManager(t)
		tracker := NewPendingWritingTracker(lggr)

		chain1 := protocol.ChainSelector(1)
		msg1 := createTrackedMessage(chain1, 100, 100, tracker)

		resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
			db,
			jobqueue.QueueConfig{
				Name:          StorageWriterJobsTableName,
				OwnerID:       "test-" + t.Name(),
				RetryDuration: time.Hour,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		processor, err := NewStorageWriterProcessor(
			t.Context(),
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

		require.NoError(t, processor.Start(t.Context()))
		t.Cleanup(func() {
			require.NoError(t, processor.Close())
		})

		require.NoError(t, resultQueue.Publish(t.Context(), msg1))

		require.Eventually(t, func() bool {
			mu.Lock()
			count := callCount
			mu.Unlock()
			return count == 1 && mockChainStatus.AssertExpectations(t)
		}, tests.WaitTimeout(t), 50*time.Millisecond)
	})

	t.Run("checkpoint advances monotonically", func(t *testing.T) {
		t.Parallel()

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
				Name:          StorageWriterJobsTableName,
				OwnerID:       "test-" + t.Name(),
				RetryDuration: time.Hour,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		processor, err := NewStorageWriterProcessor(
			t.Context(),
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

		require.NoError(t, processor.Start(t.Context()))
		t.Cleanup(func() {
			require.NoError(t, processor.Close())
		})

		// Publish messages one by one with delays to ensure separate batch processing
		require.NoError(t, resultQueue.Publish(t.Context(), msg1))
		// Wait for msg1 to be processed and checkpoint written
		require.Eventually(t, func() bool {
			return fakeStorage.GetStoredCount() >= 1
		}, tests.WaitTimeout(t), 50*time.Millisecond)

		require.NoError(t, resultQueue.Publish(t.Context(), msg2))
		// Wait for msg2 to be processed and second checkpoint written
		require.Eventually(t, func() bool {
			return fakeStorage.GetStoredCount() >= 2
		}, tests.WaitTimeout(t), 50*time.Millisecond)

		require.NoError(t, resultQueue.Publish(t.Context(), msg3))
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
				Name:          StorageWriterJobsTableName,
				OwnerID:       "test-" + t.Name(),
				RetryDuration: time.Hour,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		processor, err := NewStorageWriterProcessor(
			t.Context(),
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

		require.NoError(t, processor.Start(t.Context()))
		t.Cleanup(func() {
			require.NoError(t, processor.Close())
		})

		require.NoError(t, resultQueue.Publish(t.Context(), msg1, msg2))

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

		lggr := logger.Test(t)
		fakeStorage := NewFakeCCVNodeDataWriter()

		resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
			testutil.NewTestDB(t),
			jobqueue.QueueConfig{
				Name:          StorageWriterJobsTableName,
				OwnerID:       "test-" + t.Name(),
				RetryDuration: time.Hour,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		processor, err := NewStorageWriterProcessor(
			t.Context(),
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

		require.NoError(t, processor.Start(t.Context()))

		// Processor should stop cleanly
		require.NoError(t, processor.Close())
	})
}

// noopChainStatusManager is a no-op implementation for testing.
type noopChainStatusManager struct{}

func (n *noopChainStatusManager) GetChainStatus(ctx context.Context, chain protocol.ChainSelector) (protocol.ChainStatusInfo, error) {
	return protocol.ChainStatusInfo{}, nil
}

func (n *noopChainStatusManager) SetChainStatus(ctx context.Context, statuses []protocol.ChainStatusInfo) error {
	return nil
}

func (n *noopChainStatusManager) ReadChainStatuses(ctx context.Context, chains []protocol.ChainSelector) (map[protocol.ChainSelector]*protocol.ChainStatusInfo, error) {
	return make(map[protocol.ChainSelector]*protocol.ChainStatusInfo), nil
}

func (n *noopChainStatusManager) WriteChainStatuses(ctx context.Context, statuses []protocol.ChainStatusInfo) error {
	return nil
}

func TestConfigWithDefaults(t *testing.T) {
	tests := []struct {
		name               string
		config             CoordinatorConfig
		expectedBatchSize  int
		expectedBatchTime  time.Duration
		expectedRetryDelay time.Duration
	}{
		{
			name: "uses provided config values when valid",
			config: CoordinatorConfig{
				StorageBatchSize:    100,
				StorageBatchTimeout: 5 * time.Second,
				StorageRetryDelay:   3 * time.Second,
			},
			expectedBatchSize:  100,
			expectedBatchTime:  5 * time.Second,
			expectedRetryDelay: 3 * time.Second,
		},
		{
			name: "applies defaults for invalid values",
			config: CoordinatorConfig{
				StorageBatchSize:    0,
				StorageBatchTimeout: 0,
				StorageRetryDelay:   0,
			},
			expectedBatchSize:  50,
			expectedBatchTime:  1 * time.Second,
			expectedRetryDelay: 2 * time.Second,
		},
		{
			name: "applies defaults for negative values",
			config: CoordinatorConfig{
				StorageBatchSize:    -10,
				StorageBatchTimeout: -5 * time.Second,
				StorageRetryDelay:   -3 * time.Second,
			},
			expectedBatchSize:  50,
			expectedBatchTime:  1 * time.Second,
			expectedRetryDelay: 2 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lggr := logger.Test(t)
			batchSize, batchTimeout, retryDelay := configWithDefaults(lggr, tt.config)

			assert.Equal(t, tt.expectedBatchSize, batchSize)
			assert.Equal(t, tt.expectedBatchTime, batchTimeout)
			assert.Equal(t, tt.expectedRetryDelay, retryDelay)
		})
	}
}

// FakeCCVNodeDataWriter is a fake implementation that stores data in memory for testing.
type FakeCCVNodeDataWriter struct {
	mu            sync.RWMutex
	stored        map[protocol.Bytes32]protocol.VerifierNodeResult
	errorToReturn error
}

func NewFakeCCVNodeDataWriter() *FakeCCVNodeDataWriter {
	return &FakeCCVNodeDataWriter{
		stored: make(map[protocol.Bytes32]protocol.VerifierNodeResult),
	}
}

func (f *FakeCCVNodeDataWriter) WriteCCVNodeData(_ context.Context, ccvDataList []protocol.VerifierNodeResult) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.errorToReturn != nil {
		return f.errorToReturn
	}

	for _, data := range ccvDataList {
		f.stored[data.MessageID] = data
	}

	return nil
}

func (f *FakeCCVNodeDataWriter) SetError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errorToReturn = err
}

func (f *FakeCCVNodeDataWriter) ClearError() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errorToReturn = nil
}

func (f *FakeCCVNodeDataWriter) GetStored() map[protocol.Bytes32]protocol.VerifierNodeResult {
	f.mu.RLock()
	defer f.mu.RUnlock()

	result := make(map[protocol.Bytes32]protocol.VerifierNodeResult, len(f.stored))
	maps.Copy(result, f.stored)
	return result
}

func (f *FakeCCVNodeDataWriter) GetStoredCount() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.stored)
}

func createTestVerifierNodeResult(sequenceNumber uint64) protocol.VerifierNodeResult {
	msg := protocol.Message{
		SequenceNumber: protocol.SequenceNumber(sequenceNumber),
	}
	return protocol.VerifierNodeResult{
		MessageID:       msg.MustMessageID(),
		Message:         msg,
		CCVVersion:      []byte{1, 2, 3},
		CCVAddresses:    []protocol.UnknownAddress{},
		ExecutorAddress: protocol.UnknownAddress{},
		Signature:       []byte{4, 5, 6},
	}
}

// ----------------------
// Checkpoint Test Helpers
// ----------------------

// createTrackedMessage creates a message and tracks it properly
// Returns the VerifierNodeResult with correct MessageID that matches tracker entry.
func createTrackedMessage(chain protocol.ChainSelector, seqNum, finalizedBlock uint64, tracker *PendingWritingTracker) protocol.VerifierNodeResult {
	msg := protocol.Message{
		SourceChainSelector: chain,
		SequenceNumber:      protocol.SequenceNumber(seqNum),
	}
	msgID := msg.MustMessageID()

	// Track with actual MessageID string - this will match what SWP calls Remove() with
	tracker.Add(chain, msgID.String(), finalizedBlock)

	return protocol.VerifierNodeResult{
		MessageID:       msgID,
		Message:         msg,
		CCVVersion:      []byte{1},
		CCVAddresses:    []protocol.UnknownAddress{},
		ExecutorAddress: protocol.UnknownAddress{},
		Signature:       []byte{},
	}
}
