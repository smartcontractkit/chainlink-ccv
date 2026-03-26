package storagewriter

import (
	"context"
	"errors"
	"maps"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/jobqueue"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"
)

// TestProcessorDB_ProcessBatchesSuccessfully tests successful batch processing.
func TestProcessorDB_ProcessBatchesSuccessfully(t *testing.T) {
	// Shared DB instance for all subtests - unique OwnerIDs prevent collisions
	db := testutil.NewTestDB(t)

	t.Run("processes batches from queue until context cancelled with storage always succeeding", func(t *testing.T) {
		ctx := t.Context()

		lggr := logger.Test(t)
		fakeStorage := NewFakeCCVNodeDataWriter()

		// Create result queue
		resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
			db,
			jobqueue.QueueConfig{
				Name:          verifier.StorageWriterJobsTableName,
				OwnerID:       "test-" + t.Name(),
				RetryDuration: time.Hour,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		processor, err := NewProcessor(
			lggr,
			"test-"+t.Name(),
			testutil.NoopLatencyTracker{},
			fakeStorage,
			resultQueue,
			verifier.CoordinatorConfig{
				StorageBatchSize:  10,
				StorageRetryDelay: 100 * time.Millisecond,
			},
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
		ctx := t.Context()

		lggr := logger.Test(t)
		fakeStorage := NewFakeCCVNodeDataWriter()

		resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
			db,
			jobqueue.QueueConfig{
				Name:          verifier.StorageWriterJobsTableName,
				OwnerID:       "test-" + t.Name(),
				RetryDuration: time.Hour,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		processor, err := NewProcessor(
			lggr,
			"test-"+t.Name(),
			testutil.NoopLatencyTracker{},
			fakeStorage,
			resultQueue,
			verifier.CoordinatorConfig{
				StorageBatchSize:  5,
				StorageRetryDelay: 100 * time.Millisecond,
			},
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

// TestProcessorDB_RetryFailedBatches tests retry logic.
func TestProcessorDB_RetryFailedBatches(t *testing.T) {
	// Shared DB instance for all subtests
	db := testutil.NewTestDB(t)

	t.Run("retries failed batches after delay", func(t *testing.T) {
		lggr := logger.Test(t)
		fakeStorage := NewFakeCCVNodeDataWriter()

		resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
			db,
			jobqueue.QueueConfig{
				Name:          verifier.StorageWriterJobsTableName,
				OwnerID:       "test-" + t.Name(),
				RetryDuration: time.Hour,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		processor, err := NewProcessor(
			lggr,
			"test-"+t.Name(),
			testutil.NoopLatencyTracker{},
			fakeStorage,
			resultQueue,
			verifier.CoordinatorConfig{
				StorageBatchSize:  10,
				StorageRetryDelay: 50 * time.Millisecond,
			},
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
		lggr := logger.Test(t)
		fakeStorage := NewFakeCCVNodeDataWriter()

		resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
			db,
			jobqueue.QueueConfig{
				Name:          verifier.StorageWriterJobsTableName,
				OwnerID:       "test-" + t.Name(),
				RetryDuration: time.Hour,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		processor, err := NewProcessor(
			lggr,
			"test-"+t.Name(),
			testutil.NoopLatencyTracker{},
			fakeStorage,
			resultQueue,
			verifier.CoordinatorConfig{
				StorageBatchSize:  10,
				StorageRetryDelay: 50 * time.Millisecond,
			},
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
		lggr := logger.Test(t)
		fakeStorage := NewFakeCCVNodeDataWriter()

		// Set very short retry deadline
		shortRetryDeadline := 200 * time.Millisecond

		resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
			db,
			jobqueue.QueueConfig{
				Name:          verifier.StorageWriterJobsTableName,
				OwnerID:       "test-" + t.Name(),
				RetryDuration: shortRetryDeadline,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		// Configure storage to always fail
		fakeStorage.SetError(errors.New("persistent storage error"))

		processor, err := NewProcessor(
			lggr,
			"test-"+t.Name(),
			testutil.NoopLatencyTracker{},
			fakeStorage,
			resultQueue,
			verifier.CoordinatorConfig{
				StorageBatchSize:  10,
				StorageRetryDelay: 10 * time.Millisecond, // Fast retry to exceed deadline quickly
			},
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
				SELECT COUNT(*) FROM ccv_storage_writer_jobs_archive 
				WHERE owner_id = $1 AND status = 'failed'
			`, "test-"+t.Name()).Scan(&count)
			return err == nil && count == 1
		}, tests.WaitTimeout(t), 50*time.Millisecond, "Expected job to be marked as failed after retry deadline")

		// Verify nothing was stored
		require.Equal(t, 0, fakeStorage.GetStoredCount(), "No data should be stored for expired job")
	})
}

// TestProcessorDB_Cleanup tests cleanup of archived results.
func TestProcessorDB_Cleanup(t *testing.T) {
	db := testutil.NewTestDB(t)

	t.Run("cleans up archived results older than retention period", func(t *testing.T) {
		lggr := logger.Test(t)
		fakeStorage := NewFakeCCVNodeDataWriter()

		resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
			db,
			jobqueue.QueueConfig{
				Name:          verifier.StorageWriterJobsTableName,
				OwnerID:       "test-" + t.Name(),
				RetryDuration: time.Hour,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		processor, err := NewProcessor(
			lggr,
			"test-"+t.Name(),
			testutil.NoopLatencyTracker{},
			fakeStorage,
			resultQueue,
			verifier.CoordinatorConfig{
				StorageBatchSize:  10,
				StorageRetryDelay: 100 * time.Millisecond,
			},
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

// TestProcessorDB_StaleJobRecovery tests recovery of jobs stuck in processing state.
func TestProcessorDB_StaleJobRecovery(t *testing.T) {
	db := testutil.NewTestDB(t)

	t.Run("reclaims jobs stuck in processing state beyond lock duration", func(t *testing.T) {
		lggr := logger.Test(t)
		fakeStorage := NewFakeCCVNodeDataWriter()

		shortLockDuration := 200 * time.Millisecond

		resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
			db,
			jobqueue.QueueConfig{
				Name:          verifier.StorageWriterJobsTableName,
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
		processor, err := NewProcessor(
			lggr,
			"test-"+t.Name(),
			testutil.NoopLatencyTracker{},
			fakeStorage,
			resultQueue,
			verifier.CoordinatorConfig{
				StorageBatchSize:  10,
				StorageRetryDelay: 100 * time.Millisecond,
			},
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

// TestProcessorDB_ContextCancellation tests graceful shutdown.
func TestProcessorDB_ContextCancellation(t *testing.T) {
	t.Run("stops processing when context is cancelled", func(t *testing.T) {
		lggr := logger.Test(t)
		fakeStorage := NewFakeCCVNodeDataWriter()

		resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
			testutil.NewTestDB(t),
			jobqueue.QueueConfig{
				Name:          verifier.StorageWriterJobsTableName,
				OwnerID:       "test-" + t.Name(),
				RetryDuration: time.Hour,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		processor, err := NewProcessor(
			lggr,
			"test-"+t.Name(),
			testutil.NoopLatencyTracker{},
			fakeStorage,
			resultQueue,
			verifier.CoordinatorConfig{
				StorageBatchSize:  10,
				StorageRetryDelay: 100 * time.Millisecond,
			},
		)
		require.NoError(t, err)

		require.NoError(t, processor.Start(t.Context()))

		// Processor should stop cleanly
		require.NoError(t, processor.Close())
	})
}

func TestConfigWithDefaults(t *testing.T) {
	tests := []struct {
		name               string
		config             verifier.CoordinatorConfig
		expectedBatchSize  int
		expectedBatchTime  time.Duration
		expectedRetryDelay time.Duration
	}{
		{
			name: "uses provided config values when valid",
			config: verifier.CoordinatorConfig{
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
			config: verifier.CoordinatorConfig{
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
			config: verifier.CoordinatorConfig{
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

			require.Equal(t, tt.expectedBatchSize, batchSize)
			require.Equal(t, tt.expectedBatchTime, batchTimeout)
			require.Equal(t, tt.expectedRetryDelay, retryDelay)
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

func (f *FakeCCVNodeDataWriter) WriteCCVNodeData(_ context.Context, ccvDataList []protocol.VerifierNodeResult) ([]protocol.WriteResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	results := make([]protocol.WriteResult, len(ccvDataList))

	// Pre-populate results with input data
	for i, data := range ccvDataList {
		results[i] = protocol.WriteResult{
			Input:     data,
			Status:    protocol.WriteSuccess,
			Error:     nil,
			Retryable: false,
		}
	}

	if f.errorToReturn != nil {
		// Mark all as failed if there's an error (retryable by default for tests)
		for i := range results {
			results[i].Status = protocol.WriteFailure
			results[i].Error = f.errorToReturn
			results[i].Retryable = true
		}
		return results, f.errorToReturn
	}

	for _, data := range ccvDataList {
		f.stored[data.MessageID] = data
	}

	return results, nil
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
