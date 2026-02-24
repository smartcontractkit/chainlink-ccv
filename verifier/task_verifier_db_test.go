package verifier_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/jobqueue"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"
)

// TestTaskVerifierProcessorDB_ProcessTasksSuccessfully tests successful task processing.
func TestTaskVerifierProcessorDB_ProcessTasksSuccessfully(t *testing.T) {
	t.Parallel()

	db := testutil.NewTestDB(t)

	t.Run("processes tasks from queue and publishes results", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(t.Context(), tests.WaitTimeout(t))

		lggr := logger.Nop()
		ownerID := "test-" + t.Name()

		taskQueue, err := jobqueue.NewPostgresJobQueue[verifier.VerificationTask](
			db,
			jobqueue.QueueConfig{
				Name:          verifier.TaskVerifierJobsTableName,
				OwnerID:       ownerID,
				RetryDuration: time.Hour,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
			db,
			jobqueue.QueueConfig{
				Name:          verifier.StorageWriterJobsTableName,
				OwnerID:       ownerID,
				RetryDuration: time.Hour,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		mockVerifier := &fakeVerifierDB{}
		processor, err := verifier.NewTaskVerifierProcessorDBWithPollInterval(
			lggr,
			ownerID,
			mockVerifier,
			monitoring.NewFakeVerifierMonitoring(),
			taskQueue,
			resultQueue,
			verifier.NewPendingWritingTracker(lggr),
			10,
			50*time.Millisecond,
		)
		require.NoError(t, err)

		require.NoError(t, processor.Start(ctx))
		defer func() {
			cancel()
			require.NoError(t, processor.Close())
		}()

		// Publish test tasks
		message1 := protocol.Message{SequenceNumber: 1, SourceChainSelector: 1337}
		messageID1 := message1.MustMessageID()
		task1 := verifier.VerificationTask{
			MessageID: messageID1.String(),
			Message:   message1,
		}

		message2 := protocol.Message{SequenceNumber: 2, SourceChainSelector: 1337}
		messageID2 := message2.MustMessageID()
		task2 := verifier.VerificationTask{
			MessageID: messageID2.String(),
			Message:   message2,
		}

		require.NoError(t, taskQueue.Publish(ctx, task1, task2))

		// Wait for tasks to be archived
		require.Eventually(t, func() bool {
			return countArchivedTasks(t, db, ownerID) == 2
		}, tests.WaitTimeout(t), 100*time.Millisecond, "Expected 2 tasks in archive")

		// Wait for results to be published
		require.Eventually(t, func() bool {
			return countVerificationResults(t, db, ownerID) == 2
		}, tests.WaitTimeout(t), 100*time.Millisecond, "Expected 2 results published")

		require.Equal(t, 2, mockVerifier.GetProcessedCount())
	})

	t.Run("processes multiple batches concurrently", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(t.Context(), tests.WaitTimeout(t))

		lggr := logger.Nop()
		ownerID := "test-" + t.Name()

		taskQueue, err := jobqueue.NewPostgresJobQueue[verifier.VerificationTask](
			db,
			jobqueue.QueueConfig{
				Name:          verifier.TaskVerifierJobsTableName,
				OwnerID:       ownerID,
				RetryDuration: time.Hour,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
			db,
			jobqueue.QueueConfig{
				Name:          verifier.StorageWriterJobsTableName,
				OwnerID:       ownerID,
				RetryDuration: time.Hour,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		mockVerifier := &fakeVerifierDB{}
		processor, err := verifier.NewTaskVerifierProcessorDBWithPollInterval(
			lggr,
			ownerID,
			mockVerifier,
			monitoring.NewFakeVerifierMonitoring(),
			taskQueue,
			resultQueue,
			verifier.NewPendingWritingTracker(lggr),
			5,
			50*time.Millisecond,
		)
		require.NoError(t, err)

		require.NoError(t, processor.Start(ctx))
		defer func() {
			cancel()
			require.NoError(t, processor.Close())
		}()

		const numTasks = 20
		var wg sync.WaitGroup
		for i := range numTasks {
			wg.Add(1)
			go func(seq uint64) {
				defer wg.Done()
				message := protocol.Message{SequenceNumber: protocol.SequenceNumber(seq), SourceChainSelector: 1337}
				messageID := message.MustMessageID()
				task := verifier.VerificationTask{
					MessageID: messageID.String(),
					Message:   message,
				}
				require.NoError(t, taskQueue.Publish(ctx, task))
			}(uint64(i))
		}
		wg.Wait()

		// Wait for all tasks to be archived
		require.Eventually(t, func() bool {
			return countArchivedTasks(t, db, ownerID) == numTasks
		}, tests.WaitTimeout(t), 100*time.Millisecond, "Expected all tasks in archive")

		// Wait for all results to be published
		require.Eventually(t, func() bool {
			return countVerificationResults(t, db, ownerID) == numTasks
		}, tests.WaitTimeout(t), 100*time.Millisecond, "Expected all results published")

		require.Equal(t, numTasks, mockVerifier.GetProcessedCount())
	})
}

// TestTaskVerifierProcessorDB_RetryFailedTasks tests retry logic.
func TestTaskVerifierProcessorDB_RetryFailedTasks(t *testing.T) {
	t.Parallel()

	db := testutil.NewTestDB(t)

	t.Run("retries failed tasks after delay", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(t.Context(), tests.WaitTimeout(t))

		lggr := logger.Nop()
		ownerID := "test-" + t.Name()

		taskQueue, err := jobqueue.NewPostgresJobQueue[verifier.VerificationTask](
			db,
			jobqueue.QueueConfig{
				Name:          verifier.TaskVerifierJobsTableName,
				OwnerID:       ownerID,
				RetryDuration: time.Hour,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
			db,
			jobqueue.QueueConfig{
				Name:          verifier.StorageWriterJobsTableName,
				OwnerID:       ownerID,
				RetryDuration: time.Hour,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		message := protocol.Message{SequenceNumber: 1, SourceChainSelector: 1337}
		messageID := message.MustMessageID()
		task := verifier.VerificationTask{
			MessageID: messageID.String(),
			Message:   message,
		}

		// Configure verifier to fail twice then succeed
		fastRetry := 10 * time.Millisecond
		mockVerifier := &fakeVerifierDB{}
		mockVerifier.SetErrors(map[string]verifier.VerificationError{
			messageID.String(): {Task: task, Retryable: true, Delay: &fastRetry},
		})

		processor, err := verifier.NewTaskVerifierProcessorDBWithPollInterval(
			lggr,
			ownerID,
			mockVerifier,
			monitoring.NewFakeVerifierMonitoring(),
			taskQueue,
			resultQueue,
			verifier.NewPendingWritingTracker(lggr),
			10,
			50*time.Millisecond,
		)
		require.NoError(t, err)

		require.NoError(t, processor.Start(ctx))
		defer func() {
			cancel()
			require.NoError(t, processor.Close())
		}()

		require.NoError(t, taskQueue.Publish(ctx, task))

		// Wait a bit for retries to occur
		time.Sleep(200 * time.Millisecond)

		// Now clear the error so the next retry succeeds
		mockVerifier.SetErrors(nil)

		// Verify result was eventually published (after retries and then success)
		require.Eventually(t, func() bool {
			return countVerificationResults(t, db, ownerID) == 1
		}, tests.WaitTimeout(t), 100*time.Millisecond)

		// Verify it was processed multiple times (due to retries)
		require.Greater(t, mockVerifier.GetProcessedCount(), 1, "Task should have been retried")
	})

	t.Run("does not retry permanent failures", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(t.Context(), tests.WaitTimeout(t))

		lggr := logger.Nop()
		ownerID := "test-" + t.Name()

		taskQueue, err := jobqueue.NewPostgresJobQueue[verifier.VerificationTask](
			db,
			jobqueue.QueueConfig{
				Name:          verifier.TaskVerifierJobsTableName,
				OwnerID:       ownerID,
				RetryDuration: time.Hour,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
			db,
			jobqueue.QueueConfig{
				Name:          verifier.StorageWriterJobsTableName,
				OwnerID:       ownerID,
				RetryDuration: time.Hour,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		message := protocol.Message{SequenceNumber: 1, SourceChainSelector: 1337}
		messageID := message.MustMessageID()
		task := verifier.VerificationTask{
			MessageID: messageID.String(),
			Message:   message,
		}

		// Configure verifier to fail permanently
		mockVerifier := &fakeVerifierDB{}
		mockVerifier.SetErrors(map[string]verifier.VerificationError{
			messageID.String(): {
				Task:      task,
				Error:     errors.New("permanent error"),
				Retryable: false,
			},
		})

		processor, err := verifier.NewTaskVerifierProcessorDBWithPollInterval(
			lggr,
			ownerID,
			mockVerifier,
			monitoring.NewFakeVerifierMonitoring(),
			taskQueue,
			resultQueue,
			verifier.NewPendingWritingTracker(lggr),
			10,
			50*time.Millisecond,
		)
		require.NoError(t, err)

		require.NoError(t, processor.Start(ctx))
		defer func() {
			cancel()
			require.NoError(t, processor.Close())
		}()

		require.NoError(t, taskQueue.Publish(ctx, task))

		// Wait for processing - task should be attempted and fail
		require.Eventually(t, func() bool {
			return mockVerifier.GetProcessedCount() >= 1
		}, tests.WaitTimeout(t), 50*time.Millisecond, "Expected task to be attempted at least once")

		// Task should be marked as failed in database
		require.Eventually(t, func() bool {
			return countFailedTasks(t, db, ownerID) == 1
		}, tests.WaitTimeout(t), 100*time.Millisecond, "Expected 1 failed task in database")

		// No results should be published
		require.Eventually(t, func() bool {
			return countVerificationResults(t, db, ownerID) == 0
		}, tests.WaitTimeout(t), 100*time.Millisecond, "Expected no results for permanent failure")
	})
}

// TestTaskVerifierProcessorDB_Shutdown tests graceful shutdown.
func TestTaskVerifierProcessorDB_Shutdown(t *testing.T) {
	t.Parallel()

	db := testutil.NewTestDB(t)

	t.Run("stops processing after close", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(t.Context(), tests.WaitTimeout(t))

		lggr := logger.Nop()
		ownerID := "test-" + t.Name()

		taskQueue, err := jobqueue.NewPostgresJobQueue[verifier.VerificationTask](
			db,
			jobqueue.QueueConfig{
				Name:          verifier.TaskVerifierJobsTableName,
				OwnerID:       ownerID,
				RetryDuration: time.Hour,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
			db,
			jobqueue.QueueConfig{
				Name:          verifier.StorageWriterJobsTableName,
				OwnerID:       ownerID,
				RetryDuration: time.Hour,
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		mockVerifier := &fakeVerifierDB{}
		processor, err := verifier.NewTaskVerifierProcessorDBWithPollInterval(
			lggr,
			ownerID,
			mockVerifier,
			monitoring.NewFakeVerifierMonitoring(),
			taskQueue,
			resultQueue,
			verifier.NewPendingWritingTracker(lggr),
			10,
			50*time.Millisecond,
		)
		require.NoError(t, err)

		require.NoError(t, processor.Start(ctx))

		// Process some tasks
		message := protocol.Message{SequenceNumber: 1, SourceChainSelector: 1337}
		messageID := message.MustMessageID()
		task := verifier.VerificationTask{
			MessageID: messageID.String(),
			Message:   message,
		}
		require.NoError(t, taskQueue.Publish(ctx, task))

		time.Sleep(200 * time.Millisecond)
		initialCount := mockVerifier.GetProcessedCount()
		require.Greater(t, initialCount, 0)

		// Close processor
		cancel()
		require.NoError(t, processor.Close())

		// Publish more tasks
		message2 := protocol.Message{SequenceNumber: 2, SourceChainSelector: 1337}
		messageID2 := message2.MustMessageID()
		task2 := verifier.VerificationTask{
			MessageID: messageID2.String(),
			Message:   message2,
		}
		require.NoError(t, taskQueue.Publish(t.Context(), task2))

		// Wait and verify no new processing
		time.Sleep(200 * time.Millisecond)
		finalCount := mockVerifier.GetProcessedCount()
		require.Equal(t, initialCount, finalCount, "No new tasks should be processed after close")
	})
}

func countArchivedTasks(t *testing.T, db *sqlx.DB, ownerID string) int {
	t.Helper()
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) FROM ccv_task_verifier_jobs_archive 
		WHERE owner_id = $1
	`, ownerID).Scan(&count)
	require.NoError(t, err)
	t.Logf("Archived tasks count: %d (ownerID: %s)", count, ownerID)
	return count
}

func countVerificationResults(t *testing.T, db *sqlx.DB, ownerID string) int {
	t.Helper()
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) FROM ccv_storage_writer_jobs 
		WHERE owner_id = $1
	`, ownerID).Scan(&count)
	require.NoError(t, err)
	t.Logf("Verification results count: %d (ownerID: %s)", count, ownerID)
	return count
}

func countFailedTasks(t *testing.T, db *sqlx.DB, ownerID string) int {
	t.Helper()
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) FROM ccv_task_verifier_jobs 
		WHERE owner_id = $1 AND status = 'failed'
	`, ownerID).Scan(&count)
	require.NoError(t, err)
	t.Logf("Failed tasks count: %d (ownerID: %s)", count, ownerID)
	return count
}

// fakeVerifierDB is a test helper that simulates verification with configurable behavior.
type fakeVerifierDB struct {
	mu             sync.RWMutex
	errors         map[string]verifier.VerificationError // If set, returns errors for these message IDs
	totalProcessed int
}

func (f *fakeVerifierDB) SetErrors(errors map[string]verifier.VerificationError) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errors = errors
}

func (f *fakeVerifierDB) GetProcessedCount() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.totalProcessed
}

func (f *fakeVerifierDB) VerifyMessages(_ context.Context, tasks []verifier.VerificationTask) []verifier.VerificationResult {
	f.mu.Lock()
	defer f.mu.Unlock()

	results := make([]verifier.VerificationResult, 0, len(tasks))

	for _, task := range tasks {
		f.totalProcessed++

		// Check if there's a configured error for this message
		if verificationError, hasError := f.errors[task.MessageID]; hasError {
			verificationError.Task = task
			results = append(results, verifier.VerificationResult{
				Error: &verificationError,
			})
		} else {
			// Success case - return valid result
			messageID, err := protocol.NewBytes32FromString(task.MessageID)
			if err != nil {
				panic(err)
			}
			results = append(results, verifier.VerificationResult{
				Result: &protocol.VerifierNodeResult{
					MessageID: messageID,
					Message:   task.Message,
				},
			})
		}
	}

	return results
}
