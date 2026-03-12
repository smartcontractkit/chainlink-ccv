package verifier

import (
	"context"
	"errors"
	"maps"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/jobqueue"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"
)

func TestStorageWriterProcessorDB_PartialBatchFailures(t *testing.T) {
	t.Parallel()

	db := testutil.NewTestDB(t)

	t.Run("retries only failed requests in a partially failed batch", func(t *testing.T) {
		t.Parallel()

		lggr := logger.Test(t)
		selectiveStorage := NewSelectiveFailureStorage()

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
			lggr,
			"test-"+t.Name(),
			NoopLatencyTracker{},
			selectiveStorage,
			resultQueue,
			CoordinatorConfig{
				StorageBatchSize:  10,
				StorageRetryDelay: 50 * time.Millisecond,
			},
			NewPendingWritingTracker(lggr),
			&noopChainStatusManager{},
		)
		require.NoError(t, err)

		require.NoError(t, processor.Start(t.Context()))
		t.Cleanup(func() {
			require.NoError(t, processor.Close())
		})

		// Create a batch where some will fail
		batch := []protocol.VerifierNodeResult{
			createTestVerifierNodeResult(1), // Will succeed
			createTestVerifierNodeResult(2), // Will fail
			createTestVerifierNodeResult(3), // Will succeed
			createTestVerifierNodeResult(4), // Will fail
			createTestVerifierNodeResult(5), // Will succeed
		}

		// Configure storage to fail on even sequence numbers
		selectiveStorage.SetFailureCondition(func(data protocol.VerifierNodeResult) bool {
			return uint64(data.Message.SequenceNumber)%2 == 0
		})

		require.NoError(t, resultQueue.Publish(t.Context(), batch...))

		// Wait for successful ones to be stored immediately
		require.Eventually(t, func() bool {
			stored := selectiveStorage.GetStored()
			return len(stored) == 3 // Seqs 1, 3, 5
		}, tests.WaitTimeout(t), 50*time.Millisecond)

		// Verify only successful ones are stored
		stored := selectiveStorage.GetStored()
		require.Contains(t, stored, batch[0].MessageID, "Seq 1 should be stored")
		require.NotContains(t, stored, batch[1].MessageID, "Seq 2 should not be stored yet")
		require.Contains(t, stored, batch[2].MessageID, "Seq 3 should be stored")
		require.NotContains(t, stored, batch[3].MessageID, "Seq 4 should not be stored yet")
		require.Contains(t, stored, batch[4].MessageID, "Seq 5 should be stored")

		// Now clear the failure condition so retries succeed
		selectiveStorage.ClearFailureCondition()

		// Wait for failed ones to be retried and stored
		require.Eventually(t, func() bool {
			stored := selectiveStorage.GetStored()
			return len(stored) == 5 // All 5
		}, tests.WaitTimeout(t), 50*time.Millisecond)

		// Verify all are now stored
		stored = selectiveStorage.GetStored()
		for _, item := range batch {
			require.Contains(t, stored, item.MessageID, "All items should be stored after retry")
		}
	})

	t.Run("handles non-retryable failures without retry", func(t *testing.T) {
		t.Parallel()

		lggr := logger.Test(t)
		nonRetryableStorage := NewNonRetryableFailureStorage()

		resultQueue, err := jobqueue.NewPostgresJobQueue[protocol.VerifierNodeResult](
			db,
			jobqueue.QueueConfig{
				Name:          StorageWriterJobsTableName,
				OwnerID:       "test-" + t.Name(),
				RetryDuration: 200 * time.Millisecond, // Short deadline
				LockDuration:  time.Minute,
			},
			lggr,
		)
		require.NoError(t, err)

		processor, err := NewStorageWriterProcessor(
			lggr,
			"test-"+t.Name(),
			NoopLatencyTracker{},
			nonRetryableStorage,
			resultQueue,
			CoordinatorConfig{
				StorageBatchSize:  10,
				StorageRetryDelay: 50 * time.Millisecond,
			},
			NewPendingWritingTracker(lggr),
			&noopChainStatusManager{},
		)
		require.NoError(t, err)

		require.NoError(t, processor.Start(t.Context()))
		t.Cleanup(func() {
			require.NoError(t, processor.Close())
		})

		// Create a batch where some will fail with non-retryable errors
		batch := []protocol.VerifierNodeResult{
			createTestVerifierNodeResult(1), // Will succeed
			createTestVerifierNodeResult(2), // Will fail non-retryable
			createTestVerifierNodeResult(3), // Will succeed
		}

		// Configure storage to fail on seq 2 with non-retryable error
		nonRetryableStorage.SetNonRetryableFailure(func(data protocol.VerifierNodeResult) bool {
			return uint64(data.Message.SequenceNumber) == 2
		})

		require.NoError(t, resultQueue.Publish(t.Context(), batch...))

		// Wait for successful ones to be stored
		require.Eventually(t, func() bool {
			stored := nonRetryableStorage.GetStored()
			return len(stored) == 2 // Seqs 1 and 3
		}, tests.WaitTimeout(t), 50*time.Millisecond)

		// Verify only successful ones are stored
		stored := nonRetryableStorage.GetStored()
		require.Contains(t, stored, batch[0].MessageID, "Seq 1 should be stored")
		require.NotContains(t, stored, batch[1].MessageID, "Seq 2 should not be stored (non-retryable)")
		require.Contains(t, stored, batch[2].MessageID, "Seq 3 should be stored")

		// Wait a bit longer to ensure seq 2 is marked as failed (not retried)
		time.Sleep(300 * time.Millisecond)

		// Verify seq 2 is still not stored (was marked as failed, not retried)
		stored = nonRetryableStorage.GetStored()
		require.NotContains(t, stored, batch[1].MessageID, "Seq 2 should never be stored (non-retryable)")

		// Verify job was marked as failed in the database
		require.Eventually(t, func() bool {
			var count int
			err := db.QueryRow(`
				SELECT COUNT(*) FROM ccv_storage_writer_jobs 
				WHERE owner_id = $1 AND status = 'failed'
			`, "test-"+t.Name()).Scan(&count)
			return err == nil && count == 1 // Seq 2 should be failed
		}, tests.WaitTimeout(t), 50*time.Millisecond)
	})

	t.Run("processes mixed batch with retryable and non-retryable failures", func(t *testing.T) {
		t.Parallel()

		lggr := logger.Test(t)
		mixedStorage := NewMixedFailureStorage()

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
			lggr,
			"test-"+t.Name(),
			NoopLatencyTracker{},
			mixedStorage,
			resultQueue,
			CoordinatorConfig{
				StorageBatchSize:  10,
				StorageRetryDelay: 50 * time.Millisecond,
			},
			NewPendingWritingTracker(lggr),
			&noopChainStatusManager{},
		)
		require.NoError(t, err)

		require.NoError(t, processor.Start(t.Context()))
		t.Cleanup(func() {
			require.NoError(t, processor.Close())
		})

		batch := []protocol.VerifierNodeResult{
			createTestVerifierNodeResult(1), // Success
			createTestVerifierNodeResult(2), // Retryable failure
			createTestVerifierNodeResult(3), // Non-retryable failure
			createTestVerifierNodeResult(4), // Success
		}

		// Configure: seq 2 = retryable, seq 3 = non-retryable
		mixedStorage.SetRetryableFailure(2)
		mixedStorage.SetNonRetryableFailure(3)

		require.NoError(t, resultQueue.Publish(t.Context(), batch...))

		// Wait for successful ones to be stored
		require.Eventually(t, func() bool {
			stored := mixedStorage.GetStored()
			return len(stored) == 2 // Seqs 1 and 4
		}, tests.WaitTimeout(t), 50*time.Millisecond)

		// Clear retryable failure so seq 2 can succeed on retry
		mixedStorage.ClearRetryableFailure()

		// Wait for seq 2 to be retried and stored
		require.Eventually(t, func() bool {
			stored := mixedStorage.GetStored()
			return len(stored) == 3 // Seqs 1, 2, and 4
		}, tests.WaitTimeout(t), 50*time.Millisecond)

		// Verify final state
		stored := mixedStorage.GetStored()
		require.Contains(t, stored, batch[0].MessageID, "Seq 1 should be stored")
		require.Contains(t, stored, batch[1].MessageID, "Seq 2 should be stored after retry")
		require.NotContains(t, stored, batch[2].MessageID, "Seq 3 should not be stored (non-retryable)")
		require.Contains(t, stored, batch[3].MessageID, "Seq 4 should be stored")
	})
}

type SelectiveFailureStorage struct {
	mu               sync.RWMutex
	stored           map[protocol.Bytes32]protocol.VerifierNodeResult
	failureCondition func(protocol.VerifierNodeResult) bool
}

func NewSelectiveFailureStorage() *SelectiveFailureStorage {
	return &SelectiveFailureStorage{
		stored: make(map[protocol.Bytes32]protocol.VerifierNodeResult),
	}
}

func (s *SelectiveFailureStorage) WriteCCVNodeData(_ context.Context, ccvDataList []protocol.VerifierNodeResult) ([]protocol.WriteResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	results := make([]protocol.WriteResult, len(ccvDataList))

	for i, data := range ccvDataList {
		results[i] = protocol.WriteResult{
			Input:     data,
			Status:    protocol.WriteSuccess,
			Error:     nil,
			Retryable: true,
		}

		// Check if this specific request should fail
		if s.failureCondition != nil && s.failureCondition(data) {
			results[i].Status = protocol.WriteFailure
			results[i].Error = errors.New("selective failure")
			results[i].Retryable = true
		} else {
			// Success - store it
			s.stored[data.MessageID] = data
		}
	}

	return results, nil
}

func (s *SelectiveFailureStorage) SetFailureCondition(fn func(protocol.VerifierNodeResult) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failureCondition = fn
}

func (s *SelectiveFailureStorage) ClearFailureCondition() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failureCondition = nil
}

func (s *SelectiveFailureStorage) GetStored() map[protocol.Bytes32]protocol.VerifierNodeResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[protocol.Bytes32]protocol.VerifierNodeResult)
	maps.Copy(result, s.stored)
	return result
}

type NonRetryableFailureStorage struct {
	mu                    sync.RWMutex
	stored                map[protocol.Bytes32]protocol.VerifierNodeResult
	nonRetryableCondition func(protocol.VerifierNodeResult) bool
}

func NewNonRetryableFailureStorage() *NonRetryableFailureStorage {
	return &NonRetryableFailureStorage{
		stored: make(map[protocol.Bytes32]protocol.VerifierNodeResult),
	}
}

func (s *NonRetryableFailureStorage) WriteCCVNodeData(_ context.Context, ccvDataList []protocol.VerifierNodeResult) ([]protocol.WriteResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	results := make([]protocol.WriteResult, len(ccvDataList))

	for i, data := range ccvDataList {
		results[i] = protocol.WriteResult{
			Input:     data,
			Status:    protocol.WriteSuccess,
			Error:     nil,
			Retryable: false,
		}

		if s.nonRetryableCondition != nil && s.nonRetryableCondition(data) {
			results[i].Status = protocol.WriteFailure
			results[i].Error = errors.New("validation error: non-retryable")
			results[i].Retryable = false // Non-retryable
		} else {
			s.stored[data.MessageID] = data
		}
	}

	return results, nil
}

func (s *NonRetryableFailureStorage) SetNonRetryableFailure(fn func(protocol.VerifierNodeResult) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nonRetryableCondition = fn
}

func (s *NonRetryableFailureStorage) GetStored() map[protocol.Bytes32]protocol.VerifierNodeResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[protocol.Bytes32]protocol.VerifierNodeResult)
	maps.Copy(result, s.stored)
	return result
}

type MixedFailureStorage struct {
	mu                 sync.RWMutex
	stored             map[protocol.Bytes32]protocol.VerifierNodeResult
	retryableSeq       uint64
	nonRetryableSeq    uint64
	retryableFailureOn bool
}

func NewMixedFailureStorage() *MixedFailureStorage {
	return &MixedFailureStorage{
		stored: make(map[protocol.Bytes32]protocol.VerifierNodeResult),
	}
}

func (s *MixedFailureStorage) WriteCCVNodeData(_ context.Context, ccvDataList []protocol.VerifierNodeResult) ([]protocol.WriteResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	results := make([]protocol.WriteResult, len(ccvDataList))

	for i, data := range ccvDataList {
		results[i] = protocol.WriteResult{
			Input:     data,
			Status:    protocol.WriteSuccess,
			Error:     nil,
			Retryable: false,
		}

		seq := uint64(data.Message.SequenceNumber)

		// Check if this should fail with retryable error
		if s.retryableFailureOn && seq == s.retryableSeq {
			results[i].Status = protocol.WriteFailure
			results[i].Error = errors.New("temporary network error")
			results[i].Retryable = true
		} else if seq == s.nonRetryableSeq {
			// Non-retryable error
			results[i].Status = protocol.WriteFailure
			results[i].Error = errors.New("validation error: invalid data")
			results[i].Retryable = false
		} else {
			// Success
			s.stored[data.MessageID] = data
		}
	}

	return results, nil
}

func (s *MixedFailureStorage) SetRetryableFailure(seq uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.retryableSeq = seq
	s.retryableFailureOn = true
}

func (s *MixedFailureStorage) ClearRetryableFailure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.retryableFailureOn = false
}

func (s *MixedFailureStorage) SetNonRetryableFailure(seq uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nonRetryableSeq = seq
}

func (s *MixedFailureStorage) GetStored() map[protocol.Bytes32]protocol.VerifierNodeResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[protocol.Bytes32]protocol.VerifierNodeResult)
	maps.Copy(result, s.stored)
	return result
}
