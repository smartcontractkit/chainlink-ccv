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

	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

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

func TestStorageWriterProcessor_ProcessBatchesSuccessfully(t *testing.T) {
	lggr := logger.Test(t)

	t.Run("processes batches from channel until closed with storage always succeeding", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)

		fakeStorage := NewFakeCCVNodeDataWriter()
		processor, processorBatcher, err := NewStorageBatcherProcessor(
			lggr,
			"test-verifier",
			NoopLatencyTracker{},
			fakeStorage,
			CoordinatorConfig{
				StorageRetryDelay: 100 * time.Millisecond,
			},
			NewPendingWritingTracker(lggr),
			&noopChainStatusManager{},
		)
		require.NoError(t, err)

		processorCtx, processorCancel := context.WithCancel(ctx)
		t.Cleanup(processorCancel)
		processorBatcher.Start(processorCtx)

		batch1 := []protocol.VerifierNodeResult{
			createTestVerifierNodeResult(1),
			createTestVerifierNodeResult(2),
		}
		batch2 := []protocol.VerifierNodeResult{
			createTestVerifierNodeResult(3),
			createTestVerifierNodeResult(4),
			createTestVerifierNodeResult(5),
		}
		batch3 := []protocol.VerifierNodeResult{
			createTestVerifierNodeResult(6),
		}

		done := make(chan struct{})
		go func() {
			processor.run(processorCtx)
			close(done)
		}()

		// Send batches
		err = processorBatcher.AddImmediate(batcher.BatchResult[protocol.VerifierNodeResult]{
			Items: batch1,
			Error: nil,
		})
		require.NoError(t, err)
		err = processorBatcher.AddImmediate(batcher.BatchResult[protocol.VerifierNodeResult]{
			Items: batch2,
			Error: nil,
		})
		require.NoError(t, err)
		err = processorBatcher.AddImmediate(batcher.BatchResult[protocol.VerifierNodeResult]{
			Items: batch3,
			Error: nil,
		})
		require.NoError(t, err)

		// Give processor time to process all batches
		time.Sleep(100 * time.Millisecond)
		processorCancel()

		// Wait for processor to finish
		select {
		case <-done:
			// Processor finished successfully
		case <-time.After(1 * time.Second):
			t.Fatal("processor did not finish in time")
		}

		// Verify all items were stored
		stored := fakeStorage.GetStored()
		expectedCount := len(batch1) + len(batch2) + len(batch3)
		require.Equal(t, expectedCount, len(stored), "should have stored all items")

		// Verify each item was stored correctly
		allBatches := append(append(batch1, batch2...), batch3...)
		for _, item := range allBatches {
			storedItem, exists := stored[item.MessageID]
			require.True(t, exists, "item with MessageID %s should be stored", item.MessageID)
			require.Equal(t, item.Message.SequenceNumber, storedItem.Message.SequenceNumber)
		}
	})

	t.Run("handles empty batches gracefully", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)

		fakeStorage := NewFakeCCVNodeDataWriter()

		processor, processorBatcher, err := NewStorageBatcherProcessor(
			lggr,
			"test-verifier",
			NoopLatencyTracker{},
			fakeStorage,
			CoordinatorConfig{
				StorageRetryDelay: 100 * time.Millisecond,
			},
			NewPendingWritingTracker(lggr),
			&noopChainStatusManager{},
		)
		require.NoError(t, err)
		processorBatcher.Start(ctx)

		done := make(chan struct{})
		go func() {
			processor.run(ctx)
			close(done)
		}()

		err = processorBatcher.AddImmediate(batcher.BatchResult[protocol.VerifierNodeResult]{
			Items: []protocol.VerifierNodeResult{},
			Error: nil,
		})
		require.NoError(t, err)
		validBatch := []protocol.VerifierNodeResult{
			createTestVerifierNodeResult(1),
		}

		err = processorBatcher.AddImmediate(batcher.BatchResult[protocol.VerifierNodeResult]{
			Items: validBatch,
			Error: nil,
		})
		require.NoError(t, err)

		time.Sleep(100 * time.Millisecond)
		cancel()

		select {
		case <-done:
		case <-time.After(1 * time.Second):
			t.Fatal("processor did not finish in time")
		}

		// Verify only the valid batch was stored (empty batch should be skipped)
		require.Equal(t, 1, fakeStorage.GetStoredCount(), "should have stored only the valid batch")

		// Verify the correct item was stored
		stored := fakeStorage.GetStored()
		storedItem, exists := stored[validBatch[0].MessageID]
		require.True(t, exists)
		require.Equal(t, validBatch[0].Message.SequenceNumber, storedItem.Message.SequenceNumber)
	})

	t.Run("handles batch-level errors from batcher", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)

		fakeStorage := NewFakeCCVNodeDataWriter()

		processor, processorBatcher, err := NewStorageBatcherProcessor(
			lggr,
			"test-verifier",
			NoopLatencyTracker{},
			fakeStorage,
			CoordinatorConfig{
				StorageRetryDelay: 100 * time.Millisecond,
			},
			NewPendingWritingTracker(lggr),
			&noopChainStatusManager{},
		)
		require.NoError(t, err)
		processorBatcher.Start(ctx)

		done := make(chan struct{})
		go func() {
			processor.run(ctx)
			close(done)
		}()

		// Send batch with error
		err = processorBatcher.AddImmediate(batcher.BatchResult[protocol.VerifierNodeResult]{
			Items: nil,
			Error: errors.New("batcher internal error"),
		})
		require.NoError(t, err)

		time.Sleep(100 * time.Millisecond)
		cancel()

		select {
		case <-done:
		case <-time.After(1 * time.Second):
			t.Fatal("processor did not finish in time")
		}

		// Storage should not have stored anything for error batches
		require.Equal(t, 0, fakeStorage.GetStoredCount(), "should not have stored any items from error batches")
	})
}

func TestStorageWriterProcessor_RetryFailedBatches(t *testing.T) {
	lggr := logger.Test(t)

	t.Run("retries failed batches after delay", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)

		fakeStorage := NewFakeCCVNodeDataWriter()

		// Create batcher with real channel
		// Note: retry ticker fires every 2*maxWait = 200ms
		batcherCtx, batcherCancel := context.WithCancel(ctx)
		testBatcher := batcher.NewBatcher[protocol.VerifierNodeResult](
			10,
			100*time.Millisecond,
			100,
		)
		testBatcher.Start(batcherCtx)

		processor := &StorageWriterProcessor{
			lggr:           lggr,
			verifierID:     "test-verifier",
			messageTracker: NoopLatencyTracker{},
			storage:        fakeStorage,
			batcher:        testBatcher,
			retryDelay:     50 * time.Millisecond,
			writingTracker: NewPendingWritingTracker(lggr),
		}

		batch := []protocol.VerifierNodeResult{
			createTestVerifierNodeResult(1),
			createTestVerifierNodeResult(2),
		}

		// Configure fake to fail on first write
		fakeStorage.SetError(errors.New("storage error"))

		done := make(chan struct{})
		go func() {
			processor.run(ctx)
			close(done)
		}()

		err := testBatcher.AddImmediate(batcher.BatchResult[protocol.VerifierNodeResult]{
			Items: batch,
			Error: nil,
		})
		require.NoError(t, err)

		// Wait a bit for initial failure
		time.Sleep(30 * time.Millisecond)

		// Clear error so retry succeeds
		fakeStorage.ClearError()

		// Wait for retry to be processed:
		// - retryDelay = 50ms (items become ready at ~50ms)
		// - retry ticker fires at 200ms (2*maxWait)
		// - items move to buffer, then timer-based flush at +100ms (maxWait)
		// Total: need to wait at least 300ms for items to be flushed and re-processed
		time.Sleep(400 * time.Millisecond)

		// Close everything - items should already be stored
		batcherCancel()
		err = testBatcher.Close()
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(1 * time.Second):
			t.Fatal("processor did not finish in time")
		}

		// Verify data was eventually stored successfully (after retry)
		stored := fakeStorage.GetStored()
		require.Equal(t, len(batch), len(stored), "should have stored all items after retry")

		for _, item := range batch {
			storedItem, exists := stored[item.MessageID]
			require.True(t, exists, "item should be stored after retry")
			require.Equal(t, item.Message.SequenceNumber, storedItem.Message.SequenceNumber)
		}
	})

	t.Run("continues processing other batches when retry fails", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)

		fakeStorage := NewFakeCCVNodeDataWriter()

		batcherCtx, batcherCancel := context.WithCancel(ctx)
		testBatcher := batcher.NewBatcher[protocol.VerifierNodeResult](
			10,
			100*time.Millisecond,
			100,
		)
		testBatcher.Start(batcherCtx)

		processor := &StorageWriterProcessor{
			lggr:           lggr,
			verifierID:     "test-verifier",
			messageTracker: NoopLatencyTracker{},
			storage:        fakeStorage,
			batcher:        testBatcher,
			retryDelay:     50 * time.Millisecond,
			writingTracker: NewPendingWritingTracker(lggr),
		}

		failingBatch := []protocol.VerifierNodeResult{createTestVerifierNodeResult(1)}
		successBatch := []protocol.VerifierNodeResult{createTestVerifierNodeResult(2)}

		// Configure storage to always fail (will fail for both batches initially)
		fakeStorage.SetError(errors.New("persistent error"))

		// Start processor
		processorCtx, processorCancel := context.WithCancel(ctx)
		defer processorCancel()

		done := make(chan struct{})
		go func() {
			processor.run(processorCtx)
			close(done)
		}()

		err := testBatcher.AddImmediate(batcher.BatchResult[protocol.VerifierNodeResult]{
			Items: failingBatch,
			Error: nil,
		})
		require.NoError(t, err)

		// Wait a moment
		time.Sleep(20 * time.Millisecond)
		// Clear error so next batch succeeds
		fakeStorage.ClearError()

		err = testBatcher.AddImmediate(batcher.BatchResult[protocol.VerifierNodeResult]{
			Items: successBatch,
			Error: nil,
		})
		require.NoError(t, err)

		time.Sleep(100 * time.Millisecond)

		// Cancel processor context first to stop the run loop
		processorCancel()

		// Then close batcher
		batcherCancel()
		err = testBatcher.Close()
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(1 * time.Second):
			t.Fatal("processor did not finish in time")
		}

		// Verify that at least the success batch was stored
		stored := fakeStorage.GetStored()
		successItem, exists := stored[successBatch[0].MessageID]
		require.True(t, exists, "success batch should be stored")
		require.Equal(t, successBatch[0].Message.SequenceNumber, successItem.Message.SequenceNumber)

		// The failing batch should not be stored
		_, failedExists := stored[failingBatch[0].MessageID]
		require.False(t, failedExists, "failing batch should not be stored")
	})
}

func TestStorageWriterProcessor_ContextCancellation(t *testing.T) {
	t.Run("stops processing when context is cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)

		lggr := logger.Test(t)
		fakeStorage := NewFakeCCVNodeDataWriter()

		processor, _, err := NewStorageBatcherProcessor(
			lggr,
			"test-verifier",
			NoopLatencyTracker{},
			fakeStorage,
			CoordinatorConfig{
				StorageRetryDelay: 100 * time.Millisecond,
			},
			NewPendingWritingTracker(lggr),
			&noopChainStatusManager{},
		)
		require.NoError(t, err)

		processorCtx, processorCancel := context.WithCancel(ctx)

		done := make(chan struct{})
		go func() {
			processor.run(processorCtx)
			close(done)
		}()

		// Cancel context immediately
		processorCancel()

		// Processor should exit
		select {
		case <-done:
			// Success
		case <-time.After(500 * time.Millisecond):
			t.Fatal("processor did not stop after context cancellation")
		}
	})
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

type checkpointTestSetup struct {
	processor       *StorageWriterProcessor
	batcher         *batcher.Batcher[protocol.VerifierNodeResult]
	storage         *FakeCCVNodeDataWriter
	mockChainStatus *mocks.MockChainStatusManager
	tracker         *PendingWritingTracker
	ctx             context.Context
	cancel          context.CancelFunc
}

func setupCheckpointTest(t *testing.T) *checkpointTestSetup {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	lggr := logger.Test(t)
	fakeStorage := NewFakeCCVNodeDataWriter()
	mockChainStatus := mocks.NewMockChainStatusManager(t)
	tracker := NewPendingWritingTracker(lggr)

	processor, processorBatcher, err := NewStorageBatcherProcessor(
		lggr,
		"test-verifier",
		NoopLatencyTracker{},
		fakeStorage,
		CoordinatorConfig{
			StorageRetryDelay: 100 * time.Millisecond,
		},
		tracker,
		mockChainStatus,
	)
	require.NoError(t, err)

	processorBatcher.Start(ctx)
	return &checkpointTestSetup{
		processor:       processor,
		batcher:         processorBatcher,
		storage:         fakeStorage,
		mockChainStatus: mockChainStatus,
		tracker:         tracker,
		ctx:             ctx,
		cancel:          cancel,
	}
}

func (s *checkpointTestSetup) sendBatch(t *testing.T, items []protocol.VerifierNodeResult) {
	err := s.batcher.AddImmediate(batcher.BatchResult[protocol.VerifierNodeResult]{
		Items: items,
		Error: nil,
	})
	require.NoError(t, err)
}

// ----------------------
// Checkpoint Management Tests
// ----------------------

func TestStorageWriterProcessor_CheckpointManagement(t *testing.T) {
	t.Run("writes checkpoint after successful storage write", func(t *testing.T) {
		setup := setupCheckpointTest(t)
		chain1 := protocol.ChainSelector(1)

		// Create and track message at finalized block 100
		msg1 := createTrackedMessage(chain1, 100, 100, setup.tracker)

		var mu sync.Mutex
		callCount := 0
		// Expect checkpoint at 99 (100 - 1) after msg1 is written and removed
		setup.mockChainStatus.EXPECT().
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

		go func() {
			setup.processor.run(setup.ctx)
		}()
		setup.sendBatch(t, []protocol.VerifierNodeResult{msg1})

		require.Eventually(t, func() bool {
			mu.Lock()
			count := callCount
			mu.Unlock()
			return count == 1 && setup.mockChainStatus.AssertExpectations(t)
		}, tests.WaitTimeout(t), 500*time.Millisecond)
	})

	t.Run("checkpoint advances monotonically", func(t *testing.T) {
		setup := setupCheckpointTest(t)
		chain1 := protocol.ChainSelector(1)

		// Create messages at different finalized levels
		msg1 := createTrackedMessage(chain1, 100, 100, setup.tracker)
		msg2 := createTrackedMessage(chain1, 105, 105, setup.tracker)
		msg3 := createTrackedMessage(chain1, 110, 110, setup.tracker)

		var mu sync.Mutex
		// Expect checkpoints in order: 104, 109
		callCount := 0
		setup.mockChainStatus.EXPECT().
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

		go func() {
			setup.processor.run(setup.ctx)
		}()
		// Write messages one by one
		setup.sendBatch(t, []protocol.VerifierNodeResult{msg1})
		setup.sendBatch(t, []protocol.VerifierNodeResult{msg2})
		setup.sendBatch(t, []protocol.VerifierNodeResult{msg3})

		require.Eventually(t, func() bool {
			mu.Lock()
			count := callCount
			mu.Unlock()
			return count == 2 && setup.mockChainStatus.AssertExpectations(t)
		}, tests.WaitTimeout(t), 500*time.Millisecond)

		mu.Lock()
		finalCount := callCount
		mu.Unlock()
		require.Equal(t, 2, finalCount, "expected 2 checkpoint writes")
	})

	t.Run("no redundant checkpoint writes for same level", func(t *testing.T) {
		setup := setupCheckpointTest(t)
		chain1 := protocol.ChainSelector(1)

		// Create multiple messages at same finalized level
		msg1 := createTrackedMessage(chain1, 100, 100, setup.tracker)
		msg2 := createTrackedMessage(chain1, 101, 100, setup.tracker)
		msg3 := createTrackedMessage(chain1, 102, 100, setup.tracker)

		var mu sync.Mutex
		callCount := 0
		// Expect only ONE checkpoint write at 99 after all messages are written
		setup.mockChainStatus.EXPECT().
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

		go func() {
			setup.processor.run(setup.ctx)
		}()
		setup.sendBatch(t, []protocol.VerifierNodeResult{msg1, msg2, msg3})

		require.Eventually(t, func() bool {
			mu.Lock()
			count := callCount
			mu.Unlock()
			return count == 1 && setup.mockChainStatus.AssertExpectations(t)
		}, tests.WaitTimeout(t), 500*time.Millisecond)
	})

	t.Run("multiple chains handled independently", func(t *testing.T) {
		setup := setupCheckpointTest(t)
		chain1 := protocol.ChainSelector(1)
		chain2 := protocol.ChainSelector(2)

		// Create messages on different chains
		msg1 := createTrackedMessage(chain1, 100, 100, setup.tracker)
		msg2 := createTrackedMessage(chain2, 200, 200, setup.tracker)

		// Expect checkpoints for both chains
		var mu sync.Mutex
		chain1Written, chain2Written := false, false
		setup.mockChainStatus.EXPECT().
			WriteChainStatuses(mock.Anything, mock.Anything).
			RunAndReturn(func(_ context.Context, statuses []protocol.ChainStatusInfo) error {
				mu.Lock()
				for _, status := range statuses {
					switch status.ChainSelector {
					case chain1:
						require.Equal(t, int64(99), status.FinalizedBlockHeight.Int64())
						chain1Written = true
					case chain2:
						require.Equal(t, int64(199), status.FinalizedBlockHeight.Int64())
						chain2Written = true
					}
				}
				mu.Unlock()
				return nil
			}).
			Maybe()

		go func() {
			setup.processor.run(setup.ctx)
		}()
		setup.sendBatch(t, []protocol.VerifierNodeResult{msg1, msg2})

		require.Eventually(t, func() bool {
			mu.Lock()
			c1 := chain1Written
			c2 := chain2Written
			mu.Unlock()
			return c1 && c2 && setup.mockChainStatus.AssertExpectations(t)
		}, tests.WaitTimeout(t), 500*time.Millisecond)
	})

	t.Run("checkpoint respects pending messages at lower blocks", func(t *testing.T) {
		setup := setupCheckpointTest(t)
		chain1 := protocol.ChainSelector(1)

		// Create messages: one at 100, one at 110
		_ = createTrackedMessage(chain1, 100, 100, setup.tracker) // msg1 - stays pending
		msg2 := createTrackedMessage(chain1, 110, 110, setup.tracker)

		var mu sync.Mutex
		callCount := 0
		// Expect only checkpoint at 99 (msg1 at 100 is still pending)
		setup.mockChainStatus.EXPECT().
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

		go func() {
			setup.processor.run(setup.ctx)
		}()
		// Write only msg2 - msg1 stays pending
		setup.sendBatch(t, []protocol.VerifierNodeResult{msg2})

		require.Eventually(t, func() bool {
			mu.Lock()
			count := callCount
			mu.Unlock()
			return count == 1 && setup.mockChainStatus.AssertExpectations(t)
		}, tests.WaitTimeout(t), 500*time.Millisecond)
	})
}
