package verifier

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// Mock implementations

type mockCCVNodeDataWriter struct {
	mock.Mock
}

func (m *mockCCVNodeDataWriter) WriteCCVNodeData(ctx context.Context, data []protocol.VerifierNodeResult) error {
	args := m.Called(ctx, data)
	return args.Error(0)
}

// Helper function to create test VerifierNodeResult
func createTestVerifierNodeResult(sequenceNumber uint64) protocol.VerifierNodeResult {
	messageID, _ := protocol.NewBytes32FromString("0x0000000000000000000000000000000000000000000000000000000000000001")
	return protocol.VerifierNodeResult{
		MessageID: messageID,
		Message: protocol.Message{
			SequenceNumber: protocol.SequenceNumber(sequenceNumber),
		},
		CCVVersion:      []byte{1, 2, 3},
		CCVAddresses:    []protocol.UnknownAddress{},
		ExecutorAddress: protocol.UnknownAddress{},
		Signature:       []byte{4, 5, 6},
	}
}

func TestConfigWithDefaults(t *testing.T) {
	t.Run("uses provided config values when valid", func(t *testing.T) {
		lggr := logger.Test(t)
		config := CoordinatorConfig{
			StorageBatchSize:    100,
			StorageBatchTimeout: 5 * time.Second,
			StorageRetryDelay:   3 * time.Second,
		}

		batchSize, batchTimeout, retryDelay := configWithDefaults(lggr, config)

		assert.Equal(t, 100, batchSize)
		assert.Equal(t, 5*time.Second, batchTimeout)
		assert.Equal(t, 3*time.Second, retryDelay)
	})

	t.Run("applies default for StorageBatchSize when zero", func(t *testing.T) {
		lggr := logger.Test(t)
		config := CoordinatorConfig{
			StorageBatchSize:    0,
			StorageBatchTimeout: 5 * time.Second,
			StorageRetryDelay:   3 * time.Second,
		}

		batchSize, batchTimeout, retryDelay := configWithDefaults(lggr, config)

		assert.Equal(t, 50, batchSize)
		assert.Equal(t, 5*time.Second, batchTimeout)
		assert.Equal(t, 3*time.Second, retryDelay)
	})

	t.Run("applies default for StorageBatchSize when negative", func(t *testing.T) {
		lggr := logger.Test(t)
		config := CoordinatorConfig{
			StorageBatchSize:    -10,
			StorageBatchTimeout: 5 * time.Second,
			StorageRetryDelay:   3 * time.Second,
		}

		batchSize, batchTimeout, retryDelay := configWithDefaults(lggr, config)

		assert.Equal(t, 50, batchSize)
		assert.Equal(t, 5*time.Second, batchTimeout)
		assert.Equal(t, 3*time.Second, retryDelay)
	})

	t.Run("applies default for StorageBatchTimeout when zero", func(t *testing.T) {
		lggr := logger.Test(t)
		config := CoordinatorConfig{
			StorageBatchSize:    100,
			StorageBatchTimeout: 0,
			StorageRetryDelay:   3 * time.Second,
		}

		batchSize, batchTimeout, retryDelay := configWithDefaults(lggr, config)

		assert.Equal(t, 100, batchSize)
		assert.Equal(t, 1*time.Second, batchTimeout)
		assert.Equal(t, 3*time.Second, retryDelay)
	})

	t.Run("applies default for StorageBatchTimeout when negative", func(t *testing.T) {
		lggr := logger.Test(t)
		config := CoordinatorConfig{
			StorageBatchSize:    100,
			StorageBatchTimeout: -5 * time.Second,
			StorageRetryDelay:   3 * time.Second,
		}

		batchSize, batchTimeout, retryDelay := configWithDefaults(lggr, config)

		assert.Equal(t, 100, batchSize)
		assert.Equal(t, 1*time.Second, batchTimeout)
		assert.Equal(t, 3*time.Second, retryDelay)
	})

	t.Run("applies default for StorageRetryDelay when zero", func(t *testing.T) {
		lggr := logger.Test(t)
		config := CoordinatorConfig{
			StorageBatchSize:    100,
			StorageBatchTimeout: 5 * time.Second,
			StorageRetryDelay:   0,
		}

		batchSize, batchTimeout, retryDelay := configWithDefaults(lggr, config)

		assert.Equal(t, 100, batchSize)
		assert.Equal(t, 5*time.Second, batchTimeout)
		assert.Equal(t, 2*time.Second, retryDelay)
	})

	t.Run("applies default for StorageRetryDelay when negative", func(t *testing.T) {
		lggr := logger.Test(t)
		config := CoordinatorConfig{
			StorageBatchSize:    100,
			StorageBatchTimeout: 5 * time.Second,
			StorageRetryDelay:   -3 * time.Second,
		}

		batchSize, batchTimeout, retryDelay := configWithDefaults(lggr, config)

		assert.Equal(t, 100, batchSize)
		assert.Equal(t, 5*time.Second, batchTimeout)
		assert.Equal(t, 2*time.Second, retryDelay)
	})

	t.Run("applies all defaults when all values are zero", func(t *testing.T) {
		lggr := logger.Test(t)
		config := CoordinatorConfig{
			StorageBatchSize:    0,
			StorageBatchTimeout: 0,
			StorageRetryDelay:   0,
		}

		batchSize, batchTimeout, retryDelay := configWithDefaults(lggr, config)

		assert.Equal(t, 50, batchSize)
		assert.Equal(t, 1*time.Second, batchTimeout)
		assert.Equal(t, 2*time.Second, retryDelay)
	})
}

func TestStorageWriterProcessor_ProcessBatchesSuccessfully(t *testing.T) {
	t.Run("processes batches from channel until closed with storage always succeeding", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		lggr := logger.Test(t)
		mockStorage := &mockCCVNodeDataWriter{}

		// Create channel with sufficient buffer
		batchedCCVDataCh := make(chan batcher.BatchResult[protocol.VerifierNodeResult], 10)

		// Create processor
		processor := &StorageWriterProcessor{
			lggr:             lggr,
			verifierID:       "test-verifier",
			messageTracker:   NoopLatencyTracker{},
			storage:          mockStorage,
			batchedCCVDataCh: batchedCCVDataCh,
			retryDelay:       100 * time.Millisecond,
		}

		// Prepare test data
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

		// Set up mock expectations - storage always succeeds
		mockStorage.On("WriteCCVNodeData", mock.Anything, batch1).Return(nil).Once()
		mockStorage.On("WriteCCVNodeData", mock.Anything, batch2).Return(nil).Once()
		mockStorage.On("WriteCCVNodeData", mock.Anything, batch3).Return(nil).Once()

		// Start processor
		processorCtx, processorCancel := context.WithCancel(ctx)
		defer processorCancel()

		done := make(chan struct{})
		go func() {
			processor.run(processorCtx)
			close(done)
		}()

		// Send batches
		batchedCCVDataCh <- batcher.BatchResult[protocol.VerifierNodeResult]{
			Items: batch1,
			Error: nil,
		}
		batchedCCVDataCh <- batcher.BatchResult[protocol.VerifierNodeResult]{
			Items: batch2,
			Error: nil,
		}
		batchedCCVDataCh <- batcher.BatchResult[protocol.VerifierNodeResult]{
			Items: batch3,
			Error: nil,
		}

		// Give processor time to process all batches
		time.Sleep(100 * time.Millisecond)

		// Close channel to signal no more batches
		close(batchedCCVDataCh)

		// Wait for processor to finish
		select {
		case <-done:
			// Processor finished successfully
		case <-time.After(1 * time.Second):
			t.Fatal("processor did not finish in time")
		}

		// Verify all expectations were met
		mockStorage.AssertExpectations(t)
	})

	t.Run("handles empty batches gracefully", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		lggr := logger.Test(t)
		mockStorage := &mockCCVNodeDataWriter{}

		batchedCCVDataCh := make(chan batcher.BatchResult[protocol.VerifierNodeResult], 10)

		processor := &StorageWriterProcessor{
			lggr:             lggr,
			verifierID:       "test-verifier",
			messageTracker:   NoopLatencyTracker{},
			storage:          mockStorage,
			batchedCCVDataCh: batchedCCVDataCh,
			retryDelay:       100 * time.Millisecond,
		}

		processorCtx, processorCancel := context.WithCancel(ctx)
		defer processorCancel()

		done := make(chan struct{})
		go func() {
			processor.run(processorCtx)
			close(done)
		}()

		// Send empty batch
		batchedCCVDataCh <- batcher.BatchResult[protocol.VerifierNodeResult]{
			Items: []protocol.VerifierNodeResult{},
			Error: nil,
		}

		// Send valid batch
		validBatch := []protocol.VerifierNodeResult{createTestVerifierNodeResult(1)}
		mockStorage.On("WriteCCVNodeData", mock.Anything, validBatch).Return(nil).Once()

		batchedCCVDataCh <- batcher.BatchResult[protocol.VerifierNodeResult]{
			Items: validBatch,
			Error: nil,
		}

		time.Sleep(100 * time.Millisecond)
		close(batchedCCVDataCh)

		select {
		case <-done:
		case <-time.After(1 * time.Second):
			t.Fatal("processor did not finish in time")
		}

		// Storage should only be called once (for valid batch)
		mockStorage.AssertExpectations(t)
	})

	t.Run("handles batch-level errors from batcher", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		lggr := logger.Test(t)
		mockStorage := &mockCCVNodeDataWriter{}

		batchedCCVDataCh := make(chan batcher.BatchResult[protocol.VerifierNodeResult], 10)

		processor := &StorageWriterProcessor{
			lggr:             lggr,
			verifierID:       "test-verifier",
			messageTracker:   NoopLatencyTracker{},
			storage:          mockStorage,
			batchedCCVDataCh: batchedCCVDataCh,
			retryDelay:       100 * time.Millisecond,
		}

		processorCtx, processorCancel := context.WithCancel(ctx)
		defer processorCancel()

		done := make(chan struct{})
		go func() {
			processor.run(processorCtx)
			close(done)
		}()

		// Send batch with error
		batchedCCVDataCh <- batcher.BatchResult[protocol.VerifierNodeResult]{
			Items: nil,
			Error: errors.New("batcher internal error"),
		}

		time.Sleep(100 * time.Millisecond)
		close(batchedCCVDataCh)

		select {
		case <-done:
		case <-time.After(1 * time.Second):
			t.Fatal("processor did not finish in time")
		}

		// Storage should not be called for error batches
		mockStorage.AssertNotCalled(t, "WriteCCVNodeData")
	})
}

func TestStorageWriterProcessor_RetryFailedBatches(t *testing.T) {
	t.Run("retries failed batches after delay", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		lggr := logger.Test(t)
		mockStorage := &mockCCVNodeDataWriter{}

		// Create batcher with real channel
		batchedCCVDataCh := make(chan batcher.BatchResult[protocol.VerifierNodeResult], 100)

		batcherCtx, batcherCancel := context.WithCancel(ctx)
		defer batcherCancel()

		testBatcher := batcher.NewBatcher(
			batcherCtx,
			10,
			100*time.Millisecond,
			batchedCCVDataCh,
		)

		processor := &StorageWriterProcessor{
			lggr:             lggr,
			verifierID:       "test-verifier",
			messageTracker:   NoopLatencyTracker{},
			storage:          mockStorage,
			batcher:          testBatcher,
			batchedCCVDataCh: batchedCCVDataCh,
			retryDelay:       50 * time.Millisecond,
		}

		// Prepare test data
		batch := []protocol.VerifierNodeResult{
			createTestVerifierNodeResult(1),
			createTestVerifierNodeResult(2),
		}

		// First attempt fails, second attempt succeeds
		mockStorage.On("WriteCCVNodeData", mock.Anything, batch).
			Return(errors.New("storage error")).Once()
		mockStorage.On("WriteCCVNodeData", mock.Anything, batch).
			Return(nil).Once()

		// Start processor
		processorCtx, processorCancel := context.WithCancel(ctx)
		defer processorCancel()

		done := make(chan struct{})
		go func() {
			processor.run(processorCtx)
			close(done)
		}()

		// Send batch
		batchedCCVDataCh <- batcher.BatchResult[protocol.VerifierNodeResult]{
			Items: batch,
			Error: nil,
		}

		// Wait for initial failure and retry
		time.Sleep(200 * time.Millisecond)

		// Close everything
		batcherCancel()
		err := testBatcher.Close()
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(1 * time.Second):
			t.Fatal("processor did not finish in time")
		}

		// Verify storage was called twice (initial + retry)
		mockStorage.AssertExpectations(t)
	})

	t.Run("continues processing other batches when retry fails", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		lggr := logger.Test(t)
		mockStorage := &mockCCVNodeDataWriter{}

		batchedCCVDataCh := make(chan batcher.BatchResult[protocol.VerifierNodeResult], 100)

		batcherCtx, batcherCancel := context.WithCancel(ctx)
		defer batcherCancel()

		testBatcher := batcher.NewBatcher(
			batcherCtx,
			10,
			100*time.Millisecond,
			batchedCCVDataCh,
		)

		processor := &StorageWriterProcessor{
			lggr:             lggr,
			verifierID:       "test-verifier",
			messageTracker:   NoopLatencyTracker{},
			storage:          mockStorage,
			batcher:          testBatcher,
			batchedCCVDataCh: batchedCCVDataCh,
			retryDelay:       50 * time.Millisecond,
		}

		// Prepare test data
		failingBatch := []protocol.VerifierNodeResult{createTestVerifierNodeResult(1)}
		successBatch := []protocol.VerifierNodeResult{createTestVerifierNodeResult(2)}

		// Failing batch fails once (we'll stop before retry)
		mockStorage.On("WriteCCVNodeData", mock.Anything, failingBatch).
			Return(errors.New("persistent error")).Once()

		// Success batch succeeds
		mockStorage.On("WriteCCVNodeData", mock.Anything, successBatch).
			Return(nil).Once()

		// Start processor
		processorCtx, processorCancel := context.WithCancel(ctx)
		defer processorCancel()

		done := make(chan struct{})
		go func() {
			processor.run(processorCtx)
			close(done)
		}()

		// Send failing batch
		batchedCCVDataCh <- batcher.BatchResult[protocol.VerifierNodeResult]{
			Items: failingBatch,
			Error: nil,
		}

		// Send success batch
		batchedCCVDataCh <- batcher.BatchResult[protocol.VerifierNodeResult]{
			Items: successBatch,
			Error: nil,
		}

		// Wait for processing
		time.Sleep(100 * time.Millisecond)

		// Cancel processor context first to stop the run loop
		processorCancel()

		// Then close batcher
		batcherCancel()
		err := testBatcher.Close()
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(1 * time.Second):
			t.Fatal("processor did not finish in time")
		}

		// Verify success batch was processed
		mockStorage.AssertCalled(t, "WriteCCVNodeData", mock.Anything, successBatch)
	})
}

func TestStorageWriterProcessor_ContextCancellation(t *testing.T) {
	t.Run("stops processing when context is cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		lggr := logger.Test(t)
		mockStorage := &mockCCVNodeDataWriter{}

		batchedCCVDataCh := make(chan batcher.BatchResult[protocol.VerifierNodeResult], 10)

		processor := &StorageWriterProcessor{
			lggr:             lggr,
			verifierID:       "test-verifier",
			messageTracker:   NoopLatencyTracker{},
			storage:          mockStorage,
			batchedCCVDataCh: batchedCCVDataCh,
			retryDelay:       100 * time.Millisecond,
		}

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
