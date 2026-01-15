package verifier

import (
	"context"
	"errors"
	"maps"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

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
			ctx,
			lggr,
			"test-verifier",
			NoopLatencyTracker{},
			fakeStorage,
			CoordinatorConfig{
				StorageRetryDelay: 100 * time.Millisecond,
			},
		)
		require.NoError(t, err)

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

		processorCtx, processorCancel := context.WithCancel(ctx)
		t.Cleanup(processorCancel)

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

		// Cancel batcher context and close to allow drain loop to complete
		cancel()
		processorBatcher.Close()

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
			ctx,
			lggr,
			"test-verifier",
			NoopLatencyTracker{},
			fakeStorage,
			CoordinatorConfig{
				StorageRetryDelay: 100 * time.Millisecond,
			},
		)
		require.NoError(t, err)

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
			ctx,
			lggr,
			"test-verifier",
			NoopLatencyTracker{},
			fakeStorage,
			CoordinatorConfig{
				StorageRetryDelay: 100 * time.Millisecond,
			},
		)
		require.NoError(t, err)

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
		batcherCtx, batcherCancel := context.WithCancel(ctx)
		testBatcher := batcher.NewBatcher[protocol.VerifierNodeResult](
			batcherCtx,
			10,
			100*time.Millisecond,
			100,
		)

		processor := &StorageWriterProcessor{
			lggr:           lggr,
			verifierID:     "test-verifier",
			messageTracker: NoopLatencyTracker{},
			storage:        fakeStorage,
			batcher:        testBatcher,
			retryDelay:     50 * time.Millisecond,
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

		// Wait for retry
		time.Sleep(150 * time.Millisecond)

		// Close everything
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
			batcherCtx,
			10,
			100*time.Millisecond,
			100,
		)

		processor := &StorageWriterProcessor{
			lggr:           lggr,
			verifierID:     "test-verifier",
			messageTracker: NoopLatencyTracker{},
			storage:        fakeStorage,
			batcher:        testBatcher,
			retryDelay:     50 * time.Millisecond,
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

		// Verify that both batches were stored
		// Note: With drain using background context, retried items are processed successfully during shutdown
		stored := fakeStorage.GetStored()
		successItem, exists := stored[successBatch[0].MessageID]
		require.True(t, exists, "success batch should be stored")
		require.Equal(t, successBatch[0].Message.SequenceNumber, successItem.Message.SequenceNumber)

		// The initially-failing batch should also be stored during drain after retry
		failedItem, failedExists := stored[failingBatch[0].MessageID]
		require.True(t, failedExists, "initially-failing batch should be stored after retry during drain")
		require.Equal(t, failingBatch[0].Message.SequenceNumber, failedItem.Message.SequenceNumber)
	})
}

func TestStorageWriterProcessor_ContextCancellation(t *testing.T) {
	t.Run("stops processing when context is cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)

		lggr := logger.Test(t)
		fakeStorage := NewFakeCCVNodeDataWriter()

		processor, processorBatcher, err := NewStorageBatcherProcessor(
			ctx,
			lggr,
			"test-verifier",
			NoopLatencyTracker{},
			fakeStorage,
			CoordinatorConfig{
				StorageRetryDelay: 100 * time.Millisecond,
			},
		)
		require.NoError(t, err)

		processorCtx, processorCancel := context.WithCancel(ctx)

		done := make(chan struct{})
		go func() {
			processor.run(processorCtx)
			close(done)
		}()

		// Cancel processor context to trigger drain
		processorCancel()

		// Cancel batcher context and close to allow drain loop to complete
		cancel()
		processorBatcher.Close()

		// Processor should exit after draining
		select {
		case <-done:
			// Success
		case <-time.After(500 * time.Millisecond):
			t.Fatal("processor did not stop after context cancellation")
		}
	})

	t.Run("drains pending batches on context cancel without deadlock", func(t *testing.T) {
		// Regression test for deadlock when context is canceled with pending batches
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)

		lggr := logger.Test(t)
		fakeStorage := NewFakeCCVNodeDataWriter()

		// Create batcher with large maxWait and unbuffered channel
		batcherCtx, batcherCancel := context.WithCancel(ctx)
		testBatcher := batcher.NewBatcher[protocol.VerifierNodeResult](
			batcherCtx,
			100,            // Large batch size
			10*time.Second, // Large maxWait - won't auto-flush
			0,              // Unbuffered channel to test blocking send
		)

		processor := &StorageWriterProcessor{
			lggr:           lggr,
			verifierID:     "test-verifier",
			messageTracker: NoopLatencyTracker{},
			storage:        fakeStorage,
			batcher:        testBatcher,
			retryDelay:     50 * time.Millisecond,
		}

		batch := []protocol.VerifierNodeResult{
			createTestVerifierNodeResult(1),
			createTestVerifierNodeResult(2),
		}

		processorCtx, processorCancel := context.WithCancel(ctx)

		done := make(chan struct{})
		go func() {
			processor.run(processorCtx)
			close(done)
		}()

		// Add items that won't trigger auto-flush
		err := testBatcher.Add(batch...)
		require.NoError(t, err)

		// Cancel processor context immediately
		processorCancel()

		// Give time for drain to start
		time.Sleep(50 * time.Millisecond)

		// Close batcher - this should not deadlock
		batcherCancel()
		closeErr := testBatcher.Close()
		require.NoError(t, closeErr)

		// Processor should complete without deadlock
		select {
		case <-done:
			// Success - no deadlock
		case <-time.After(2 * time.Second):
			t.Fatal("processor did not finish - DEADLOCK detected")
		}

		// Verify items were stored during drain
		stored := fakeStorage.GetStored()
		require.Equal(t, len(batch), len(stored), "all items should be stored during drain")

		for _, item := range batch {
			storedItem, exists := stored[item.MessageID]
			require.True(t, exists, "item should be stored during drain")
			require.Equal(t, item.Message.SequenceNumber, storedItem.Message.SequenceNumber)
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
