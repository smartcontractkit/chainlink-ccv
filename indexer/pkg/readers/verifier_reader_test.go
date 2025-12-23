package readers

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// mockVerifierResultsAPI is a simple mock implementation of VerifierResultsAPI for testing.
type mockVerifierResultsAPI struct {
	results map[protocol.Bytes32]protocol.VerifierResult
	err     error
}

func (m *mockVerifierResultsAPI) GetVerifications(ctx context.Context, messageIDs []protocol.Bytes32) (map[protocol.Bytes32]protocol.VerifierResult, error) {
	if m.err != nil {
		return m.results, m.err
	}
	return m.results, nil
}

// newTestVerifierReader creates a new VerifierReader instance for testing.
func newTestVerifierReader(mockVerifier *mockVerifierResultsAPI, config *config.VerifierConfig) *VerifierReader {
	ctx := context.Background()
	return NewVerifierReader(ctx, mockVerifier, config)
}

func TestNewVerifierReader(t *testing.T) {
	config := &config.VerifierConfig{
		BatchSize:        100,
		MaxBatchWaitTime: 100,
	}

	mockVerifier := &mockVerifierResultsAPI{
		results: make(map[protocol.Bytes32]protocol.VerifierResult),
	}

	reader := newTestVerifierReader(mockVerifier, config)
	require.NotNil(t, reader)
}

func TestVerifierReader_ProcessMessage_Success(t *testing.T) {
	config := &config.VerifierConfig{
		BatchSize:        100,
		MaxBatchWaitTime: 100,
	}

	mockVerifier := &mockVerifierResultsAPI{
		results: make(map[protocol.Bytes32]protocol.VerifierResult),
	}
	reader := newTestVerifierReader(mockVerifier, config)
	messageID := protocol.Bytes32{1, 2, 3}

	resultCh, err := reader.ProcessMessage(messageID)
	require.NoError(t, err)
	require.NotNil(t, resultCh)

	// Channel should be created but not yet closed
	select {
	case <-resultCh:
		t.Fatal("channel should not have received a result yet")
	default:
		// Expected
	}
}

func TestVerifierReader_ProcessMessage_BatcherClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	config := &config.VerifierConfig{
		BatchSize:        100,
		MaxBatchWaitTime: 100,
	}
	mockVerifier := &mockVerifierResultsAPI{
		results: make(map[protocol.Bytes32]protocol.VerifierResult),
	}
	reader := NewVerifierReader(ctx, mockVerifier, config)

	// Cancel context to close batcher
	cancel()

	// Wait a bit for batcher to process cancellation
	time.Sleep(50 * time.Millisecond)

	messageID := protocol.Bytes32{1, 2, 3}
	resultCh, err := reader.ProcessMessage(messageID)

	// Should return error because batcher is closed
	require.Error(t, err)
	assert.Nil(t, resultCh)
}

func TestVerifierReader_Start(t *testing.T) {
	ctx := context.Background()
	config := &config.VerifierConfig{
		BatchSize:        2, // Small batch size for testing
		MaxBatchWaitTime: 50,
	}

	mockVerifier := &mockVerifierResultsAPI{
		results: make(map[protocol.Bytes32]protocol.VerifierResult),
	}
	reader := newTestVerifierReader(mockVerifier, config)

	err := reader.Start(ctx)
	require.NoError(t, err)

	// Give goroutine a moment to start
	time.Sleep(10 * time.Millisecond)

	// Verify goroutine is running by checking that we can process messages
	messageID := protocol.Bytes32{1, 2, 3}
	resultCh, err := reader.ProcessMessage(messageID)
	require.NoError(t, err)
	require.NotNil(t, resultCh)
}

func TestVerifierReader_Run_ProcessesBatches(t *testing.T) {
	ctx := context.Background()

	config := &config.VerifierConfig{
		BatchSize:        2, // Small batch size to trigger batch quickly
		MaxBatchWaitTime: 50,
	}

	messageID1 := protocol.Bytes32{1, 2, 3}
	messageID2 := protocol.Bytes32{4, 5, 6}

	ccvData1 := protocol.VerifierResult{MessageID: messageID1}
	ccvData2 := protocol.VerifierResult{MessageID: messageID2}

	mockVerifier := &mockVerifierResultsAPI{
		results: map[protocol.Bytes32]protocol.VerifierResult{
			messageID1: ccvData1,
			messageID2: ccvData2,
		},
	}
	reader := NewVerifierReader(ctx, mockVerifier, config)

	err := reader.Start(ctx)
	require.NoError(t, err)

	// Give the run goroutine a moment to start and be ready to receive batches
	time.Sleep(10 * time.Millisecond)

	// Process two messages to trigger a batch
	resultCh1, err := reader.ProcessMessage(messageID1)
	require.NoError(t, err)

	resultCh2, err := reader.ProcessMessage(messageID2)
	require.NoError(t, err)

	// Wait for batch to be processed (batch size is 2, so it should trigger immediately)
	var result1 common.Result[protocol.VerifierResult]
	require.Eventually(t, func() bool {
		select {
		case r := <-resultCh1:
			result1 = r
			return true
		default:
			return false
		}
	}, waitTimeout(t), 50*time.Millisecond, "waiting for result1")
	assert.Equal(t, ccvData1, result1.Value())
	assert.NoError(t, result1.Err())

	var result2 common.Result[protocol.VerifierResult]
	require.Eventually(t, func() bool {
		select {
		case r := <-resultCh2:
			result2 = r
			return true
		default:
			return false
		}
	}, waitTimeout(t), 50*time.Millisecond, "waiting for result2")
	assert.Equal(t, ccvData2, result2.Value())
	assert.NoError(t, result2.Err())

	// Clean up to ensure goroutines finish properly
	err = reader.Close()
	require.NoError(t, err)
}

func TestVerifierReader_Run_HandlesVerifierError(t *testing.T) {
	ctx := context.Background()

	config := &config.VerifierConfig{
		BatchSize:        1, // Process immediately
		MaxBatchWaitTime: 50,
	}

	messageID := protocol.Bytes32{1, 2, 3}
	expectedError := errors.New("verifier error")

	mockVerifier := &mockVerifierResultsAPI{
		results: make(map[protocol.Bytes32]protocol.VerifierResult),
		err:     expectedError,
	}
	reader := NewVerifierReader(ctx, mockVerifier, config)

	err := reader.Start(ctx)
	require.NoError(t, err)

	// Give the run goroutine a moment to start and be ready to receive batches
	time.Sleep(10 * time.Millisecond)

	resultCh, err := reader.ProcessMessage(messageID)
	require.NoError(t, err)

	// Wait for result
	select {
	case result := <-resultCh:
		assert.Error(t, result.Err())
		assert.Equal(t, expectedError, result.Err())
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timeout waiting for result")
	}

	// Clean up to ensure goroutines finish properly
	err = reader.Close()
	require.NoError(t, err)
}

func TestVerifierReader_Close_GracefulShutdown(t *testing.T) {
	ctx := context.Background()
	config := &config.VerifierConfig{
		BatchSize:        10,
		MaxBatchWaitTime: 100,
	}

	mockVerifier := &mockVerifierResultsAPI{
		results: make(map[protocol.Bytes32]protocol.VerifierResult),
	}
	reader := newTestVerifierReader(mockVerifier, config)

	err := reader.Start(ctx)
	require.NoError(t, err)

	// Give goroutine a moment to start
	time.Sleep(10 * time.Millisecond)

	// Close should complete without blocking indefinitely
	done := make(chan bool)
	go func() {
		err := reader.Close()
		assert.NoError(t, err)
		done <- true
	}()

	select {
	case <-done:
		// Success - Close completed
	case <-time.After(2 * time.Second):
		t.Fatal("Close() did not complete within timeout")
	}

	// Verify run goroutine has finished
	reader.runWg.Wait()
}

func TestVerifierReader_Close_MultipleCalls(t *testing.T) {
	ctx := context.Background()
	config := &config.VerifierConfig{
		BatchSize:        10,
		MaxBatchWaitTime: 100,
	}

	mockVerifier := &mockVerifierResultsAPI{
		results: make(map[protocol.Bytes32]protocol.VerifierResult),
	}
	reader := newTestVerifierReader(mockVerifier, config)

	err := reader.Start(ctx)
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)

	// First close should succeed
	err1 := reader.Close()
	require.NoError(t, err1)

	// Subsequent closes should be no-ops
	err2 := reader.Close()
	require.NoError(t, err2)

	err3 := reader.Close()
	require.NoError(t, err3)
}

func TestVerifierReader_Close_WithPendingBatches(t *testing.T) {
	ctx := context.Background()
	config := &config.VerifierConfig{
		BatchSize:        10, // Large batch size so items don't auto-flush
		MaxBatchWaitTime: 200,
	}

	mockVerifier := &mockVerifierResultsAPI{
		results: make(map[protocol.Bytes32]protocol.VerifierResult),
	}
	reader := newTestVerifierReader(mockVerifier, config)

	err := reader.Start(ctx)
	require.NoError(t, err)

	// Add a message that won't trigger a batch immediately
	messageID := protocol.Bytes32{1, 2, 3}
	resultCh, err := reader.ProcessMessage(messageID)
	require.NoError(t, err)

	// Close immediately - should gracefully handle pending message
	err = reader.Close()
	require.NoError(t, err)

	// Wait a bit for any final processing
	time.Sleep(50 * time.Millisecond)

	// The result channel should eventually receive a result or be closed
	// (depending on whether the batch was processed before Close)
	select {
	case result, ok := <-resultCh:
		if ok {
			// Got a result, that's fine
			_ = result
		}
		// Channel closed, also fine
	default:
		// No result yet, also acceptable - the message may be in the batcher's buffer
	}
}

func TestVerifierReader_Run_ChannelClosed(t *testing.T) {
	ctx := context.Background()

	config := &config.VerifierConfig{
		BatchSize:        10,
		MaxBatchWaitTime: 100,
	}

	mockVerifier := &mockVerifierResultsAPI{
		results: make(map[protocol.Bytes32]protocol.VerifierResult),
	}
	reader := NewVerifierReader(ctx, mockVerifier, config)

	err := reader.Start(ctx)
	require.NoError(t, err)

	// Cancel the batcher's context, which will cause it to close batchCh
	// This tests the channel-closed path in run()
	if reader.batcherCancel != nil {
		reader.batcherCancel()
	}

	// Close the batcher, which waits for its goroutine to finish
	err = reader.batcher.Close()
	require.NoError(t, err)

	// Wait for run goroutine to finish
	reader.runWg.Wait()
}

func waitTimeout(t *testing.T) time.Duration {
	deadline, ok := t.Deadline()
	if !ok {
		deadline = time.Now().Add(10 * time.Second)
	}
	return time.Until(deadline)
}
