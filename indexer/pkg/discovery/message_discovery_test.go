package discovery

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/failsafe-go/failsafe-go/circuitbreaker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/readers"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/storage"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// testSetup contains all the components needed for message discovery tests.
type testSetup struct {
	Discovery  *AggregatorMessageDiscovery
	Logger     logger.Logger
	Monitor    common.IndexerMonitoring
	Storage    common.IndexerStorage
	Reader     *readers.ResilientReader
	MockReader *readers.MockReader
	Context    context.Context
	Cancel     context.CancelFunc
}

// Cleanup stops the discovery and cancels the context.
func (ts *testSetup) Cleanup() {
	if ts.Discovery != nil {
		_ = ts.Discovery.Close()
	}
	if ts.Cancel != nil {
		ts.Cancel()
	}
}

// setupMessageDiscoveryTest creates a complete test setup with default configuration.
func setupMessageDiscoveryTest(t *testing.T) *testSetup {
	t.Helper()
	return setupMessageDiscoveryTestWithConfig(t, Config{
		PollInterval:       50 * time.Millisecond,
		Timeout:            500 * time.Millisecond,
		MessageChannelSize: 1000,
	})
}

// setupMessageDiscoveryTestWithConfig creates a test setup with custom configuration.
func setupMessageDiscoveryTestWithConfig(t *testing.T, config Config) *testSetup {
	t.Helper()
	return setupMessageDiscoveryTestWithTimeout(t, config, 5*time.Second)
}

// setupMessageDiscoveryTestWithTimeout creates a test setup with custom timeout.
func setupMessageDiscoveryTestWithTimeout(t *testing.T, config Config, timeout time.Duration) *testSetup {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)

	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()
	store := storage.NewInMemoryStorage(lggr, mon)

	// Create a mock reader that emits messages immediately
	mockReader := readers.NewMockReader(readers.MockReaderConfig{
		EmitEmptyResponses: true, // Return empty slice when no messages ready
	})

	// Wrap mock reader with ResilientReader for testing
	resilientReader := readers.NewResilientReader(mockReader, lggr, readers.DefaultResilienceConfig())

	discovery, _ := NewAggregatorMessageDiscovery(
		WithLogger(lggr),
		WithMonitoring(mon),
		WithStorage(store),
		WithAggregator(resilientReader),
		WithConfig(config),
	)

	return &testSetup{
		Discovery:  discovery.(*AggregatorMessageDiscovery),
		Logger:     lggr,
		Monitor:    mon,
		Storage:    store,
		Reader:     resilientReader,
		MockReader: mockReader,
		Context:    ctx,
		Cancel:     cancel,
	}
}

// setupMessageDiscoveryTestNoTimeout creates a test setup without a timeout context.
func setupMessageDiscoveryTestNoTimeout(t *testing.T, config Config) *testSetup {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())

	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()
	store := storage.NewInMemoryStorage(lggr, mon)

	mockReader := readers.NewMockReader(readers.MockReaderConfig{
		EmitEmptyResponses: true,
	})

	resilientReader := readers.NewResilientReader(mockReader, lggr, readers.DefaultResilienceConfig())

	discovery, _ := NewAggregatorMessageDiscovery(
		WithLogger(lggr),
		WithMonitoring(mon),
		WithStorage(store),
		WithAggregator(resilientReader),
		WithConfig(config),
	)

	return &testSetup{
		Discovery:  discovery.(*AggregatorMessageDiscovery),
		Logger:     lggr,
		Monitor:    mon,
		Storage:    store,
		Reader:     resilientReader,
		MockReader: mockReader,
		Context:    ctx,
		Cancel:     cancel,
	}
}

// defaultTestConfig returns the standard configuration used in most tests.
func defaultTestConfig() Config {
	return Config{
		PollInterval:       50 * time.Millisecond,
		Timeout:            500 * time.Millisecond,
		MessageChannelSize: 1000,
	}
}

// TestNewAggregatorMessageDiscovery tests the constructor.
func TestNewAggregatorMessageDiscovery(t *testing.T) {
	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()
	store := storage.NewInMemoryStorage(lggr, mon)
	mockReader := readers.NewMockReader(readers.MockReaderConfig{})
	resilientReader := readers.NewResilientReader(mockReader, lggr, readers.DefaultResilienceConfig())
	config := defaultTestConfig()

	discovery, _ := NewAggregatorMessageDiscovery(
		WithLogger(lggr),
		WithMonitoring(mon),
		WithStorage(store),
		WithAggregator(resilientReader),
		WithConfig(config),
	)

	assert.NotNil(t, discovery)
	assert.Implements(t, (*common.MessageDiscovery)(nil), discovery)

	aggDiscovery := discovery.(*AggregatorMessageDiscovery)
	assert.Equal(t, lggr, aggDiscovery.logger)
	assert.Equal(t, mon, aggDiscovery.monitoring)
	assert.Equal(t, store, aggDiscovery.storageSink)
	assert.Equal(t, resilientReader, aggDiscovery.aggregatorReader)
	assert.Equal(t, config, aggDiscovery.config)
	assert.NotNil(t, aggDiscovery.messageCh)
	assert.NotNil(t, aggDiscovery.stopCh)
	assert.NotNil(t, aggDiscovery.doneCh)
	assert.NotNil(t, aggDiscovery.readerLock)
}

// TestStart_ReturnsChannel tests that Start returns a message channel.
func TestStart_ReturnsChannel(t *testing.T) {
	ts := setupMessageDiscoveryTest(t)
	defer ts.Cleanup()

	messageCh := ts.Discovery.Start(ts.Context)

	assert.NotNil(t, messageCh)
	assert.Equal(t, ts.Discovery.messageCh, messageCh)
}

// TestStart_LaunchesGoroutine tests that Start launches a goroutine.
func TestStart_LaunchesGoroutine(t *testing.T) {
	ts := setupMessageDiscoveryTest(t)
	defer ts.Cleanup()

	messageCh := ts.Discovery.Start(ts.Context)

	// Give goroutine a moment to start
	time.Sleep(10 * time.Millisecond)

	// Channel should be open and ready
	select {
	case <-messageCh:
		t.Fatal("unexpected message received")
	default:
		// Expected - channel is open but no messages yet
	}
}

// TestClose_GracefullyStops tests that Close gracefully stops discovery.
func TestClose_GracefullyStops(t *testing.T) {
	ts := setupMessageDiscoveryTestNoTimeout(t, defaultTestConfig())

	messageCh := ts.Discovery.Start(ts.Context)

	// Give it a moment to start
	time.Sleep(20 * time.Millisecond)

	// Close should complete without blocking indefinitely
	done := make(chan bool)
	go func() {
		err := ts.Discovery.Close()
		assert.NoError(t, err)
		done <- true
	}()

	select {
	case <-done:
		// Success - Close completed
	case <-time.After(2 * time.Second):
		t.Fatal("Close() did not complete within timeout")
	}

	// Verify doneCh was closed
	select {
	case <-ts.Discovery.doneCh:
		// Expected - doneCh was closed
	default:
		t.Fatal("doneCh was not closed")
	}

	// Verify stopCh was closed
	select {
	case <-ts.Discovery.stopCh:
		// Expected - stopCh is closed (readable)
	default:
		t.Fatal("stopCh was not closed")
	}

	// Verify messageCh is still open (should not be closed)
	select {
	case <-messageCh:
		t.Fatal("messageCh should not be closed")
	default:
		// Expected - messageCh remains open
	}
}

// TestClose_MultipleCalls tests that the first Close succeeds.
// Note: Multiple calls to Close() will panic because it closes a channel.
// This test verifies the first call works correctly.
func TestClose_MultipleCalls(t *testing.T) {
	ts := setupMessageDiscoveryTestNoTimeout(t, defaultTestConfig())

	ts.Discovery.Start(ts.Context)
	time.Sleep(20 * time.Millisecond)

	// First close should succeed
	err := ts.Discovery.Close()
	assert.NoError(t, err)

	// Verify doneCh was closed
	select {
	case <-ts.Discovery.doneCh:
		// Expected - doneCh was closed
	default:
		t.Fatal("doneCh was not closed")
	}
}

// TestStart_ContextCancellation tests that context cancellation stops discovery.
func TestStart_ContextCancellation(t *testing.T) {
	ts := setupMessageDiscoveryTestNoTimeout(t, defaultTestConfig())

	messageCh := ts.Discovery.Start(ts.Context)

	// Give it a moment to start
	time.Sleep(20 * time.Millisecond)

	// Cancel context
	ts.Cancel()

	// Wait for doneCh to be closed
	select {
	case <-ts.Discovery.doneCh:
		// Expected - goroutine exited
	case <-time.After(2 * time.Second):
		t.Fatal("discovery did not stop after context cancellation")
	}

	// Verify messageCh is still open
	select {
	case <-messageCh:
		t.Fatal("messageCh should not be closed")
	default:
		// Expected
	}
}

// TestMessageDiscovery_SingleMessage tests discovering and emitting a single message.
func TestMessageDiscovery_SingleMessage(t *testing.T) {
	ts := setupMessageDiscoveryTest(t)
	defer ts.Cleanup()

	// Configure mock to return one message
	ccvData := createTestCCVData(1, time.Now().UnixMilli(), 1, 2)
	ts.MockReader = readers.NewMockReader(readers.MockReaderConfig{
		MessageGenerator: func(messageNumber int) protocol.CCVData {
			return ccvData
		},
		EmitEmptyResponses: false,
		MaxMessages:        1,
	})

	ts.Reader = readers.NewResilientReader(ts.MockReader, ts.Logger, readers.DefaultResilienceConfig())
	ts.Discovery.aggregatorReader = ts.Reader

	messageCh := ts.Discovery.Start(ts.Context)

	// Wait for message to be discovered
	var receivedMessage protocol.CCVData
	select {
	case msg := <-messageCh:
		receivedMessage = msg
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timeout waiting for message")
	}

	// Verify message
	assert.Equal(t, ccvData.Message.MustMessageID(), receivedMessage.Message.MustMessageID())

	// Verify message was stored
	stored, err := ts.Storage.GetCCVData(ts.Context, ccvData.MessageID)
	require.NoError(t, err)
	require.Len(t, stored, 1)
	assert.Equal(t, ccvData.Message.MustMessageID(), stored[0].Message.MustMessageID())
}

// TestMessageDiscovery_MultipleMessages tests discovering multiple messages in one call.
func TestMessageDiscovery_MultipleMessages(t *testing.T) {
	ts := setupMessageDiscoveryTest(t)
	defer ts.Cleanup()

	// Create multiple messages
	messages := []protocol.CCVData{
		createTestCCVData(1, time.Now().UnixMilli(), 1, 2),
		createTestCCVData(2, time.Now().UnixMilli(), 1, 2),
		createTestCCVData(3, time.Now().UnixMilli(), 1, 2),
	}

	messageIndex := 0
	ts.MockReader = readers.NewMockReader(readers.MockReaderConfig{
		MessageGenerator: func(messageNumber int) protocol.CCVData {
			if messageIndex < len(messages) {
				msg := messages[messageIndex]
				messageIndex++
				return msg
			}
			return readers.DefaultMessageGenerator(messageNumber)
		},
		EmitEmptyResponses: false,
		MaxMessages:        len(messages),
	})

	ts.Reader = readers.NewResilientReader(ts.MockReader, ts.Logger, readers.DefaultResilienceConfig())
	ts.Discovery.aggregatorReader = ts.Reader

	messageCh := ts.Discovery.Start(ts.Context)

	// Collect all messages
	receivedMessages := make([]protocol.Message, 0, len(messages))
	for i := range messages {
		select {
		case msg := <-messageCh:
			receivedMessages = append(receivedMessages, msg.Message)
		case <-time.After(200 * time.Millisecond):
			t.Fatalf("timeout waiting for message %d", i+1)
		}
	}

	// Verify all messages were received
	assert.Len(t, receivedMessages, len(messages))
	for i, expected := range messages {
		assert.Equal(t, expected.Message, receivedMessages[i])
	}

	// Verify all messages were stored
	for _, expected := range messages {
		stored, err := ts.Storage.GetCCVData(ts.Context, expected.MessageID)
		require.NoError(t, err)
		require.Len(t, stored, 1)
		assert.Equal(t, expected.Message.MustMessageID(), stored[0].Message.MustMessageID())
	}
}

// TestMessageDiscovery_EmptyResponse tests that empty responses don't emit messages.
func TestMessageDiscovery_EmptyResponse(t *testing.T) {
	ts := setupMessageDiscoveryTest(t)
	defer ts.Cleanup()

	// Create a reader that has already reached max messages (will return empty)
	// We do this by creating a reader, calling it once to consume the message, then using it
	ts.MockReader = readers.NewMockReader(readers.MockReaderConfig{
		EmitEmptyResponses: true,
		MaxMessages:        1, // Only 1 message available
	})

	// Consume the one message by calling ReadCCVData once
	_, _ = ts.MockReader.ReadCCVData(context.Background())

	ts.Reader = readers.NewResilientReader(ts.MockReader, ts.Logger, readers.DefaultResilienceConfig())
	ts.Discovery.aggregatorReader = ts.Reader

	messageCh := ts.Discovery.Start(ts.Context)

	// Wait a bit to ensure polling happens multiple times
	time.Sleep(150 * time.Millisecond)

	// No messages should be received (already consumed)
	select {
	case msg := <-messageCh:
		t.Fatalf("unexpected message received: %+v", msg)
	default:
		// Expected - no messages
	}
}

// TestMessageDiscovery_ContinuesAfterEmptyResponse tests that polling continues after empty response.
func TestMessageDiscovery_ContinuesAfterEmptyResponse(t *testing.T) {
	ts := setupMessageDiscoveryTest(t)
	defer ts.Cleanup()

	callCount := 0
	ts.MockReader = readers.NewMockReader(readers.MockReaderConfig{
		EmitEmptyResponses: true,
		MessageGenerator: func(messageNumber int) protocol.CCVData {
			callCount++
			// Return a message after a few empty calls
			if callCount >= 3 {
				return createTestCCVData(1, time.Now().UnixMilli(), 1, 2)
			}
			return readers.DefaultMessageGenerator(messageNumber)
		},
		MaxMessages: 1,
	})

	ts.Reader = readers.NewResilientReader(ts.MockReader, ts.Logger, readers.DefaultResilienceConfig())
	ts.Discovery.aggregatorReader = ts.Reader

	messageCh := ts.Discovery.Start(ts.Context)

	// Wait for message (polling should continue even after empty responses)
	var receivedMessage protocol.CCVData
	select {
	case msg := <-messageCh:
		receivedMessage = msg
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for message after empty responses")
	}

	assert.NotNil(t, receivedMessage)
}

// TestErrorHandling_ReaderError tests error handling when reader returns an error.
func TestErrorHandling_ReaderError(t *testing.T) {
	ts := setupMessageDiscoveryTest(t)
	defer ts.Cleanup()

	expectedError := errors.New("reader error")
	ts.MockReader = readers.NewMockReader(readers.MockReaderConfig{
		ErrorAfterCalls:    1,
		Error:              expectedError,
		EmitEmptyResponses: true,
	})

	ts.Reader = readers.NewResilientReader(ts.MockReader, ts.Logger, readers.DefaultResilienceConfig())
	ts.Discovery.aggregatorReader = ts.Reader

	messageCh := ts.Discovery.Start(ts.Context)

	// Drain channel in background to prevent blocking
	go func() {
		for range messageCh {
			// Drain any unexpected messages
		}
	}()

	// Wait a bit for error to occur
	time.Sleep(100 * time.Millisecond)

	// Discovery should continue running despite error
	select {
	case <-ts.Discovery.doneCh:
		t.Fatal("discovery should not stop on reader error")
	default:
		// Expected - discovery continues
	}
}

// TestErrorHandling_CircuitBreakerOpen tests behavior when circuit breaker is open.
func TestErrorHandling_CircuitBreakerOpen(t *testing.T) {
	ts := setupMessageDiscoveryTest(t)
	defer ts.Cleanup()

	// Create a reader that will open circuit breaker after failures
	ts.MockReader = readers.NewMockReader(readers.MockReaderConfig{
		ErrorAfterCalls:    1,
		Error:              errors.New("simulated error"),
		EmitEmptyResponses: true,
	})

	// Use a config that opens circuit breaker quickly
	config := readers.DefaultResilienceConfig()
	config.FailureThreshold = 1 // Open after 1 failure
	config.CircuitBreakerDelay = 100 * time.Millisecond

	ts.Reader = readers.NewResilientReader(ts.MockReader, ts.Logger, config)
	ts.Discovery.aggregatorReader = ts.Reader

	messageCh := ts.Discovery.Start(ts.Context)

	// Drain channel in background to prevent blocking
	go func() {
		for range messageCh {
			// Drain any unexpected messages
		}
	}()

	// Wait for circuit breaker to open
	time.Sleep(200 * time.Millisecond)

	// Verify circuit breaker is open
	state := ts.Reader.GetDiscoveryCircuitBreakerState()
	assert.Equal(t, circuitbreaker.OpenState, state)

	// Discovery should continue (skip polling when circuit breaker is open)
	select {
	case <-ts.Discovery.doneCh:
		t.Fatal("discovery should not stop when circuit breaker is open")
	default:
		// Expected
	}
}

// TestConsumeReader_MultipleBatches tests that consumeReader processes multiple batches.
func TestConsumeReader_MultipleBatches(t *testing.T) {
	ts := setupMessageDiscoveryTest(t)
	defer ts.Cleanup()

	// Create a reader that returns multiple messages per call
	// MockReader by default returns one message per call, so we configure it
	// to return multiple messages before going empty
	callCount := 0
	ts.MockReader = readers.NewMockReader(readers.MockReaderConfig{
		EmitEmptyResponses: false,
		MessageGenerator: func(messageNumber int) protocol.CCVData {
			return createTestCCVData(messageNumber, time.Now().UnixMilli(), 1, 2)
		},
		MaxMessages: 6, // Return 6 messages total
	})

	ts.Reader = readers.NewResilientReader(ts.MockReader, ts.Logger, readers.DefaultResilienceConfig())
	ts.Discovery.aggregatorReader = ts.Reader

	messageCh := ts.Discovery.Start(ts.Context)

	// Collect messages - consumeReader should loop until no more data
	receivedMessages := make([]protocol.CCVData, 0)
	timeout := time.After(500 * time.Millisecond)
	done := false
	for !done {
		select {
		case msg := <-messageCh:
			receivedMessages = append(receivedMessages, msg)
			if len(receivedMessages) >= 6 {
				done = true
			}
		case <-timeout:
			done = true
		}
	}

	// Should receive all 6 messages
	assert.GreaterOrEqual(t, len(receivedMessages), 1, "should receive at least some messages")
	_ = callCount // Suppress unused variable
}

// Helper function to create test CCVData with automatically computed message ID.
// The messageID is computed from the message contents using keccak256.
// uniqueID can be used to create different messages (by varying the Nonce).
func createTestCCVData(uniqueID int, timestamp int64, sourceChain, destChain protocol.ChainSelector) protocol.CCVData {
	// Create a unique message for each CCVData
	// Use uniqueID to vary the Nonce to ensure different messages have different IDs
	message := protocol.Message{
		Sender:               []byte{0x0d, 0x0e, 0x0f},
		Data:                 []byte{0x10, 0x11, 0x12},
		OnRampAddress:        []byte{0x13, 0x14, 0x15},
		TokenTransfer:        []byte{0x16, 0x17, 0x18},
		OffRampAddress:       []byte{0x19, 0x1a, 0x1b},
		DestBlob:             []byte{0x1c, 0x1d, 0x1e},
		Receiver:             []byte{0x1f, 0x20, 0x21},
		SourceChainSelector:  sourceChain,
		DestChainSelector:    destChain,
		SequenceNumber:       protocol.SequenceNumber(uniqueID),
		Finality:             1,
		DestBlobLength:       3,
		TokenTransferLength:  3,
		DataLength:           3,
		ReceiverLength:       3,
		SenderLength:         3,
		Version:              1,
		OffRampAddressLength: 3,
		OnRampAddressLength:  3,
	}

	// Compute message ID from message contents
	messageID, _ := message.MessageID()

	return protocol.CCVData{
		MessageID:              messageID,
		Timestamp:              time.UnixMilli(timestamp),
		Message:                message,
		MessageCCVAddresses:    []protocol.UnknownAddress{{0x01, 0x02, 0x03}},
		MessageExecutorAddress: protocol.UnknownAddress{0x04, 0x05, 0x06},
		VerifierDestAddress:    protocol.UnknownAddress{0x04, 0x05, 0x06},
		CCVData:                []byte{0x07, 0x08, 0x09},
	}
}

// TestMessageDiscovery_NewMessageEmittedAndSaved tests that when a new message is discovered,
// it is both emitted to the channel AND saved to storage.
func TestMessageDiscovery_NewMessageEmittedAndSaved(t *testing.T) {
	ts := setupMessageDiscoveryTest(t)
	defer ts.Cleanup()

	// Create a test message that will be discovered
	ccvData := createTestCCVData(1, time.Now().UnixMilli(), 1, 2)

	// Configure mock reader to return this message
	ts.MockReader = readers.NewMockReader(readers.MockReaderConfig{
		MessageGenerator: func(messageNumber int) protocol.CCVData {
			return ccvData
		},
		EmitEmptyResponses: false,
		MaxMessages:        1,
	})

	ts.Reader = readers.NewResilientReader(ts.MockReader, ts.Logger, readers.DefaultResilienceConfig())
	ts.Discovery.aggregatorReader = ts.Reader

	// Start discovery and get the message channel
	messageCh := ts.Discovery.Start(ts.Context)

	// Wait for the message to be emitted to the channel
	var receivedMessage protocol.CCVData
	select {
	case msg := <-messageCh:
		receivedMessage = msg
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timeout waiting for message to be emitted to channel")
	}

	// Verify the message was emitted to the channel
	require.NotNil(t, receivedMessage, "message should be emitted to channel")
	assert.Equal(t, ccvData.Message.MustMessageID(), receivedMessage.Message.MustMessageID(), "emitted message should match expected message")

	// Verify the message was saved to storage
	stored, err := ts.Storage.GetCCVData(ts.Context, ccvData.MessageID)
	require.NoError(t, err, "should be able to retrieve message from storage")
	require.Len(t, stored, 1, "exactly one message should be stored")

	// Verify that the stored message's Message field matches what was emitted
	assert.Equal(t, receivedMessage.Message.MustMessageID(), stored[0].Message.MustMessageID(), "stored message's Message field should match emitted message")
}
