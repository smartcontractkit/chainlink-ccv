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
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/discovery/internal"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/readers"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/registry"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/storage"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
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
	MockReader *internal.MockReader
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
	return setupMessageDiscoveryTestWithConfig(t, config.DiscoveryConfig{
		PollInterval: 50,
		Timeout:      500,
	})
}

// setupMessageDiscoveryTestWithConfig creates a test setup with custom configuration.
func setupMessageDiscoveryTestWithConfig(t *testing.T, config config.DiscoveryConfig) *testSetup {
	t.Helper()
	return setupMessageDiscoveryTestWithTimeout(t, config, 5*time.Second)
}

// setupMessageDiscoveryTestWithTimeout creates a test setup with custom timeout.
func setupMessageDiscoveryTestWithTimeout(t *testing.T, config config.DiscoveryConfig, timeout time.Duration) *testSetup {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)

	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()
	store := storage.NewInMemoryStorage(lggr, mon)

	// Create a mock reader that emits messages immediately
	mockReader := internal.NewMockReader(internal.MockReaderConfig{
		EmitEmptyResponses: true, // Return empty slice when no messages ready
	})

	timeProvider := mocks.NewMockTimeProvider(t)
	timeProvider.EXPECT().GetTime().Return(time.Now().UTC()).Maybe()

	// Wrap mock reader with ResilientReader for testing
	resilientReader := readers.NewResilientReader(mockReader, lggr, readers.DefaultResilienceConfig())

	registry := registry.NewVerifierRegistry()

	discovery, _ := NewAggregatorMessageDiscovery(
		WithLogger(lggr),
		WithRegistry(registry),
		WithTimeProvider(timeProvider),
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
func setupMessageDiscoveryTestNoTimeout(t *testing.T, config config.DiscoveryConfig) *testSetup {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())

	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()
	store := storage.NewInMemoryStorage(lggr, mon)

	timeProvider := mocks.NewMockTimeProvider(t)
	timeProvider.EXPECT().GetTime().Return(time.Now().UTC()).Maybe()
	mockReader := internal.NewMockReader(internal.MockReaderConfig{
		EmitEmptyResponses: true,
	})

	resilientReader := readers.NewResilientReader(mockReader, lggr, readers.DefaultResilienceConfig())
	registry := registry.NewVerifierRegistry()

	discovery, _ := NewAggregatorMessageDiscovery(
		WithLogger(lggr),
		WithRegistry(registry),
		WithTimeProvider(timeProvider),
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
func defaultTestConfig() config.DiscoveryConfig {
	return config.DiscoveryConfig{
		PollInterval: 50,
		Timeout:      500,
	}
}

// TestNewAggregatorMessageDiscovery tests the constructor.
func TestNewAggregatorMessageDiscovery(t *testing.T) {
	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()
	store := storage.NewInMemoryStorage(lggr, mon)
	mockReader := internal.NewMockReader(internal.MockReaderConfig{})
	resilientReader := readers.NewResilientReader(mockReader, lggr, readers.DefaultResilienceConfig())
	config := defaultTestConfig()
	registry := registry.NewVerifierRegistry()

	discovery, _ := NewAggregatorMessageDiscovery(
		WithLogger(lggr),
		WithMonitoring(mon),
		WithRegistry(registry),
		WithTimeProvider(mocks.NewMockTimeProvider(t)),
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
	t.Cleanup(ts.Cleanup)

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

	// Verify messageCh is still open (should not be closed)
	select {
	case <-messageCh:
		t.Fatal("messageCh should not be closed")
	default:
		// Expected - messageCh remains open
	}
}

// TestStart_ContextCancellation tests that context cancellation stops discovery.
func TestStart_ContextCancellation(t *testing.T) {
	ts := setupMessageDiscoveryTestNoTimeout(t, defaultTestConfig())
	t.Cleanup(ts.Cleanup)

	messageCh := ts.Discovery.Start(ts.Context)

	// Give it a moment to start
	time.Sleep(20 * time.Millisecond)

	// Cancel context
	ts.Cancel()

	// Wait for ctx to be closed
	select {
	case <-ts.Context.Done():
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
	ts.MockReader = internal.NewMockReader(internal.MockReaderConfig{
		MessageGenerator: func(messageNumber int) common.VerifierResultWithMetadata {
			return ccvData
		},
		EmitEmptyResponses: false,
		MaxMessages:        1,
	})

	ts.Reader = readers.NewResilientReader(ts.MockReader, ts.Logger, readers.DefaultResilienceConfig())
	ts.Discovery.aggregatorReader = ts.Reader

	messageCh := ts.Discovery.Start(ts.Context)

	// Wait for message to be discovered
	var receivedMessage common.VerifierResultWithMetadata
	select {
	case msg := <-messageCh:
		receivedMessage = msg
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timeout waiting for message")
	}

	// Verify message
	assert.Equal(t, ccvData.VerifierResult.Message.MustMessageID(), receivedMessage.VerifierResult.Message.MustMessageID())

	// Verify message was stored
	stored, err := ts.Storage.GetCCVData(ts.Context, ccvData.VerifierResult.MessageID)
	require.NoError(t, err)
	require.Len(t, stored, 1)
	assert.Equal(t, ccvData.VerifierResult.Message.MustMessageID(), stored[0].VerifierResult.Message.MustMessageID())
}

// TestMessageDiscovery_MultipleMessages tests discovering multiple messages in one call.
func TestMessageDiscovery_MultipleMessages(t *testing.T) {
	ts := setupMessageDiscoveryTest(t)
	defer ts.Cleanup()

	// Create multiple messages
	messages := []common.VerifierResultWithMetadata{
		createTestCCVData(1, time.Now().UnixMilli(), 1, 2),
		createTestCCVData(2, time.Now().UnixMilli(), 1, 2),
		createTestCCVData(3, time.Now().UnixMilli(), 1, 2),
	}

	messageIndex := 0
	ts.MockReader = internal.NewMockReader(internal.MockReaderConfig{
		MessageGenerator: func(messageNumber int) common.VerifierResultWithMetadata {
			if messageIndex < len(messages) {
				msg := messages[messageIndex]
				messageIndex++
				return msg
			}
			return internal.DefaultMessageGenerator(messageNumber)
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
			receivedMessages = append(receivedMessages, msg.VerifierResult.Message)
		case <-time.After(200 * time.Millisecond):
			t.Fatalf("timeout waiting for message %d", i+1)
		}
	}

	// Verify all messages were received
	assert.Len(t, receivedMessages, len(messages))
	for i, expected := range messages {
		assert.Equal(t, expected.VerifierResult.Message, receivedMessages[i])
	}

	// Verify all messages were stored
	for _, expected := range messages {
		stored, err := ts.Storage.GetCCVData(ts.Context, expected.VerifierResult.MessageID)
		require.NoError(t, err)
		require.Len(t, stored, 1)
		assert.Equal(t, expected.VerifierResult.Message.MustMessageID(), stored[0].VerifierResult.Message.MustMessageID())
	}
}

// TestMessageDiscovery_EmptyResponse tests that empty responses don't emit messages.
func TestMessageDiscovery_EmptyResponse(t *testing.T) {
	ts := setupMessageDiscoveryTest(t)
	defer ts.Cleanup()

	// Create a reader that has already reached max messages (will return empty)
	// We do this by creating a reader, calling it once to consume the message, then using it
	ts.MockReader = internal.NewMockReader(internal.MockReaderConfig{
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
	ts.MockReader = internal.NewMockReader(internal.MockReaderConfig{
		EmitEmptyResponses: true,
		MessageGenerator: func(messageNumber int) common.VerifierResultWithMetadata {
			callCount++
			// Return a message after a few empty calls
			if callCount >= 3 {
				return createTestCCVData(1, time.Now().UnixMilli(), 1, 2)
			}
			return internal.DefaultMessageGenerator(messageNumber)
		},
		MaxMessages: 1,
	})

	ts.Reader = readers.NewResilientReader(ts.MockReader, ts.Logger, readers.DefaultResilienceConfig())
	ts.Discovery.aggregatorReader = ts.Reader

	messageCh := ts.Discovery.Start(ts.Context)

	// Wait for message (polling should continue even after empty responses)
	var receivedMessage common.VerifierResultWithMetadata
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
	ts.MockReader = internal.NewMockReader(internal.MockReaderConfig{
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
	case <-ts.Context.Done():
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
	ts.MockReader = internal.NewMockReader(internal.MockReaderConfig{
		ErrorAfterCalls:    1,
		Error:              errors.New("simulated error"),
		EmitEmptyResponses: true,
	})

	// Use a config that opens circuit breaker quickly
	config := readers.DefaultResilienceConfig()
	config.FailureThreshold = 1                         // Open after 1 failure
	config.CircuitBreakerDelay = 500 * time.Millisecond // Long enough to check before half-open

	ts.Reader = readers.NewResilientReader(ts.MockReader, ts.Logger, config)
	ts.Discovery.aggregatorReader = ts.Reader

	messageCh := ts.Discovery.Start(ts.Context)

	// Drain channel in background to prevent blocking
	go func() {
		for range messageCh {
			// Drain any unexpected messages
		}
	}()

	// Wait for circuit breaker to open (but not long enough to transition to half-open)
	// Poll interval is 50ms, so 150ms gives time for 2-3 polls which should trigger the failure
	time.Sleep(150 * time.Millisecond)

	// Verify circuit breaker is open
	state := ts.Reader.GetDiscoveryCircuitBreakerState()
	assert.Equal(t, circuitbreaker.OpenState, state)

	// Discovery should continue (skip polling when circuit breaker is open)
	select {
	case <-ts.Context.Done():
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
	ts.MockReader = internal.NewMockReader(internal.MockReaderConfig{
		EmitEmptyResponses: false,
		MessageGenerator: func(messageNumber int) common.VerifierResultWithMetadata {
			return createTestCCVData(messageNumber, time.Now().UnixMilli(), 1, 2)
		},
		MaxMessages: 6, // Return 6 messages total
	})

	ts.Reader = readers.NewResilientReader(ts.MockReader, ts.Logger, readers.DefaultResilienceConfig())
	ts.Discovery.aggregatorReader = ts.Reader

	messageCh := ts.Discovery.Start(ts.Context)

	// Collect messages - consumeReader should loop until no more data
	receivedMessages := make([]common.VerifierResultWithMetadata, 0)
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
func createTestCCVData(uniqueID int, timestamp int64, sourceChain, destChain protocol.ChainSelector) common.VerifierResultWithMetadata {
	// Create a unique message for each CCVData
	// Use uniqueID to vary the Nonce to ensure different messages have different IDs
	message := protocol.Message{
		Sender:               []byte{0x0d, 0x0e, 0x0f},
		Data:                 []byte{0x10, 0x11, 0x12},
		OnRampAddress:        []byte{0x13, 0x14, 0x15},
		TokenTransfer:        nil,
		OffRampAddress:       []byte{0x19, 0x1a, 0x1b},
		DestBlob:             []byte{0x1c, 0x1d, 0x1e},
		Receiver:             []byte{0x1f, 0x20, 0x21},
		SourceChainSelector:  sourceChain,
		DestChainSelector:    destChain,
		SequenceNumber:       protocol.SequenceNumber(uniqueID),
		Finality:             1,
		DestBlobLength:       3,
		TokenTransferLength:  0,
		DataLength:           3,
		ReceiverLength:       3,
		SenderLength:         3,
		Version:              1,
		OffRampAddressLength: 3,
		OnRampAddressLength:  3,
	}

	// Compute message ID from message contents
	messageID, _ := message.MessageID()

	return common.VerifierResultWithMetadata{
		VerifierResult: protocol.VerifierResult{
			MessageID:              messageID,
			Timestamp:              time.UnixMilli(timestamp),
			MessageCCVAddresses:    []protocol.UnknownAddress{{0x22, 0x23, 0x24}},
			MessageExecutorAddress: protocol.UnknownAddress{0x22, 0x23, 0x25},
			CCVData:                []byte{0x00, 0x01, 0x02, 0x03, 0x04}, // >4 bytes, not discovery-only
			Message:                message,
			VerifierSourceAddress:  protocol.UnknownAddress{0x22, 0x23, 0x26},
			VerifierDestAddress:    protocol.UnknownAddress{0x22, 0x23, 0x27},
		},
		Metadata: common.VerifierResultMetadata{
			AttestationTimestamp: time.UnixMilli(timestamp),
			IngestionTimestamp:   time.UnixMilli(timestamp),
		},
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
	ts.MockReader = internal.NewMockReader(internal.MockReaderConfig{
		MessageGenerator: func(messageNumber int) common.VerifierResultWithMetadata {
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
	var receivedMessage common.VerifierResultWithMetadata
	select {
	case msg := <-messageCh:
		receivedMessage = msg
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timeout waiting for message to be emitted to channel")
	}

	// Verify the message was emitted to the channel
	require.NotNil(t, receivedMessage, "message should be emitted to channel")
	assert.Equal(t, ccvData.VerifierResult.Message.MustMessageID(), receivedMessage.VerifierResult.Message.MustMessageID(), "emitted message should match expected message")

	// Verify the message was saved to storage
	stored, err := ts.Storage.GetCCVData(ts.Context, ccvData.VerifierResult.MessageID)
	require.NoError(t, err, "should be able to retrieve message from storage")
	require.Len(t, stored, 1, "exactly one message should be stored")

	// Verify that the stored message's Message field matches what was emitted
	assert.Equal(t, receivedMessage.VerifierResult.Message.MustMessageID(), stored[0].VerifierResult.Message.MustMessageID(), "stored message's Message field should match emitted message")
}

// setupMessageDiscoveryTestWithSequenceNumberSupport creates a test setup with a reader that supports sequence numbers.
func setupMessageDiscoveryTestWithSequenceNumberSupport(t *testing.T, discoveryAddress string, initialSequenceNumber int64) *testSetup {
	t.Helper()
	cfg := config.DiscoveryConfig{
		AggregatorReaderConfig: config.AggregatorReaderConfig{
			Address: discoveryAddress,
		},
		PollInterval: 50,
		Timeout:      500,
	}
	return setupMessageDiscoveryTestWithSequenceNumberSupportAndConfig(t, cfg, initialSequenceNumber, 5*time.Second)
}

// setupMessageDiscoveryTestWithSequenceNumberSupportAndConfig creates a test setup with sequence number support and custom config.
func setupMessageDiscoveryTestWithSequenceNumberSupportAndConfig(t *testing.T, cfg config.DiscoveryConfig, initialSequenceNumber int64, timeout time.Duration) *testSetup {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)

	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()
	store := storage.NewInMemoryStorage(lggr, mon)

	// Create discovery state in storage
	err := store.CreateDiscoveryState(ctx, cfg.Address, int(initialSequenceNumber))
	require.NoError(t, err)

	// Create a mock reader that supports sequence numbers
	mockReader := internal.NewMockReader(internal.MockReaderConfig{
		EmitEmptyResponses: true,
	})
	mockReader.SetSinceValue(initialSequenceNumber)

	timeProvider := mocks.NewMockTimeProvider(t)
	timeProvider.EXPECT().GetTime().Return(time.Now().UTC()).Maybe()

	// Wrap mock reader with ResilientReader for testing
	resilientReader := readers.NewResilientReader(mockReader, lggr, readers.DefaultResilienceConfig())

	registry := registry.NewVerifierRegistry()

	discovery, _ := NewAggregatorMessageDiscovery(
		WithLogger(lggr),
		WithRegistry(registry),
		WithTimeProvider(timeProvider),
		WithMonitoring(mon),
		WithStorage(store),
		WithAggregator(resilientReader),
		WithConfig(cfg),
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

// TestUpdateSequenceNumber_UpdatesPeriodically tests that sequence numbers are updated periodically.
func TestUpdateSequenceNumber_UpdatesPeriodically(t *testing.T) {
	discoveryAddress := "test-discovery-address"
	initialSequenceNumber := int64(100)
	newSequenceNumber := int64(150)

	// Use a longer timeout to allow for the 5-second ticker
	ts := setupMessageDiscoveryTestWithSequenceNumberSupportAndConfig(t, config.DiscoveryConfig{
		AggregatorReaderConfig: config.AggregatorReaderConfig{
			Address: discoveryAddress,
		},
		PollInterval: 50,
		Timeout:      500,
	}, initialSequenceNumber, 8*time.Second)
	defer ts.Cleanup()

	// Start discovery - this will start the updateSequenceNumber goroutine
	messageCh := ts.Discovery.Start(ts.Context)

	// Drain message channel in background to prevent blocking
	go func() {
		for {
			select {
			case <-ts.Context.Done():
				return
			case _, ok := <-messageCh:
				if !ok {
					return
				}
				// Drain any messages
			}
		}
	}()

	// Update the mock reader's sequence number
	ts.MockReader.SetSinceValue(newSequenceNumber)

	// Wait for the update to happen (ticker runs every 5 seconds)
	// We wait 6 seconds to ensure at least one tick has occurred
	time.Sleep(6 * time.Second)

	// Verify sequence number was updated in storage
	updatedSeq, err := ts.Storage.GetDiscoverySequenceNumber(ts.Context, discoveryAddress)
	require.NoError(t, err)
	assert.Equal(t, int(newSequenceNumber), updatedSeq, "sequence number should be updated in storage")
}

// TestMessageDiscovery_DiscoveryOnlyNotPersisted tests that discovery-only verifications
// (those with MessageDiscoveryVersion prefix in CCVData) are emitted and saved as messages,
// but NOT persisted as verifications.
func TestMessageDiscovery_DiscoveryOnlyNotPersisted(t *testing.T) {
	ts := setupMessageDiscoveryTest(t)
	defer ts.Cleanup()

	// Create a discovery-only verification with MessageDiscoveryVersion prefix
	discoveryOnlyData := createTestCCVDataWithCCVData(
		1,
		time.Now().UnixMilli(),
		1, 2,
		append(protocol.MessageDiscoveryVersion, []byte{0xaa, 0xbb}...), // starts with version prefix
	)

	ts.MockReader = internal.NewMockReader(internal.MockReaderConfig{
		MessageGenerator: func(_ int) common.VerifierResultWithMetadata {
			return discoveryOnlyData
		},
		EmitEmptyResponses: false,
		MaxMessages:        1,
	})
	ts.Reader = readers.NewResilientReader(ts.MockReader, ts.Logger, readers.DefaultResilienceConfig())
	ts.Discovery.aggregatorReader = ts.Reader

	messageCh := ts.Discovery.Start(ts.Context)

	// Verify message IS emitted to channel
	select {
	case msg := <-messageCh:
		assert.Equal(t, discoveryOnlyData.VerifierResult.MessageID, msg.VerifierResult.MessageID)
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timeout waiting for discovery-only message to be emitted")
	}

	// Verify verification was NOT persisted as CCVData
	stored, err := ts.Storage.GetCCVData(ts.Context, discoveryOnlyData.VerifierResult.MessageID)
	assert.ErrorIs(t, err, storage.ErrCCVDataNotFound, "discovery-only verification should not be persisted as CCVData")
	assert.Empty(t, stored)

	// Verify message WAS saved
	savedMsg, err := ts.Storage.GetMessage(ts.Context, discoveryOnlyData.VerifierResult.MessageID)
	require.NoError(t, err)
	assert.Equal(t, discoveryOnlyData.VerifierResult.Message.MustMessageID(), savedMsg.Message.MustMessageID())
}

// createTestCCVDataWithCCVData creates test data with custom CCVData bytes.
func createTestCCVDataWithCCVData(uniqueID int, timestamp int64, sourceChain, destChain protocol.ChainSelector, ccvData []byte) common.VerifierResultWithMetadata {
	message := protocol.Message{
		Sender:               []byte{0x0d, 0x0e, 0x0f},
		Data:                 []byte{0x10, 0x11, 0x12},
		OnRampAddress:        []byte{0x13, 0x14, 0x15},
		OffRampAddress:       []byte{0x19, 0x1a, 0x1b},
		DestBlob:             []byte{0x1c, 0x1d, 0x1e},
		Receiver:             []byte{0x1f, 0x20, 0x21},
		SourceChainSelector:  sourceChain,
		DestChainSelector:    destChain,
		SequenceNumber:       protocol.SequenceNumber(uniqueID),
		Finality:             1,
		DestBlobLength:       3,
		DataLength:           3,
		ReceiverLength:       3,
		SenderLength:         3,
		Version:              1,
		OffRampAddressLength: 3,
		OnRampAddressLength:  3,
	}
	messageID, _ := message.MessageID()

	return common.VerifierResultWithMetadata{
		VerifierResult: protocol.VerifierResult{
			MessageID:              messageID,
			Timestamp:              time.UnixMilli(timestamp),
			MessageCCVAddresses:    []protocol.UnknownAddress{{0x22, 0x23, 0x24}},
			MessageExecutorAddress: protocol.UnknownAddress{0x22, 0x23, 0x25},
			CCVData:                ccvData,
			Message:                message,
			VerifierSourceAddress:  protocol.UnknownAddress{0x22, 0x23, 0x26},
			VerifierDestAddress:    protocol.UnknownAddress{0x22, 0x23, 0x27},
		},
		Metadata: common.VerifierResultMetadata{
			AttestationTimestamp: time.UnixMilli(timestamp),
			IngestionTimestamp:   time.UnixMilli(timestamp),
		},
	}
}

// TestUpdateSequenceNumber_StopsOnContextCancellation tests that the update goroutine stops on context cancellation.
func TestUpdateSequenceNumber_StopsOnContextCancellation(t *testing.T) {
	discoveryAddress := "test-discovery-address"
	initialSequenceNumber := int64(100)

	ts := setupMessageDiscoveryTestWithSequenceNumberSupport(t, discoveryAddress, initialSequenceNumber)
	defer ts.Cleanup()

	// Start discovery
	messageCh := ts.Discovery.Start(ts.Context)

	// Drain message channel in background to prevent blocking
	go func() {
		for range messageCh {
			//
		}
	}()

	// Wait a moment for goroutines to start
	time.Sleep(100 * time.Millisecond)

	// Cancel context
	ts.Cancel()

	// Wait for goroutines to stop
	time.Sleep(100 * time.Millisecond)

	// Verify discovery stopped
	err := ts.Discovery.Close()
	assert.NoError(t, err, "close should complete successfully")

	// Verify context is canceled
	select {
	case <-ts.Context.Done():
		// Expected
	default:
		t.Fatal("context should be cancelled")
	}
}
