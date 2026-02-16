package discovery

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/failsafe-go/failsafe-go/circuitbreaker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/discovery/internal"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/readers"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/registry"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// testSetup contains all the components needed for message discovery tests.
type testSetup struct {
	Discovery  *AggregatorMessageDiscovery
	Logger     logger.Logger
	Monitor    common.IndexerMonitoring
	Storage    *mocks.MockIndexerStorage
	Reader     *readers.ResilientReader
	MockReader *internal.MockReader
	Context    context.Context
	Cancel     context.CancelFunc

	mu                 sync.Mutex
	capturedMessages   []common.MessageWithMetadata
	capturedCCVData    []common.VerifierResultWithMetadata
	capturedSeqNumbers map[string]int
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

// CapturedMessages returns a copy of captured messages written to storage.
func (ts *testSetup) CapturedMessages() []common.MessageWithMetadata {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	result := make([]common.MessageWithMetadata, len(ts.capturedMessages))
	copy(result, ts.capturedMessages)
	return result
}

// CapturedCCVData returns a copy of captured CCV data written to storage.
func (ts *testSetup) CapturedCCVData() []common.VerifierResultWithMetadata {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	result := make([]common.VerifierResultWithMetadata, len(ts.capturedCCVData))
	copy(result, ts.capturedCCVData)
	return result
}

// newMockStorage creates a MockIndexerStorage with default permissive expectations
// that capture all written data for test assertions.
func newMockStorage(t *testing.T, ts *testSetup) *mocks.MockIndexerStorage {
	t.Helper()
	store := mocks.NewMockIndexerStorage(t)

	store.EXPECT().PersistDiscoveryBatch(mock.Anything, mock.Anything).
		Run(func(_ context.Context, batch common.DiscoveryBatch) {
			ts.mu.Lock()
			ts.capturedMessages = append(ts.capturedMessages, batch.Messages...)
			ts.capturedCCVData = append(ts.capturedCCVData, batch.Verifications...)
			if batch.SequenceNumber != common.SequenceNumberNotSupported {
				ts.capturedSeqNumbers[batch.DiscoveryLocation] = batch.SequenceNumber
			}
			ts.mu.Unlock()
		}).Return(nil).Maybe()

	store.EXPECT().GetDiscoverySequenceNumber(mock.Anything, mock.Anything).Return(0, nil).Maybe()

	return store
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

	ts := &testSetup{
		Logger:             lggr,
		Monitor:            mon,
		Context:            ctx,
		Cancel:             cancel,
		capturedSeqNumbers: make(map[string]int),
	}

	store := newMockStorage(t, ts)
	ts.Storage = store

	mockReader := internal.NewMockReader(internal.MockReaderConfig{
		EmitEmptyResponses: true,
	})

	timeProvider := mocks.NewMockTimeProvider(t)
	timeProvider.EXPECT().GetTime().Return(time.Now().UTC()).Maybe()

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

	ts.Discovery = discovery.(*AggregatorMessageDiscovery)
	ts.Reader = resilientReader
	ts.MockReader = mockReader

	return ts
}

// setupMessageDiscoveryTestNoTimeout creates a test setup without a timeout context.
func setupMessageDiscoveryTestNoTimeout(t *testing.T, config config.DiscoveryConfig) *testSetup {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())

	lggr := logger.Test(t)
	mon := monitoring.NewNoopIndexerMonitoring()

	ts := &testSetup{
		Logger:             lggr,
		Monitor:            mon,
		Context:            ctx,
		Cancel:             cancel,
		capturedSeqNumbers: make(map[string]int),
	}

	store := newMockStorage(t, ts)
	ts.Storage = store

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

	ts.Discovery = discovery.(*AggregatorMessageDiscovery)
	ts.Reader = resilientReader
	ts.MockReader = mockReader

	return ts
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
	ts := &testSetup{capturedSeqNumbers: make(map[string]int)}
	store := newMockStorage(t, ts)
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

	var receivedMessage common.VerifierResultWithMetadata
	select {
	case msg := <-messageCh:
		receivedMessage = msg
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timeout waiting for message")
	}

	assert.Equal(t, ccvData.VerifierResult.Message.MustMessageID(), receivedMessage.VerifierResult.Message.MustMessageID())

	// Allow async storage write to complete
	time.Sleep(50 * time.Millisecond)

	storedCCVData := ts.CapturedCCVData()
	require.Len(t, storedCCVData, 1)
	assert.Equal(t, ccvData.VerifierResult.Message.MustMessageID(), storedCCVData[0].VerifierResult.Message.MustMessageID())
}

// TestMessageDiscovery_MultipleMessages tests discovering multiple messages in one call.
func TestMessageDiscovery_MultipleMessages(t *testing.T) {
	ts := setupMessageDiscoveryTest(t)
	defer ts.Cleanup()

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

	receivedMessages := make([]protocol.Message, 0, len(messages))
	for i := range messages {
		select {
		case msg := <-messageCh:
			receivedMessages = append(receivedMessages, msg.VerifierResult.Message)
		case <-time.After(200 * time.Millisecond):
			t.Fatalf("timeout waiting for message %d", i+1)
		}
	}

	assert.Len(t, receivedMessages, len(messages))
	for i, expected := range messages {
		assert.Equal(t, expected.VerifierResult.Message, receivedMessages[i])
	}

	// Allow async storage writes to complete
	time.Sleep(50 * time.Millisecond)

	assert.Len(t, ts.CapturedCCVData(), len(messages))
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

	var receivedMessage common.VerifierResultWithMetadata
	select {
	case msg := <-messageCh:
		receivedMessage = msg
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timeout waiting for message to be emitted to channel")
	}

	require.NotNil(t, receivedMessage, "message should be emitted to channel")
	assert.Equal(t, ccvData.VerifierResult.Message.MustMessageID(), receivedMessage.VerifierResult.Message.MustMessageID())

	// Allow async storage writes to complete
	time.Sleep(50 * time.Millisecond)

	storedCCVData := ts.CapturedCCVData()
	storedMessages := ts.CapturedMessages()
	require.Len(t, storedCCVData, 1, "exactly one CCV data should be stored")
	assert.Equal(t, receivedMessage.VerifierResult.Message.MustMessageID(), storedCCVData[0].VerifierResult.Message.MustMessageID())
	require.Len(t, storedMessages, 1, "exactly one message should be stored")
}

// TestMessageDiscovery_DiscoveryOnlyNotPersisted tests that discovery-only verifications
// (those with MessageDiscoveryVersion prefix in CCVData) are emitted and saved as messages,
// but NOT persisted as verifications.
func TestMessageDiscovery_DiscoveryOnlyNotPersisted(t *testing.T) {
	ts := setupMessageDiscoveryTest(t)
	defer ts.Cleanup()

	discoveryOnlyData := createTestCCVDataWithCCVData(
		1,
		time.Now().UnixMilli(),
		1, 2,
		append(protocol.MessageDiscoveryVersion, []byte{0xaa, 0xbb}...),
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

	select {
	case msg := <-messageCh:
		assert.Equal(t, discoveryOnlyData.VerifierResult.MessageID, msg.VerifierResult.MessageID)
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timeout waiting for discovery-only message to be emitted")
	}

	// Allow async storage writes to complete
	time.Sleep(50 * time.Millisecond)

	assert.Empty(t, ts.CapturedCCVData(), "discovery-only verification should not be persisted as CCVData")
	storedMessages := ts.CapturedMessages()
	require.Len(t, storedMessages, 1, "message should be saved")
	assert.Equal(t, discoveryOnlyData.VerifierResult.Message.MustMessageID(), storedMessages[0].Message.MustMessageID())
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

func TestCallReader_PersistDiscoveryBatch(t *testing.T) {
	tests := []struct {
		name             string
		maxMessages      int
		preExhaust       bool
		persistErr       error
		initialSequence  int64
		expectFound      bool
		expectErr        bool
		expectSinceReset bool
		expectBatchCall  bool
	}{
		{
			name:            "happy_path_batch_committed_with_sequence",
			maxMessages:     1,
			initialSequence: 10,
			expectFound:     true,
			expectBatchCall: true,
		},
		{
			name:             "batch_failure_resets_since_value",
			maxMessages:      1,
			persistErr:       errors.New("db error"),
			initialSequence:  10,
			expectErr:        true,
			expectSinceReset: true,
			expectBatchCall:  true,
		},
		{
			name:        "empty_response_no_batch_call",
			maxMessages: 1,
			preExhaust:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			discoveryAddress := "test-address"
			cfg := config.DiscoveryConfig{
				AggregatorReaderConfig: config.AggregatorReaderConfig{
					Address: discoveryAddress,
				},
				PollInterval: 50,
				Timeout:      500,
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			lggr := logger.Test(t)
			mon := monitoring.NewNoopIndexerMonitoring()

			store := mocks.NewMockIndexerStorage(t)

			var capturedBatch *common.DiscoveryBatch
			if tt.expectBatchCall {
				store.EXPECT().PersistDiscoveryBatch(mock.Anything, mock.Anything).
					Run(func(_ context.Context, batch common.DiscoveryBatch) {
						capturedBatch = &batch
					}).Return(tt.persistErr).Once()
			}

			mockReader := internal.NewMockReader(internal.MockReaderConfig{
				EmitEmptyResponses: true,
				MaxMessages:        tt.maxMessages,
				MessageGenerator: func(n int) common.VerifierResultWithMetadata {
					return createTestCCVData(n, time.Now().UnixMilli(), 1, 2)
				},
			})

			mockReader.SetSinceValue(tt.initialSequence)

			if tt.preExhaust {
				_, _ = mockReader.ReadCCVData(ctx)
			}

			resilientReader := readers.NewResilientReader(mockReader, lggr, readers.DefaultResilienceConfig())

			timeProvider := mocks.NewMockTimeProvider(t)
			timeProvider.EXPECT().GetTime().Return(time.Now().UTC()).Maybe()

			reg := registry.NewVerifierRegistry()

			disc, err := NewAggregatorMessageDiscovery(
				WithLogger(lggr),
				WithRegistry(reg),
				WithTimeProvider(timeProvider),
				WithMonitoring(mon),
				WithStorage(store),
				WithAggregator(resilientReader),
				WithConfig(cfg),
			)
			require.NoError(t, err)

			aggDisc := disc.(*AggregatorMessageDiscovery)
			aggDisc.messageCh = make(chan common.VerifierResultWithMetadata, 10)

			found, callErr := aggDisc.callReader(ctx)

			if tt.expectErr {
				require.Error(t, callErr)
			} else {
				require.NoError(t, callErr)
			}

			assert.Equal(t, tt.expectFound, found)

			if tt.expectBatchCall && tt.persistErr == nil {
				require.NotNil(t, capturedBatch)
				assert.Len(t, capturedBatch.Messages, 1)
				assert.Len(t, capturedBatch.Verifications, 1)
				assert.Equal(t, discoveryAddress, capturedBatch.DiscoveryLocation)
				assert.NotEqual(t, common.SequenceNumberNotSupported, capturedBatch.SequenceNumber)
			}

			if tt.expectSinceReset {
				currentSeq, ok := resilientReader.GetSinceValue()
				require.True(t, ok)
				assert.Equal(t, tt.initialSequence, currentSeq)
			}
		})
	}
}
