package internal

import (
	"context"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

var (
	_ protocol.OffchainStorageReader  = (*MockReader)(nil)
	_ protocol.VerifierResultsAPI     = (*MockReader)(nil)
	_ protocol.DiscoveryStorageReader = (*MockReader)(nil)
)

// MockReaderConfig configures the behavior of the mock reader.
type MockReaderConfig struct {
	// MessageGenerator is a function that generates CCVData for the mock reader.
	// If nil, a default generator will be used.
	// The parameter is the message number (1-indexed), not the call count.
	MessageGenerator func(messageNumber int) common.VerifierResultWithMetadata

	// EmitInterval is the interval at which messages should be emitted.
	// If zero, messages are emitted on every call to ReadCCVData.
	EmitInterval time.Duration

	// MaxMessages is the maximum number of messages to emit before signaling disconnection.
	// If zero, the reader will emit messages indefinitely.
	MaxMessages int

	// ErrorAfterCalls will cause ReadCCVData to return an error after the specified number of calls.
	// If zero, no error will be returned.
	ErrorAfterCalls int

	// Error is the error to return when ErrorAfterCalls is reached.
	Error error

	// EmitEmptyResponses controls whether to return empty responses when no message is ready.
	// If false, the reader will block/wait until a message is ready.
	// If true, the reader will return an empty slice immediately.
	EmitEmptyResponses bool

	// LatencyGenerator is a function that returns a latency duration to simulate read delays.
	// If nil, no latency is added. Use DefaultLatencyGenerator for a uniform distribution.
	LatencyGenerator func() time.Duration

	// MinLatency is the minimum latency for the default latency generator.
	// Only used if LatencyGenerator is nil and MinLatency > 0.
	MinLatency time.Duration

	// MaxLatency is the maximum latency for the default latency generator.
	// Only used if LatencyGenerator is nil and MaxLatency > MinLatency.
	MaxLatency time.Duration
}

// MockReader is a mock implementation of OffchainStorageReader for testing.
// It emits messages at a configurable interval and can be configured to disconnect
// after a certain number of messages. When EmitInterval is set, it will emit multiple
// messages in a single call if enough time has passed since the last call.
type MockReader struct {
	config          MockReaderConfig
	mu              sync.Mutex
	callCount       int
	messagesEmitted int
	lastEmitTime    time.Time
	lastCallTime    time.Time
	sinceValue      int64 // Latest sequence number for GetSinceValue()
}

// NewMockReader creates a new mock reader with the given configuration.
func NewMockReader(config MockReaderConfig) *MockReader {
	// Set default message generator if not provided
	if config.MessageGenerator == nil {
		config.MessageGenerator = DefaultMessageGenerator
	}

	// Set up default latency generator if min/max latency is configured
	if config.LatencyGenerator == nil && config.MinLatency > 0 && config.MaxLatency > config.MinLatency {
		config.LatencyGenerator = NewUniformLatencyGenerator(config.MinLatency, config.MaxLatency)
	}

	return &MockReader{
		config: config,
		// Initialize lastEmitTime to zero so the first message emits immediately
		lastEmitTime: time.Time{},
	}
}

func (m *MockReader) GetVerifications(ctx context.Context, batch []protocol.Bytes32) (map[protocol.Bytes32]protocol.VerifierResult, error) {
	return nil, nil
}

// ReadCCVData implements the OffchainStorageReader interface.
// It returns CCVData based on the configured emit interval and max messages.
// If EmitInterval is set and enough time has passed since the last call,
// it will emit multiple messages to "catch up" on missed intervals.
func (m *MockReader) ReadCCVData(ctx context.Context) ([]protocol.QueryResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.callCount++
	now := time.Now()
	m.lastCallTime = now

	// Check for error condition
	if err := m.shouldReturnError(); err != nil {
		m.addLatency()
		return nil, err
	}

	// Check if we've already reached the max messages
	if m.hasReachedMaxMessages() {
		m.addLatency()
		return []protocol.QueryResponse{}, nil
	}

	// Calculate how many messages to emit
	messagesToEmit, updatedNow := m.calculateMessagesToEmit(now)
	if messagesToEmit == 0 {
		m.addLatency()
		return []protocol.QueryResponse{}, nil
	}

	// Respect max messages limit
	messagesToEmit = m.capMessagesToEmit(messagesToEmit)

	// Generate response messages
	responses := m.generateResponses(messagesToEmit, updatedNow)

	// Update tracking state
	m.updateLastEmitTime(messagesToEmit, updatedNow)

	// Apply latency simulation if configured
	m.addLatency()

	return responses, nil
}

func (m *MockReader) addLatency() {
	if m.config.LatencyGenerator != nil {
		latency := m.config.LatencyGenerator()
		time.Sleep(latency)
	}
}

// shouldReturnError checks if an error should be returned based on call count.
func (m *MockReader) shouldReturnError() error {
	if m.config.ErrorAfterCalls > 0 && m.callCount >= m.config.ErrorAfterCalls {
		if m.config.Error != nil {
			return m.config.Error
		}
	}
	return nil
}

// hasReachedMaxMessages checks if the maximum message limit has been reached.
func (m *MockReader) hasReachedMaxMessages() bool {
	return m.config.MaxMessages > 0 && m.messagesEmitted >= m.config.MaxMessages
}

// calculateMessagesToEmit determines how many messages should be emitted based on time elapsed.
// Returns the number of messages to emit and the potentially updated current time (if sleep occurred).
func (m *MockReader) calculateMessagesToEmit(now time.Time) (int, time.Time) {
	// No interval configured, emit one message per call
	if m.config.EmitInterval == 0 {
		return 1, now
	}

	// Handle first call (lastEmitTime is zero)
	if m.lastEmitTime.IsZero() {
		return 1, now
	}

	timeSinceLastEmit := now.Sub(m.lastEmitTime)

	// Not enough time has passed
	if timeSinceLastEmit < m.config.EmitInterval {
		if m.config.EmitEmptyResponses {
			return 0, now
		}
		// Wait until the interval has passed
		sleepDuration := m.config.EmitInterval - timeSinceLastEmit
		time.Sleep(sleepDuration)
		now = time.Now()
		timeSinceLastEmit = now.Sub(m.lastEmitTime)
	}

	// Calculate how many intervals have passed
	messagesToEmit := int(timeSinceLastEmit / m.config.EmitInterval)
	if messagesToEmit == 0 {
		messagesToEmit = 1
	}

	return messagesToEmit, now
}

// capMessagesToEmit ensures the number of messages doesn't exceed the max limit.
func (m *MockReader) capMessagesToEmit(messagesToEmit int) int {
	if m.config.MaxMessages > 0 {
		remainingMessages := m.config.MaxMessages - m.messagesEmitted
		if messagesToEmit > remainingMessages {
			return remainingMessages
		}
	}
	return messagesToEmit
}

// generateResponses creates the response messages.
func (m *MockReader) generateResponses(messagesToEmit int, now time.Time) []protocol.QueryResponse {
	responses := make([]protocol.QueryResponse, 0, messagesToEmit)

	for i := range messagesToEmit {
		m.messagesEmitted++

		messageTime := m.calculateMessageTime(i, now)
		ccvData := m.config.MessageGenerator(m.messagesEmitted)
		timestamp := messageTime.UnixMilli()

		response := protocol.QueryResponse{
			Timestamp: &timestamp,
			Data:      ccvData.VerifierResult,
		}
		responses = append(responses, response)
	}

	return responses
}

// calculateMessageTime determines the timestamp for a message based on its position in the batch.
func (m *MockReader) calculateMessageTime(messageIndex int, now time.Time) time.Time {
	if m.config.EmitInterval > 0 && !m.lastEmitTime.IsZero() {
		// Subsequent messages: space them by EmitInterval
		return m.lastEmitTime.Add(m.config.EmitInterval * time.Duration(messageIndex+1))
	}
	// First message or no interval: use current time
	return now
}

// updateLastEmitTime updates the last emit time after messages have been generated.
func (m *MockReader) updateLastEmitTime(messagesToEmit int, now time.Time) {
	if m.config.EmitInterval > 0 {
		if m.lastEmitTime.IsZero() {
			// First emission: set to now
			m.lastEmitTime = now
		} else {
			// Subsequent emissions: advance by the number of intervals
			m.lastEmitTime = m.lastEmitTime.Add(m.config.EmitInterval * time.Duration(messagesToEmit))
		}
	} else {
		m.lastEmitTime = now
	}
}

// GetCallCount returns the number of times ReadCCVData has been called.
// This is useful for testing and verification.
func (m *MockReader) GetCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount
}

// GetMessagesEmitted returns the number of messages that have been emitted.
// This is useful for testing and verification.
func (m *MockReader) GetMessagesEmitted() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.messagesEmitted
}

// GetSinceValue returns the latest sequence number.
// This implements protocol.DiscoveryStorageReader interface.
// Returns 0 if not set. Use SetSinceValue to configure it.
func (m *MockReader) GetSinceValue() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sinceValue
}

// SetSinceValue sets the sequence number that will be returned by GetSinceValue.
// This is useful for testing sequence number updates.
func (m *MockReader) SetSinceValue(value int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sinceValue = value
}

// DefaultMessageGenerator is the default message generator function.
// It creates a simple CCVData with predictable values for testing.
// The parameter represents the message number (not call count).
func DefaultMessageGenerator(messageNumber int) common.VerifierResultWithMetadata {
	sourceAddr, _ := protocol.RandomAddress()
	destAddr, _ := protocol.RandomAddress()
	onRampAddr, _ := protocol.RandomAddress()
	offRampAddr, _ := protocol.RandomAddress()
	sender, _ := protocol.RandomAddress()
	receiver, _ := protocol.RandomAddress()

	// #nosec G115 -- integer conversions are safe: messageNumber is controlled
	message := protocol.Message{
		Version:              protocol.MessageVersion,
		SourceChainSelector:  protocol.ChainSelector(1),
		DestChainSelector:    protocol.ChainSelector(2),
		SequenceNumber:       protocol.SequenceNumber(messageNumber),
		OnRampAddressLength:  uint8(len(onRampAddr)),
		OnRampAddress:        onRampAddr,
		OffRampAddressLength: uint8(len(offRampAddr)),
		OffRampAddress:       offRampAddr,
		Finality:             10,
		SenderLength:         uint8(len(sender)),
		Sender:               sender,
		ReceiverLength:       uint8(len(receiver)),
		Receiver:             receiver,
		DataLength:           0,
		Data:                 []byte{},
		TokenTransferLength:  0,
		TokenTransfer:        nil,
		DestBlobLength:       0,
		DestBlob:             []byte{},
	}

	messageID, _ := message.MessageID()

	return common.VerifierResultWithMetadata{
		VerifierResult: protocol.VerifierResult{
			VerifierSourceAddress:  sourceAddr,
			VerifierDestAddress:    destAddr,
			Message:                message,
			MessageID:              messageID,
			CCVData:                []byte{},
			MessageCCVAddresses:    []protocol.UnknownAddress{},
			MessageExecutorAddress: protocol.UnknownAddress{},
			Timestamp:              time.Now(),
		},
		Metadata: common.VerifierResultMetadata{
			AttestationTimestamp: time.Now(),
			IngestionTimestamp:   time.Now(),
		},
	}
}

// NewUniformLatencyGenerator creates a latency generator that returns a random duration
// uniformly distributed between min and max latency.
func NewUniformLatencyGenerator(minLatency, maxLatency time.Duration) func() time.Duration {
	if maxLatency <= minLatency {
		// If invalid range, return constant latency
		return func() time.Duration { return minLatency }
	}

	latencyRange := maxLatency - minLatency
	return func() time.Duration {
		randomDuration := time.Duration(rand.Int64N(int64(latencyRange))) // #nosec G404 -- weak random is acceptable for test latency simulation
		return minLatency + randomDuration
	}
}

// NewConstantLatencyGenerator creates a latency generator that always returns the same latency.
func NewConstantLatencyGenerator(latency time.Duration) func() time.Duration {
	return func() time.Duration { return latency }
}
