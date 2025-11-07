package readers

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMockReader_EmitsMessagesImmediately(t *testing.T) {
	config := MockReaderConfig{
		EmitEmptyResponses: false,
		MaxMessages:        3,
	}

	reader := NewMockReader(config)

	ctx := context.Background()

	// Read messages
	for i := 0; i < 3; i++ {
		responses, err := reader.ReadCCVData(ctx)
		require.NoError(t, err)
		require.Len(t, responses, 1)
		assert.NotNil(t, responses[0].Timestamp)
		assert.Equal(t, protocol.Nonce(i+1), responses[0].Data.Nonce)
	}

	assert.Equal(t, 3, reader.GetMessagesEmitted())
	assert.Equal(t, 3, reader.GetCallCount())
}

func TestMockReader_EmitsMessagesWithInterval(t *testing.T) {
	config := MockReaderConfig{
		EmitInterval:       100 * time.Millisecond,
		EmitEmptyResponses: true,
		MaxMessages:        2,
	}

	reader := NewMockReader(config)
	ctx := context.Background()

	start := time.Now()

	// First call should emit immediately
	responses, err := reader.ReadCCVData(ctx)
	require.NoError(t, err)
	require.Len(t, responses, 1)

	// Second call should return empty (not enough time passed)
	responses, err = reader.ReadCCVData(ctx)
	require.NoError(t, err)
	require.Len(t, responses, 0)

	// Wait for interval
	time.Sleep(110 * time.Millisecond)

	// Third call should emit a message
	responses, err = reader.ReadCCVData(ctx)
	require.NoError(t, err)
	require.Len(t, responses, 1)

	elapsed := time.Since(start)
	assert.GreaterOrEqual(t, elapsed, 100*time.Millisecond)

	assert.Equal(t, 2, reader.GetMessagesEmitted())
	assert.Equal(t, 3, reader.GetCallCount())
}

func TestMockReader_ReturnsErrorAfterCalls(t *testing.T) {
	expectedError := errors.New("mock error")
	config := MockReaderConfig{
		ErrorAfterCalls: 2,
		Error:           expectedError,
	}

	reader := NewMockReader(config)
	ctx := context.Background()

	// First call should succeed
	_, err := reader.ReadCCVData(ctx)
	require.NoError(t, err)

	// Second call should return error
	_, err = reader.ReadCCVData(ctx)
	require.Error(t, err)
	assert.Equal(t, expectedError, err)
}

func TestMockReader_CustomMessageGenerator(t *testing.T) {
	customNonce := protocol.Nonce(999)
	customGenerator := func(callCount int) protocol.CCVData {
		return protocol.CCVData{
			Nonce: customNonce,
		}
	}

	config := MockReaderConfig{
		MessageGenerator: customGenerator,
		MaxMessages:      1,
	}

	reader := NewMockReader(config)
	ctx := context.Background()

	responses, err := reader.ReadCCVData(ctx)
	require.NoError(t, err)
	require.Len(t, responses, 1)
	assert.Equal(t, customNonce, responses[0].Data.Nonce)
}

func TestMockReader_InfiniteMessages(t *testing.T) {
	config := MockReaderConfig{
		EmitEmptyResponses: false,
		// MaxMessages not set, so it should emit indefinitely
	}

	reader := NewMockReader(config)
	ctx := context.Background()

	// Read many messages
	for i := 0; i < 10; i++ {
		responses, err := reader.ReadCCVData(ctx)
		require.NoError(t, err)
		require.Len(t, responses, 1)
	}

	assert.Equal(t, 10, reader.GetMessagesEmitted())
}

func TestMockReader_DisconnectAfterMaxMessages(t *testing.T) {
	config := MockReaderConfig{
		MaxMessages:        2,
		EmitEmptyResponses: true,
	}

	reader := NewMockReader(config)
	ctx := context.Background()

	// Read first message
	responses, err := reader.ReadCCVData(ctx)
	require.NoError(t, err)
	require.Len(t, responses, 1)

	// Read second message
	responses, err = reader.ReadCCVData(ctx)
	require.NoError(t, err)
	require.Len(t, responses, 1)

	// Next call should return empty since max messages reached
	responses, err = reader.ReadCCVData(ctx)
	require.NoError(t, err)
	require.Len(t, responses, 0)
}

func TestMockReader_TimestampIncreases(t *testing.T) {
	config := MockReaderConfig{
		MaxMessages: 3,
	}

	reader := NewMockReader(config)
	ctx := context.Background()

	var lastTimestamp int64
	for i := 0; i < 3; i++ {
		responses, err := reader.ReadCCVData(ctx)
		require.NoError(t, err)
		require.Len(t, responses, 1)
		require.NotNil(t, responses[0].Timestamp)

		if i > 0 {
			assert.GreaterOrEqual(t, *responses[0].Timestamp, lastTimestamp)
		}
		lastTimestamp = *responses[0].Timestamp
	}
}

func TestMockReader_EmitsMultipleMessagesWhenTimeHasPassed(t *testing.T) {
	config := MockReaderConfig{
		EmitInterval:       100 * time.Millisecond,
		EmitEmptyResponses: true,
		MaxMessages:        10,
	}

	reader := NewMockReader(config)
	ctx := context.Background()

	// First call should emit one message
	responses, err := reader.ReadCCVData(ctx)
	require.NoError(t, err)
	require.Len(t, responses, 1)
	assert.Equal(t, protocol.Nonce(1), responses[0].Data.Nonce)

	// Wait for 250ms (2.5 intervals)
	time.Sleep(250 * time.Millisecond)

	// Second call should emit 2 messages (for the 2 full intervals that passed)
	responses, err = reader.ReadCCVData(ctx)
	require.NoError(t, err)
	require.Len(t, responses, 2)
	assert.Equal(t, protocol.Nonce(2), responses[0].Data.Nonce)
	assert.Equal(t, protocol.Nonce(3), responses[1].Data.Nonce)

	// Verify timestamps are spaced correctly (100ms = 0.1 seconds in Unix timestamp)
	// Since we're using UnixMilli() which gives seconds, the difference should be at least 0
	// The timestamps should be increasing
	assert.GreaterOrEqual(t, *responses[1].Timestamp, *responses[0].Timestamp)

	assert.Equal(t, 3, reader.GetMessagesEmitted())
}

func TestMockReader_MultipleMessagesRespectsMaxLimit(t *testing.T) {
	config := MockReaderConfig{
		EmitInterval:       50 * time.Millisecond,
		EmitEmptyResponses: true,
		MaxMessages:        5,
	}

	reader := NewMockReader(config)
	ctx := context.Background()

	// First call - emit 1 message
	responses, err := reader.ReadCCVData(ctx)
	require.NoError(t, err)
	require.Len(t, responses, 1)

	// Wait for 10 intervals worth of time
	time.Sleep(500 * time.Millisecond)

	// Should emit 4 messages (to reach max of 5, not 10)
	responses, err = reader.ReadCCVData(ctx)
	require.NoError(t, err)
	require.Len(t, responses, 4)

	assert.Equal(t, 5, reader.GetMessagesEmitted())

	// Next call should return empty
	responses, err = reader.ReadCCVData(ctx)
	require.NoError(t, err)
	require.Len(t, responses, 0)
}

func TestMockReader_WithUniformLatency(t *testing.T) {
	minLatency := 10 * time.Millisecond
	maxLatency := 50 * time.Millisecond

	config := MockReaderConfig{
		MinLatency:  minLatency,
		MaxLatency:  maxLatency,
		MaxMessages: 5,
	}

	reader := NewMockReader(config)
	ctx := context.Background()

	// Measure latencies across multiple calls
	var latencies []time.Duration
	for i := 0; i < 5; i++ {
		start := time.Now()
		_, err := reader.ReadCCVData(ctx)
		require.NoError(t, err)
		elapsed := time.Since(start)
		latencies = append(latencies, elapsed)
	}

	// All latencies should be within the expected range (with some tolerance for execution time)
	for _, latency := range latencies {
		assert.GreaterOrEqual(t, latency, minLatency, "Latency should be >= min")
		assert.LessOrEqual(t, latency, maxLatency+10*time.Millisecond, "Latency should be <= max (with tolerance)")
	}

	// Verify we got some variation (not all the same)
	allSame := true
	firstLatency := latencies[0]
	for _, l := range latencies[1:] {
		if l != firstLatency {
			allSame = false
			break
		}
	}
	assert.False(t, allSame, "Expected variation in latencies")
}

func TestMockReader_WithConstantLatency(t *testing.T) {
	constantLatency := 20 * time.Millisecond

	config := MockReaderConfig{
		LatencyGenerator: NewConstantLatencyGenerator(constantLatency),
		MaxMessages:      3,
	}

	reader := NewMockReader(config)
	ctx := context.Background()

	// Measure latencies across multiple calls
	for i := 0; i < 3; i++ {
		start := time.Now()
		_, err := reader.ReadCCVData(ctx)
		require.NoError(t, err)
		elapsed := time.Since(start)

		// Should be approximately the constant latency (with tolerance for execution time)
		assert.GreaterOrEqual(t, elapsed, constantLatency)
		assert.LessOrEqual(t, elapsed, constantLatency+5*time.Millisecond)
	}
}

func TestMockReader_WithCustomLatencyGenerator(t *testing.T) {
	callCount := 0
	customLatency := func() time.Duration {
		callCount++
		// Increase latency with each call
		return time.Duration(callCount*5) * time.Millisecond
	}

	config := MockReaderConfig{
		LatencyGenerator: customLatency,
		MaxMessages:      3,
	}

	reader := NewMockReader(config)
	ctx := context.Background()

	// First call - 5ms latency
	start := time.Now()
	_, err := reader.ReadCCVData(ctx)
	require.NoError(t, err)
	elapsed1 := time.Since(start)
	assert.GreaterOrEqual(t, elapsed1, 5*time.Millisecond)

	// Second call - 10ms latency
	start = time.Now()
	_, err = reader.ReadCCVData(ctx)
	require.NoError(t, err)
	elapsed2 := time.Since(start)
	assert.GreaterOrEqual(t, elapsed2, 10*time.Millisecond)

	// Third call - 15ms latency
	start = time.Now()
	_, err = reader.ReadCCVData(ctx)
	require.NoError(t, err)
	elapsed3 := time.Since(start)
	assert.GreaterOrEqual(t, elapsed3, 15*time.Millisecond)

	// Verify increasing pattern
	assert.Less(t, elapsed1, elapsed2)
	assert.Less(t, elapsed2, elapsed3)
}

func TestMockReader_NoLatency(t *testing.T) {
	config := MockReaderConfig{
		MaxMessages: 3,
		// No latency configured
	}

	reader := NewMockReader(config)
	ctx := context.Background()

	// Should execute very quickly (< 5ms)
	start := time.Now()
	for i := 0; i < 3; i++ {
		_, err := reader.ReadCCVData(ctx)
		require.NoError(t, err)
	}
	totalElapsed := time.Since(start)

	assert.Less(t, totalElapsed, 10*time.Millisecond, "Without latency, calls should be very fast")
}

func TestMockReader_LatencyWithEmptyResponses(t *testing.T) {
	minLatency := 10 * time.Millisecond
	maxLatency := 20 * time.Millisecond

	config := MockReaderConfig{
		MinLatency:         minLatency,
		MaxLatency:         maxLatency,
		EmitInterval:       100 * time.Millisecond,
		EmitEmptyResponses: true,
		MaxMessages:        5,
	}

	reader := NewMockReader(config)
	ctx := context.Background()

	// First call should emit with latency
	start := time.Now()
	responses, err := reader.ReadCCVData(ctx)
	require.NoError(t, err)
	require.Len(t, responses, 1)
	elapsed := time.Since(start)
	assert.GreaterOrEqual(t, elapsed, minLatency)

	// Second call (too soon) should return empty but still have latency
	start = time.Now()
	responses, err = reader.ReadCCVData(ctx)
	require.NoError(t, err)
	require.Len(t, responses, 0)
	elapsed = time.Since(start)
	assert.GreaterOrEqual(t, elapsed, minLatency, "Latency should apply even for empty responses")
}
