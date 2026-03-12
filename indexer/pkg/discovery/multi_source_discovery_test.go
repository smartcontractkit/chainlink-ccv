package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// newMockMessageDiscoveryWithMessages returns a MockMessageDiscovery that emits the given messages
// when Start is called. The returned mock expects Close once; Start is Once() if messages are
// non-empty and Maybe() if empty (so tests that never call Start, e.g. Replay, pass).
func newMockMessageDiscoveryWithMessages(t *testing.T, messages []common.VerifierResultWithMetadata) *mocks.MockMessageDiscovery {
	t.Helper()
	mockSrc := mocks.NewMockMessageDiscovery(t)
	ch := make(chan common.VerifierResultWithMetadata, len(messages)+1)
	if len(messages) > 0 {
		mockSrc.EXPECT().Start(mock.Anything).Return(ch).Once()
		go func() {
			for _, msg := range messages {
				ch <- msg
			}
		}()
	} else {
		mockSrc.EXPECT().Start(mock.Anything).Return(ch).Maybe()
	}
	mockSrc.EXPECT().Close().Return(nil).Once()
	mockSrc.EXPECT().Replay(mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
	return mockSrc
}

// collectUntilTimeout reads from ch until no message is received for the given timeout, then returns
// all messages collected. The channel is not closed; use when the producer may send a bounded set of messages.
func collectUntilTimeout(ch <-chan common.VerifierResultWithMetadata, timeout time.Duration) []common.VerifierResultWithMetadata {
	var received []common.VerifierResultWithMetadata
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case m, ok := <-ch:
			if !ok {
				return received
			}
			received = append(received, m)
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(timeout)
		case <-timer.C:
			return received
		}
	}
}

func TestMultiSourceMessageDiscovery_Deduplication(t *testing.T) {
	// Same messageID from two sources → exactly one emitted, first received wins.
	msg := createTestCCVData(1, time.Now().UnixMilli(), 1, 2)
	msgB := createTestCCVData(1, time.Now().UnixMilli()+1, 1, 2) // same uniqueID => same messageID
	require.Equal(t, msg.VerifierResult.MessageID, msgB.VerifierResult.MessageID, "test precondition: same messageID")

	sourceA := newMockMessageDiscoveryWithMessages(t, []common.VerifierResultWithMetadata{msg})
	sourceB := newMockMessageDiscoveryWithMessages(t, []common.VerifierResultWithMetadata{msgB})

	multi, err := NewMultiSourceMessageDiscovery(
		logger.Test(t),
		[]common.MessageDiscovery{sourceA, sourceB},
	)
	require.NoError(t, err)
	defer func() { _ = multi.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out := multi.Start(ctx)

	// The goal is to check that only a single unique message is output (deduplication works).
	select {
	case m, ok := <-out:
		require.True(t, ok, "expected at least one message")
		assert.Equal(t, msg.VerifierResult.MessageID, m.VerifierResult.MessageID)
	case <-ctx.Done():
		t.Fatal("timed out waiting for message")
	}
	// Now make sure there are no more messages.
	select {
	case m := <-out:
		t.Fatalf("expected only one output, but got extra: %+v", m)
	case <-time.After(100 * time.Millisecond):
		// no more messages as expected
	}
}

func TestMultiSourceMessageDiscovery_DifferentMessageIDs(t *testing.T) {
	msg1 := createTestCCVData(1, time.Now().UnixMilli(), 1, 2)
	msg2 := createTestCCVData(2, time.Now().UnixMilli(), 1, 2)
	require.NotEqual(t, msg1.VerifierResult.MessageID, msg2.VerifierResult.MessageID)

	sourceA := newMockMessageDiscoveryWithMessages(t, []common.VerifierResultWithMetadata{msg1})
	sourceB := newMockMessageDiscoveryWithMessages(t, []common.VerifierResultWithMetadata{msg2})

	multi, err := NewMultiSourceMessageDiscovery(
		logger.Test(t),
		[]common.MessageDiscovery{sourceA, sourceB},
	)
	require.NoError(t, err)
	defer func() { _ = multi.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out := multi.Start(ctx)

	received := collectUntilTimeout(out, 500*time.Millisecond)
	assert.Len(t, received, 2, "different messageIDs should both be emitted")
	ids := make(map[protocol.Bytes32]struct{})
	for _, m := range received {
		ids[m.VerifierResult.MessageID] = struct{}{}
	}
	assert.Len(t, ids, 2)
}

func TestMultiSourceMessageDiscovery_SingleSource(t *testing.T) {
	msg1 := createTestCCVData(1, time.Now().UnixMilli(), 1, 2)
	msg2 := createTestCCVData(2, time.Now().UnixMilli(), 1, 2)
	single := newMockMessageDiscoveryWithMessages(t, []common.VerifierResultWithMetadata{msg1, msg2})

	multi, err := NewMultiSourceMessageDiscovery(
		logger.Test(t),
		[]common.MessageDiscovery{single},
	)
	require.NoError(t, err)
	defer func() { _ = multi.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out := multi.Start(ctx)

	received := collectUntilTimeout(out, 500*time.Millisecond)
	assert.Len(t, received, 2, "single source: all messages emitted")
}

func TestMultiSourceMessageDiscovery_CloseStopsAll(t *testing.T) {
	msg := createTestCCVData(1, time.Now().UnixMilli(), 1, 2)
	sourceA := newMockMessageDiscoveryWithMessages(t, []common.VerifierResultWithMetadata{msg})
	sourceB := newMockMessageDiscoveryWithMessages(t, []common.VerifierResultWithMetadata{msg})

	multi, err := NewMultiSourceMessageDiscovery(
		logger.Test(t),
		[]common.MessageDiscovery{sourceA, sourceB},
	)
	require.NoError(t, err)

	ctx := context.Background()
	_ = multi.Start(ctx)

	done := make(chan struct{})
	go func() {
		err := multi.Close()
		assert.NoError(t, err)
		close(done)
	}()
	select {
	case <-done:
		// Close completed
	case <-time.After(2 * time.Second):
		t.Fatal("Close() did not complete within timeout")
	}
}

// TestMultiSourceMessageDiscovery_FirstDiscoveryWinsExplicit verifies that when the same messageID
// is delivered by source A then source B, the emitted value is from source A (first discovery wins).
func TestMultiSourceMessageDiscovery_FirstDiscoveryWinsExplicit(t *testing.T) {
	msgA := createTestCCVData(1, 1000, 1, 2)
	msgB := createTestCCVData(1, 2000, 1, 2)
	require.Equal(t, msgA.VerifierResult.MessageID, msgB.VerifierResult.MessageID)

	// Source A sends one message, then source B sends the same messageID (we can't guarantee order
	// with two goroutines, so we use a single source that sends in order to simulate A then B).
	// To enforce order: use one mock that sends msgA then msgB; first wins should be msgA.
	source := newMockMessageDiscoveryWithMessages(t, []common.VerifierResultWithMetadata{msgA, msgB})
	multi, err := NewMultiSourceMessageDiscovery(
		logger.Test(t),
		[]common.MessageDiscovery{source},
	)
	require.NoError(t, err)
	defer func() { _ = multi.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out := multi.Start(ctx)

	var first common.VerifierResultWithMetadata
	select {
	case first = <-out:
	case <-ctx.Done():
		t.Fatal("timeout waiting for first message")
	}
	// First discovery wins: must be msgA (same messageID, first in sequence).
	assert.Equal(t, msgA.VerifierResult.Timestamp.UnixMilli(), first.VerifierResult.Timestamp.UnixMilli(),
		"first discovery wins: emitted message must be the first occurrence")
	// Second receive should be deduplicated (same messageID) so we get nothing more, or channel stays open.
	select {
	case second := <-out:
		t.Fatalf("expected no second message (dedupe), got timestamp %d", second.VerifierResult.Timestamp.UnixMilli())
	case <-time.After(200 * time.Millisecond):
		// Expected: no second message
	}
}

func TestMultiSourceMessageDiscovery_AllSourcesRunning(t *testing.T) {
	// N sources each emitting; distinct messageIDs; total received = sum of distinct (overlaps deduped).
	msg1 := createTestCCVData(1, time.Now().UnixMilli(), 1, 2)
	msg2 := createTestCCVData(2, time.Now().UnixMilli(), 1, 2)
	msg3 := createTestCCVData(3, time.Now().UnixMilli(), 1, 2)
	msg3dup := createTestCCVData(3, time.Now().UnixMilli()+1, 1, 2) // same ID as msg3
	sourceA := newMockMessageDiscoveryWithMessages(t, []common.VerifierResultWithMetadata{msg1, msg3})
	sourceB := newMockMessageDiscoveryWithMessages(t, []common.VerifierResultWithMetadata{msg2, msg3dup})

	multi, err := NewMultiSourceMessageDiscovery(
		logger.Test(t),
		[]common.MessageDiscovery{sourceA, sourceB},
	)
	require.NoError(t, err)
	defer func() { _ = multi.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out := multi.Start(ctx)

	received := collectUntilTimeout(out, 500*time.Millisecond)
	assert.Len(t, received, 3, "three distinct messageIDs across sources (one duplicate dropped)")
	ids := make(map[protocol.Bytes32]struct{})
	for _, m := range received {
		ids[m.VerifierResult.MessageID] = struct{}{}
	}
	assert.Len(t, ids, 3)
}

// newMockMessageDiscoveryWithClosingChannel returns a MockMessageDiscovery whose
// Start channel is closed after all messages are sent. This simulates a source
// that terminates, which exercises the merge goroutine's channel-close detection.
func newMockMessageDiscoveryWithClosingChannel(t *testing.T, messages []common.VerifierResultWithMetadata) *mocks.MockMessageDiscovery {
	t.Helper()
	mockSrc := mocks.NewMockMessageDiscovery(t)
	ch := make(chan common.VerifierResultWithMetadata, len(messages)+1)
	mockSrc.EXPECT().Start(mock.Anything).Return(ch).Once()
	go func() {
		for _, msg := range messages {
			ch <- msg
		}
		close(ch)
	}()
	mockSrc.EXPECT().Close().Return(nil).Once()
	mockSrc.EXPECT().Replay(mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
	return mockSrc
}

func TestMultiSourceMessageDiscovery_MergeExitsWhenAllSourcesClosed(t *testing.T) {
	tests := []struct {
		name             string
		sourceMessages   [][]common.VerifierResultWithMetadata
		expectedCount    int
		expectedUniqueID int
	}{
		{
			name: "single source closes after sending messages",
			sourceMessages: [][]common.VerifierResultWithMetadata{
				{
					createTestCCVData(1, time.Now().UnixMilli(), 1, 2),
					createTestCCVData(2, time.Now().UnixMilli(), 1, 2),
				},
			},
			expectedCount:    2,
			expectedUniqueID: 2,
		},
		{
			name: "multiple sources all close after sending messages",
			sourceMessages: [][]common.VerifierResultWithMetadata{
				{createTestCCVData(10, time.Now().UnixMilli(), 1, 2)},
				{createTestCCVData(20, time.Now().UnixMilli(), 1, 2)},
				{createTestCCVData(30, time.Now().UnixMilli(), 1, 2)},
			},
			expectedCount:    3,
			expectedUniqueID: 3,
		},
		{
			name: "multiple sources with duplicate across closed channels",
			sourceMessages: [][]common.VerifierResultWithMetadata{
				{createTestCCVData(42, time.Now().UnixMilli(), 1, 2)},
				{createTestCCVData(42, time.Now().UnixMilli()+1, 1, 2)},
			},
			expectedCount:    1,
			expectedUniqueID: 1,
		},
		{
			name: "sources close immediately with no messages",
			sourceMessages: [][]common.VerifierResultWithMetadata{
				{},
				{},
			},
			expectedCount:    0,
			expectedUniqueID: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sources := make([]common.MessageDiscovery, 0, len(tt.sourceMessages))
			for _, msgs := range tt.sourceMessages {
				sources = append(sources, newMockMessageDiscoveryWithClosingChannel(t, msgs))
			}

			multi, err := NewMultiSourceMessageDiscovery(logger.Test(t), sources)
			require.NoError(t, err)

			ctx := context.Background()
			out := multi.Start(ctx)

			received := collectUntilTimeout(out, 500*time.Millisecond)
			assert.Len(t, received, tt.expectedCount)

			ids := make(map[protocol.Bytes32]struct{})
			for _, m := range received {
				ids[m.VerifierResult.MessageID] = struct{}{}
			}
			assert.Len(t, ids, tt.expectedUniqueID)

			closeDone := make(chan struct{})
			go func() {
				assert.NoError(t, multi.Close())
				close(closeDone)
			}()
			select {
			case <-closeDone:
			case <-time.After(2 * time.Second):
				t.Fatal("Close() did not complete within timeout; merge goroutine likely blocked on closed channels")
			}
		})
	}
}

// validMinimalConfig returns a Config with valid Scheduler and Storage so we can test Discoveries validation in isolation.
func validMinimalConfig(discoveries []config.DiscoveryConfig) *config.Config {
	return &config.Config{
		Scheduler: config.SchedulerConfig{
			TickerInterval:               100,
			VerificationVisibilityWindow: 120,
			BaseDelay:                    1000,
			MaxDelay:                     5000,
		},
		Discoveries: discoveries,
		Storage: config.StorageConfig{
			Strategy: config.StorageStrategySingle,
			Single: &config.SingleStorageConfig{
				Type: config.StorageBackendTypePostgres,
				Postgres: &config.PostgresConfig{
					URI:                "postgresql://test:test@localhost:5432/test",
					MaxOpenConnections: 10,
					MaxIdleConnections: 5,
				},
			},
		},
	}
}

func TestConfig_Validate_Discoveries(t *testing.T) {
	tests := []struct {
		name        string
		discoveries []config.DiscoveryConfig
		wantErr     bool
	}{
		{
			name:        "zero discoveries returns error",
			discoveries: nil,
			wantErr:     true,
		},
		{
			name:        "empty discoveries returns error",
			discoveries: []config.DiscoveryConfig{},
			wantErr:     true,
		},
		{
			name: "one valid discovery succeeds",
			discoveries: []config.DiscoveryConfig{
				{
					AggregatorReaderConfig: config.AggregatorReaderConfig{Address: "http://agg1", Since: 0},
					PollInterval:           100,
					Timeout:                200,
				},
			},
			wantErr: false,
		},
		{
			name: "two valid discoveries succeed",
			discoveries: []config.DiscoveryConfig{
				{
					AggregatorReaderConfig: config.AggregatorReaderConfig{Address: "http://agg1", Since: 0},
					PollInterval:           100,
					Timeout:                200,
				},
				{
					AggregatorReaderConfig: config.AggregatorReaderConfig{Address: "http://agg2", Since: 0},
					PollInterval:           100,
					Timeout:                200,
				},
			},
			wantErr: false,
		},
		{
			name: "discovery with missing address fails",
			discoveries: []config.DiscoveryConfig{
				{
					AggregatorReaderConfig: config.AggregatorReaderConfig{Address: "", Since: 0},
					PollInterval:           100,
					Timeout:                200,
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validMinimalConfig(tt.discoveries)
			err := cfg.Validate()
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
