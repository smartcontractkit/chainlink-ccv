package ccvstreamer_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	v1 "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api/handlers/v1"
	icommon "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/ccvstreamer"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"
)

func TestNoReader(t *testing.T) {
	lggr := logger.Test(t)
	oss := ccvstreamer.NewIndexerStorageStreamer(lggr, ccvstreamer.IndexerStorageConfig{})
	require.NotNil(t, oss)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	_, _, err := oss.Start(ctx)
	require.ErrorContains(t, err, "reader not set")
}

func TestOffchainStorageStreamerLifecycle(t *testing.T) {
	lggr := logger.Test(t)
	reader := mocks.MockMessageReader{}
	reader.EXPECT().ReadMessages(mock.Anything, mock.Anything).Return(nil, nil)
	timeProvider := mocks.NewMockTimeProvider(t)
	timeProvider.EXPECT().GetTime().Return(time.Now()).Maybe()
	oss := ccvstreamer.NewIndexerStorageStreamer(lggr, ccvstreamer.IndexerStorageConfig{
		IndexerClient:     &reader,
		EnabledDestChains: []protocol.ChainSelector{1},
		PollingInterval:   150 * time.Millisecond,
		TimeProvider:      timeProvider,
		ExpiryDuration:    10 * time.Second,
		CleanInterval:     1 * time.Second,
	})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	messageChan, errorsChan, err := oss.Start(ctx)
	require.NotNil(t, messageChan)
	require.NotNil(t, errorsChan)

	require.NoError(t, err)
	require.True(t, oss.IsRunning())

	cancel()
	require.Eventually(t, func() bool {
		return !oss.IsRunning()
	}, tests.WaitTimeout(t), 50*time.Millisecond)
}

// newTestMessage builds a minimal but valid protocol.Message so that MessageID() succeeds.
func newTestMessage(t *testing.T, sequenceNumber protocol.SequenceNumber) protocol.Message {
	t.Helper()

	sender, err := protocol.RandomAddress()
	require.NoError(t, err)
	receiver, err := protocol.RandomAddress()
	require.NoError(t, err)
	onRampAddr, err := protocol.RandomAddress()
	require.NoError(t, err)
	offRampAddr, err := protocol.RandomAddress()
	require.NoError(t, err)

	msg, err := protocol.NewMessage(
		protocol.ChainSelector(1337),
		protocol.ChainSelector(2337),
		sequenceNumber,
		onRampAddr,
		offRampAddr,
		10,      // finality
		200_000, // execution gas limit
		100_000, // ccip receive gas limit
		protocol.Bytes32{},
		sender,
		receiver,
		[]byte("test data"),
		[]byte("test data"),
		protocol.NewEmptyTokenTransfer(),
	)
	require.NoError(t, err)
	return *msg
}

// TestOffchainStorageStreamerReadMessages_NoResultsPreservesLookback reproduces a bug where, if
// ReadMessages returns zero results, the streamer's lookback window (lastQueryTime) was reset to
// the zero time instead of being preserved, causing every subsequent poll to re-read the entire
// history of the indexer.
func TestOffchainStorageStreamerReadMessages_NoResultsPreservesLookback(t *testing.T) {
	lggr := logger.Test(t)
	reader := mocks.MockMessageReader{}
	timeProvider := mocks.NewMockTimeProvider(t)
	timeProvider.EXPECT().GetTime().Return(time.Now()).Maybe()

	initialQueryTime := time.Now().Add(-1 * time.Hour).Truncate(time.Second)

	var mu sync.Mutex
	var capturedStarts []string

	reader.EXPECT().ReadMessages(mock.Anything, mock.Anything).Run(func(_ context.Context, q v1.MessagesInput) {
		mu.Lock()
		capturedStarts = append(capturedStarts, q.Start)
		mu.Unlock()
	}).Return(nil, nil)

	oss := ccvstreamer.NewIndexerStorageStreamer(lggr, ccvstreamer.IndexerStorageConfig{
		IndexerClient:     &reader,
		EnabledDestChains: []protocol.ChainSelector{1},
		InitialQueryTime:  initialQueryTime,
		PollingInterval:   20 * time.Millisecond,
		QueryLimit:        100,
		TimeProvider:      timeProvider,
		ExpiryDuration:    10 * time.Second,
		CleanInterval:     1 * time.Second,
	})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	_, errorsChan, err := oss.Start(ctx)
	require.NoError(t, err)
	go func() {
		for range errorsChan {
		}
	}()

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(capturedStarts) >= 2
	}, tests.WaitTimeout(t), 10*time.Millisecond)

	cancel()
	require.Eventually(t, func() bool {
		return !oss.IsRunning()
	}, tests.WaitTimeout(t), 50*time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	expectedStart := initialQueryTime.Format(time.RFC3339)
	for i, start := range capturedStarts {
		require.Equalf(t, expectedStart, start, "call %d used Start=%q, want lookback window preserved as %q", i, start, expectedStart)
	}
}

// TestOffchainStorageStreamerReadMessages_MessageAdvancesLookback confirms that when a message is
// returned, the lookback window correctly advances to the message's ingestion timestamp for the
// next poll.
func TestOffchainStorageStreamerReadMessages_MessageAdvancesLookback(t *testing.T) {
	lggr := logger.Test(t)
	reader := mocks.MockMessageReader{}
	timeProvider := mocks.NewMockTimeProvider(t)
	timeProvider.EXPECT().GetTime().Return(time.Now()).Maybe()

	initialQueryTime := time.Now().Add(-1 * time.Hour).Truncate(time.Second)
	ingestionTime := initialQueryTime.Add(30 * time.Minute).Truncate(time.Second)

	msg := newTestMessage(t, 123)
	msgID, err := msg.MessageID()
	require.NoError(t, err)

	msgWithMetadata := icommon.MessageWithMetadata{
		Message: msg,
		Metadata: icommon.MessageMetadata{
			Status:             icommon.MessageSuccessful,
			IngestionTimestamp: ingestionTime,
		},
	}

	var mu sync.Mutex
	var capturedStarts []string
	var callCount int

	reader.EXPECT().ReadMessages(mock.Anything, mock.Anything).RunAndReturn(
		func(_ context.Context, q v1.MessagesInput) (map[string]icommon.MessageWithMetadata, error) {
			mu.Lock()
			defer mu.Unlock()
			capturedStarts = append(capturedStarts, q.Start)
			callCount++
			if callCount == 1 {
				return map[string]icommon.MessageWithMetadata{msgID.String(): msgWithMetadata}, nil
			}
			return nil, nil
		},
	)

	oss := ccvstreamer.NewIndexerStorageStreamer(lggr, ccvstreamer.IndexerStorageConfig{
		IndexerClient:     &reader,
		EnabledDestChains: []protocol.ChainSelector{1},
		InitialQueryTime:  initialQueryTime,
		PollingInterval:   20 * time.Millisecond,
		QueryLimit:        100,
		TimeProvider:      timeProvider,
		ExpiryDuration:    10 * time.Second,
		CleanInterval:     1 * time.Second,
	})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	messageChan, errorsChan, err := oss.Start(ctx)
	require.NoError(t, err)
	go func() {
		for range errorsChan {
		}
	}()

	select {
	case received := <-messageChan:
		require.Equal(t, msgID, mustMessageID(t, received.Message))
	case <-time.After(tests.WaitTimeout(t)):
		t.Fatal("timed out waiting for message")
	}

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(capturedStarts) >= 2
	}, tests.WaitTimeout(t), 10*time.Millisecond)

	cancel()
	require.Eventually(t, func() bool {
		return !oss.IsRunning()
	}, tests.WaitTimeout(t), 50*time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, initialQueryTime.Format(time.RFC3339), capturedStarts[0])
	require.Equal(t, ingestionTime.Format(time.RFC3339), capturedStarts[1])
}

func mustMessageID(t *testing.T, msg protocol.Message) protocol.Bytes32 {
	t.Helper()
	id, err := msg.MessageID()
	require.NoError(t, err)
	return id
}
