package ccvstreamer_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/ccvstreamer"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
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
	oss := ccvstreamer.NewIndexerStorageStreamer(lggr, ccvstreamer.IndexerStorageConfig{
		IndexerClient:   &reader,
		PollingInterval: 150 * time.Millisecond,
		TimeProvider:    mocks.NewMockTimeProvider(t),
		ExpiryDuration:  10 * time.Second,
		CleanInterval:   1 * time.Second,
	})
	require.NotNil(t, oss)

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
