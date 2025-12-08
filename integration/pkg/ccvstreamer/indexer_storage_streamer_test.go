package ccvstreamer_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/integration/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/ccvstreamer"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestNoReader(t *testing.T) {
	lggr := logger.Test(t)
	oss := ccvstreamer.NewIndexerStorageStreamer(lggr, ccvstreamer.IndexerStorageConfig{})
	require.NotNil(t, oss)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var wg sync.WaitGroup
	_, err := oss.Start(ctx, &wg)

	require.ErrorContains(t, err, "reader not set")
}

func TestOffchainStorageStreamerLifecycle(t *testing.T) {
	lggr := logger.Test(t)
	reader := mocks.MockMessageReader{}
	reader.EXPECT().ReadMessages(mock.Anything, mock.Anything).Return(nil, nil)
	oss := ccvstreamer.NewIndexerStorageStreamer(lggr, ccvstreamer.IndexerStorageConfig{
		IndexerClient:   &reader,
		PollingInterval: 150 * time.Millisecond,
	})
	require.NotNil(t, oss)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var wg sync.WaitGroup
	_, err := oss.Start(ctx, &wg)

	require.NoError(t, err)
	require.True(t, oss.IsRunning())

	deadline, ok := t.Deadline()
	if !ok {
		deadline = time.Now().Add(10 * time.Second)
	}
	waitTimeout := time.Until(deadline)
	cancel()
	require.Eventually(t, func() bool {
		return !oss.IsRunning()
	}, waitTimeout, 50*time.Millisecond)
}
