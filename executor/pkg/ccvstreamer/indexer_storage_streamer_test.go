package ccvstreamer_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/executor/internal/executor_mocks"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/ccvstreamer"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestNoReader(t *testing.T) {
	oss := ccvstreamer.NewIndexerStorageStreamer(nil, ccvstreamer.IndexerStorageConfig{})
	require.NotNil(t, oss)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var wg sync.WaitGroup
	lggr := logger.Test(t)
	_, err := oss.Start(ctx, lggr, &wg)

	require.ErrorContains(t, err, "reader not set")
}

func TestOffchainStorageStreamerLifecycle(t *testing.T) {
	reader := executor_mocks.NewMockOffchainStorageReader(t)
	reader.EXPECT().ReadCCVData(mock.Anything).Return(nil, nil)
	oss := ccvstreamer.NewIndexerStorageStreamer(nil, ccvstreamer.IndexerStorageConfig{})
	require.NotNil(t, oss)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var wg sync.WaitGroup
	lggr := logger.Test(t)
	_, err := oss.Start(ctx, lggr, &wg)

	require.NoError(t, err)
	require.True(t, oss.IsRunning())

	// let it run a bit to ensure ReadCCVData is called
	time.Sleep(200 * time.Millisecond)

	cancel()
	wg.Wait()
	require.False(t, oss.IsRunning())
}
