package ccvstreamer_test

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/executor/internal/executor_mocks"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/ccvstreamer"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestNoReader(t *testing.T) {
	oss := ccvstreamer.NewOffchainStorageStreamer(nil, 0, 0)
	require.NotNil(t, oss)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var wg sync.WaitGroup
	lggr := logger.Test(t)
	_, err := oss.Start(ctx, lggr, &wg)

	require.ErrorContains(t, err, "reader not set")
}

func TestLifecycle(t *testing.T) {
	reader := executor_mocks.NewMockOffchainStorageReader(t)
	oss := ccvstreamer.NewOffchainStorageStreamer(reader, 0, 0)
	require.NotNil(t, oss)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var wg sync.WaitGroup
	lggr := logger.Test(t)
	_, err := oss.Start(ctx, lggr, &wg)

	require.NoError(t, err)
	running, err := oss.Status()
	require.NoError(t, err)
	require.True(t, running)

	cancel()
	wg.Wait()
	running, err = oss.Status()
	require.NoError(t, err)
	require.False(t, running)
}
