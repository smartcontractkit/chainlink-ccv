package executor_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	executor "github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/internal/executor_mocks"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestConstructor(t *testing.T) {
	lggr := logger.Test(t)

	type args struct {
		lggr logger.Logger
		exec executor.Executor
		sub  executor.MessageSubscriber
		le   executor.LeaderElector
		mon  executor.Monitoring
	}

	testcases := []struct {
		name      string
		args      args
		expectErr bool
	}{
		{
			name:      "missing every required component",
			args:      args{},
			expectErr: true,
		},
		{
			name: "happy",
			args: args{
				lggr: lggr,
				exec: executor_mocks.NewMockExecutor(t),
				sub:  executor_mocks.NewMockMessageSubscriber(t),
				le:   executor_mocks.NewMockLeaderElector(t),
				mon:  monitoring.NewNoopExecutorMonitoring(),
			},
			expectErr: false,
		},
		{
			name: "missing executor",
			args: args{
				lggr: lggr,
				sub:  executor_mocks.NewMockMessageSubscriber(t),
				le:   executor_mocks.NewMockLeaderElector(t),
				mon:  monitoring.NewNoopExecutorMonitoring(),
			},
			expectErr: true,
		},
		{
			name: "missing logger",
			args: args{
				exec: executor_mocks.NewMockExecutor(t),
				sub:  executor_mocks.NewMockMessageSubscriber(t),
				le:   executor_mocks.NewMockLeaderElector(t),
				mon:  monitoring.NewNoopExecutorMonitoring(),
			},
			expectErr: true,
		},
		{
			name: "missing leaderElector",
			args: args{
				lggr: lggr,
				exec: executor_mocks.NewMockExecutor(t),
				sub:  executor_mocks.NewMockMessageSubscriber(t),
				mon:  monitoring.NewNoopExecutorMonitoring(),
			},
			expectErr: true,
		},
		{
			name: "missing MessageSubscriber",
			args: args{
				lggr: lggr,
				exec: executor_mocks.NewMockExecutor(t),
				le:   executor_mocks.NewMockLeaderElector(t),
				mon:  monitoring.NewNoopExecutorMonitoring(),
			},
			expectErr: true,
		},
		{
			name: "missing Monitoring",
			args: args{
				lggr: lggr,
				exec: executor_mocks.NewMockExecutor(t),
				sub:  executor_mocks.NewMockMessageSubscriber(t),
				le:   executor_mocks.NewMockLeaderElector(t),
			},
			expectErr: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := executor.NewCoordinator(tc.args.lggr, tc.args.exec, tc.args.sub, tc.args.le, tc.args.mon)

			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestLifecycle(t *testing.T) {
	lggr := logger.Test(t)

	ccvDataReader := executor_mocks.NewMockMessageSubscriber(t)
	messageChan := make(chan executor.StreamerResult)
	ccvDataReader.EXPECT().Start(mock.Anything, mock.Anything).Return(messageChan, nil)

	ec, err := executor.NewCoordinator(
		lggr,
		executor_mocks.NewMockExecutor(t),
		ccvDataReader,
		executor_mocks.NewMockLeaderElector(t),
		monitoring.NewNoopExecutorMonitoring(),
	)
	require.NoError(t, err)
	require.NotNil(t, ec)

	require.NoError(t, ec.Start(t.Context()))
	require.NoError(t, ec.Ready())
	require.NoError(t, ec.Close())
	require.Eventuallyf(t, func() bool { return ec.Ready() != nil }, 2*time.Second, 100*time.Millisecond, "executor coordinator did not stop in time")
}

func TestSubscribeMessagesError(t *testing.T) {
	lggr, hook := logger.TestObserved(t, zapcore.InfoLevel)

	// Generate an error when SubscribeMessages() is called during Start().
	messageSubscriber := executor_mocks.NewMockMessageSubscriber(t)
	messageChan := make(chan executor.StreamerResult)
	sentinelError := fmt.Errorf("lilo & stitch")
	messageSubscriber.EXPECT().Start(mock.Anything, mock.Anything).Return(messageChan, sentinelError)

	ec, err := executor.NewCoordinator(
		lggr,
		executor_mocks.NewMockExecutor(t),
		messageSubscriber,
		executor_mocks.NewMockLeaderElector(t),
		monitoring.NewNoopExecutorMonitoring(),
	)
	require.NoError(t, err)
	require.NotNil(t, ec)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	require.NoError(t, ec.Start(ctx))

	found := func() bool {
		for _, entry := range hook.All() {
			entryStr := fmt.Sprintf("%+v", entry)
			if strings.Contains(entryStr, sentinelError.Error()) {
				return true
			}
		}
		return false
	}
	require.Eventuallyf(t, found, 2*time.Second, 100*time.Millisecond, "executor coordinator did not stop in time")
}

func TestStopNotRunning(t *testing.T) {
	lggr := logger.Test(t)

	ec, err := executor.NewCoordinator(
		lggr,
		executor_mocks.NewMockExecutor(t),
		executor_mocks.NewMockMessageSubscriber(t),
		executor_mocks.NewMockLeaderElector(t),
		monitoring.NewNoopExecutorMonitoring(),
	)
	require.NoError(t, err)
	require.NotNil(t, ec)

	require.ErrorContains(t, ec.Close(), "has not been started")
}
