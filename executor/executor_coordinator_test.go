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

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/internal/executor_mocks"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestConstructor(t *testing.T) {
	lggr := logger.Test(t)

	testcases := []struct {
		name    string
		options []executor.Option
		err     []string
	}{
		{
			name:    "missing every option",
			options: []executor.Option{},
			err:     []string{"executor is not set", "logger is not set", "leaderElector is not set", "ccvResultStreamer is not set"},
		},
		{
			name: "happy",
			options: []executor.Option{
				executor.WithLogger(lggr),
				executor.WithExecutor(executor_mocks.NewMockExecutor(t)),
				executor.WithLeaderElector(executor_mocks.NewMockLeaderElector(t)),
				executor.WithCCVResultStreamer(executor_mocks.NewMockCCVResultStreamer(t)),
			},
			err: nil,
		},
		{
			name: "missing executor",
			options: []executor.Option{
				executor.WithLogger(lggr),
				executor.WithLeaderElector(executor_mocks.NewMockLeaderElector(t)),
				executor.WithCCVResultStreamer(executor_mocks.NewMockCCVResultStreamer(t)),
			},
			err: []string{"executor is not set"},
		},
		{
			name: "missing logger",
			options: []executor.Option{
				executor.WithExecutor(executor_mocks.NewMockExecutor(t)),
				executor.WithLeaderElector(executor_mocks.NewMockLeaderElector(t)),
				executor.WithCCVResultStreamer(executor_mocks.NewMockCCVResultStreamer(t)),
			},
			err: []string{"logger is not set"},
		},
		{
			name: "missing leaderElector",
			options: []executor.Option{
				executor.WithLogger(lggr),
				executor.WithExecutor(executor_mocks.NewMockExecutor(t)),
				executor.WithCCVResultStreamer(executor_mocks.NewMockCCVResultStreamer(t)),
			},
			err: []string{"leaderElector is not set"},
		},
		{
			name: "missing CCVResultStreamer",
			options: []executor.Option{
				executor.WithLogger(lggr),
				executor.WithExecutor(executor_mocks.NewMockExecutor(t)),
				executor.WithLeaderElector(executor_mocks.NewMockLeaderElector(t)),
			},
			err: []string{"ccvResultStreamer is not set"},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ec, err := executor.NewCoordinator(tc.options...)

			if len(tc.err) > 0 {
				require.Error(t, err)
				require.Nil(t, ec)
				joinedError := err.Error()

				for _, errStr := range tc.err {
					require.ErrorContains(t, err, errStr)
				}

				require.Len(t, tc.err, len(strings.Split(joinedError, "\n")), "unexpected number of errors")
			} else {
				require.NoError(t, err)
				require.NotNil(t, ec)
			}
		})
	}
}

func TestLifecycle(t *testing.T) {
	getReader := func() *executor.Coordinator {
		lggr := logger.Test(t)

		ccvDataReader := executor_mocks.NewMockCCVResultStreamer(t)
		messageChan := make(chan executor.StreamerResult)
		ccvDataReader.EXPECT().Start(mock.Anything, mock.Anything, mock.Anything).Return(messageChan, nil)

		ec, err := executor.NewCoordinator(
			executor.WithLogger(lggr),
			executor.WithExecutor(executor_mocks.NewMockExecutor(t)),
			executor.WithLeaderElector(executor_mocks.NewMockLeaderElector(t)),
			executor.WithCCVResultStreamer(ccvDataReader),
		)
		require.NoError(t, err)
		require.NotNil(t, ec)

		return ec
	}

	t.Run("context cancelled", func(t *testing.T) {
		ec := getReader()
		ctx, cancel := context.WithCancel(t.Context())
		require.NoError(t, ec.Start(ctx))
		require.NoError(t, ec.Ready())
		cancel()
		require.Eventuallyf(t, func() bool { return ec.Ready() != nil }, 2*time.Second, 100*time.Millisecond, "executor coordinator did not stop in time")
	})

	t.Run("stop called", func(t *testing.T) {
		ec := getReader()
		require.NoError(t, ec.Start(t.Context()))
		require.NoError(t, ec.Ready())
		require.NoError(t, ec.Close())
		require.Eventuallyf(t, func() bool { return ec.Ready() != nil }, 2*time.Second, 100*time.Millisecond, "executor coordinator did not stop in time")
	})
}

func TestSubscribeMessagesError(t *testing.T) {
	lggr, hook := logger.TestObserved(t, zapcore.InfoLevel)

	// Generate an error when SubscribeMessages() is called during Start().
	ccvDataReader := executor_mocks.NewMockCCVResultStreamer(t)
	messageChan := make(chan executor.StreamerResult)
	sentinelError := fmt.Errorf("lilo & stitch")
	ccvDataReader.EXPECT().Start(mock.Anything, mock.Anything, mock.Anything).Return(messageChan, sentinelError)

	ec, err := executor.NewCoordinator(
		executor.WithLogger(lggr),
		executor.WithExecutor(executor_mocks.NewMockExecutor(t)),
		executor.WithLeaderElector(executor_mocks.NewMockLeaderElector(t)),
		executor.WithCCVResultStreamer(ccvDataReader),
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
		executor.WithLogger(lggr),
		executor.WithExecutor(executor_mocks.NewMockExecutor(t)),
		executor.WithLeaderElector(executor_mocks.NewMockLeaderElector(t)),
		executor.WithCCVResultStreamer(executor_mocks.NewMockCCVResultStreamer(t)),
	)
	require.NoError(t, err)
	require.NotNil(t, ec)

	require.ErrorContains(t, ec.Close(), "coordinator not running")
}
