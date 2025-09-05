package executor_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/executor/types"
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
			err:     []string{"executor is not set", "logger is not set", "leaderElector is not set", "ccvDataReader is not set"},
		},
		{
			name: "happy",
			options: []executor.Option{
				executor.WithLogger(lggr),
				executor.WithExecutor(executor_mocks.NewMockExecutor(t)),
				executor.WithLeaderElector(executor_mocks.NewMockLeaderElector(t)),
				executor.WithCCVDataReader(executor_mocks.NewMockCcvDataReader(t)),
			},
			err: nil,
		},
		{
			name: "missing executor",
			options: []executor.Option{
				executor.WithLogger(lggr),
				executor.WithLeaderElector(executor_mocks.NewMockLeaderElector(t)),
				executor.WithCCVDataReader(executor_mocks.NewMockCcvDataReader(t)),
			},
			err: []string{"executor is not set"},
		},
		{
			name: "missing logger",
			options: []executor.Option{
				executor.WithExecutor(executor_mocks.NewMockExecutor(t)),
				executor.WithLeaderElector(executor_mocks.NewMockLeaderElector(t)),
				executor.WithCCVDataReader(executor_mocks.NewMockCcvDataReader(t)),
			},
			err: []string{"logger is not set"},
		},
		{
			name: "missing leaderElector",
			options: []executor.Option{
				executor.WithLogger(lggr),
				executor.WithExecutor(executor_mocks.NewMockExecutor(t)),
				executor.WithCCVDataReader(executor_mocks.NewMockCcvDataReader(t)),
			},
			err: []string{"leaderElector is not set"},
		},
		{
			name: "missing ccvDataReader",
			options: []executor.Option{
				executor.WithLogger(lggr),
				executor.WithExecutor(executor_mocks.NewMockExecutor(t)),
				executor.WithLeaderElector(executor_mocks.NewMockLeaderElector(t)),
			},
			err: []string{"ccvDataReader is not set"},
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

		ccvDataReader := executor_mocks.NewMockCcvDataReader(t)
		messageChan := make(chan types.MessageWithCCVData)
		ccvDataReader.EXPECT().SubscribeMessages().Return(messageChan, nil)

		ec, err := executor.NewCoordinator(
			executor.WithLogger(lggr),
			executor.WithExecutor(executor_mocks.NewMockExecutor(t)),
			executor.WithLeaderElector(executor_mocks.NewMockLeaderElector(t)),
			executor.WithCCVDataReader(ccvDataReader),
		)
		require.NoError(t, err)
		require.NotNil(t, ec)

		return ec
	}

	{
		ec := getReader()
		ctx, cancel := context.WithCancel(t.Context())
		require.NoError(t, ec.Start(ctx))
		require.True(t, ec.IsRunning())
		cancel()
		require.Eventuallyf(t, func() bool { return ec.IsRunning() == false }, 2*time.Second, 100*time.Millisecond, "executor coordinator did not stop in time")
	}

	{
		ec := getReader()
		require.NoError(t, ec.Start(t.Context()))
		require.True(t, ec.IsRunning())
		require.NoError(t, ec.Stop())
		require.Eventuallyf(t, func() bool { return ec.IsRunning() == false }, 2*time.Second, 100*time.Millisecond, "executor coordinator did not stop in time")
	}
}

func TestSubscribeMessagesError(t *testing.T) {
	lggr, hook := logger.TestObserved(t, zapcore.InfoLevel)

	// Generate an error when SubscribeMessages() is called during Start().
	ccvDataReader := executor_mocks.NewMockCcvDataReader(t)
	messageChan := make(chan types.MessageWithCCVData)
	sentinelError := fmt.Errorf("lilo & stitch")
	ccvDataReader.EXPECT().SubscribeMessages().Return(messageChan, sentinelError)

	ec, err := executor.NewCoordinator(
		executor.WithLogger(lggr),
		executor.WithExecutor(executor_mocks.NewMockExecutor(t)),
		executor.WithLeaderElector(executor_mocks.NewMockLeaderElector(t)),
		executor.WithCCVDataReader(ccvDataReader),
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
