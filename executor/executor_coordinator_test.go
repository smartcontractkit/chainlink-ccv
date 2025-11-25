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
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
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
			_, err := executor.NewCoordinator(tc.args.lggr, tc.args.exec, tc.args.sub, tc.args.le, tc.args.mon, 8*time.Hour)

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
		8*time.Hour,
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
		8*time.Hour,
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
		8*time.Hour,
	)
	require.NoError(t, err)
	require.NotNil(t, ec)

	require.ErrorContains(t, ec.Close(), "has not been started")
}

func TestMessageExpiration(t *testing.T) {
	testcases := []struct {
		name              string
		expiryDuration    time.Duration
		retryDelay        time.Duration
		initialReadyDelay time.Duration
		shouldRetry       bool
		shouldExecute     bool
		shouldExpire      bool
	}{
		{
			name:              "message expires when retry time exceeds expiry",
			expiryDuration:    1 * time.Second,
			retryDelay:        3 * time.Second, // retry after 3 s
			initialReadyDelay: 1 * time.Second, // ready immediately
			shouldRetry:       true,
			shouldExecute:     false,
			shouldExpire:      true,
		},
		{
			name:              "message retries when within expiry window",
			expiryDuration:    20 * time.Second,
			retryDelay:        2 * time.Second, // 2 seconds retry delay
			initialReadyDelay: 0 * time.Second,
			shouldRetry:       true,
			shouldExecute:     false,
			shouldExpire:      false,
		},
		{
			name:              "message does not retry when shouldRetry is false",
			expiryDuration:    1 * time.Second,
			retryDelay:        2 * time.Second,
			initialReadyDelay: 1 * time.Second,
			shouldRetry:       false,
			shouldExecute:     false,
			shouldExpire:      false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a new observed logger for each test case
			lggr, hook := logger.TestObserved(t, zapcore.InfoLevel)

			// Create a test message
			testMessage := executor.StreamerResult{
				Messages: []protocol.MessageWithMetadata{
					{
						Message: protocol.Message{
							DestChainSelector:   1,
							SourceChainSelector: 2,
							SequenceNumber:      1,
						},
						Metadata: protocol.MessageMetadata{
							IngestionTimestamp: time.Now().UTC().Add(tc.initialReadyDelay),
						},
					},
				},
			}

			// Set up message subscriber to send one message
			messageSubscriber := executor_mocks.NewMockMessageSubscriber(t)
			messageChan := make(chan executor.StreamerResult, 1)
			messageSubscriber.EXPECT().Start(mock.Anything, mock.Anything).Return(messageChan, nil)

			// Set up executor mock
			mockExecutor := executor_mocks.NewMockExecutor(t)
			mockExecutor.EXPECT().CheckValidMessage(mock.Anything, mock.Anything).Return(nil).Maybe()

			// Set up leader elector mock
			leaderElector := executor_mocks.NewMockLeaderElector(t)
			leaderElector.EXPECT().GetReadyTimestamp(mock.Anything, mock.Anything, mock.Anything).Return(time.Now().UTC().Add(tc.initialReadyDelay)).Maybe()
			leaderElector.EXPECT().GetRetryDelay(mock.Anything).Return(tc.retryDelay).Maybe()

			mockExecutor.EXPECT().GetMessageStatus(mock.Anything, mock.Anything).
				Return(executor.MessageStatusResults{ShouldRetry: tc.shouldRetry, ShouldExecute: tc.shouldExecute}, nil).Maybe()

			// Create coordinator with test expiry duration
			ec, err := executor.NewCoordinator(
				lggr,
				mockExecutor,
				messageSubscriber,
				leaderElector,
				monitoring.NewNoopExecutorMonitoring(),
				tc.expiryDuration,
			)
			require.NoError(t, err)
			require.NotNil(t, ec)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// Start the coordinator
			require.NoError(t, ec.Start(ctx))
			defer func() {
				_ = ec.Close()
			}()

			// Send the test message
			messageChan <- testMessage

			// Wait for processing to occur (ticker fires every second)
			time.Sleep(5 * time.Second)

			// Check for expected log entries
			found := func(searchStr string) bool {
				for _, entry := range hook.All() {
					entryStr := fmt.Sprintf("%+v", entry)
					if strings.Contains(entryStr, searchStr) {
						return true
					}
				}
				return false
			}

			if tc.shouldExecute {
				require.Eventuallyf(t, func() bool {
					return found("attempting to execute message")
				}, 5*time.Second, 1*time.Second, "expected to find 'attempting to execute message' log entry")
			}

			if tc.shouldExpire {
				require.Eventuallyf(t, func() bool {
					return found("message has expired")
				}, 3*time.Second, 1*time.Second, "expected to find 'message has expired' log entry")
			}

			if tc.shouldRetry {
				require.Eventuallyf(t, func() bool {
					return found("message should be retried")
				}, 3*time.Second, 1*time.Second, "expected to find 'message should be retried' log entry")
			}

			if !tc.shouldExecute && !tc.shouldRetry {
				// If neither should happen, verify no expiration or retry log entries exist
				time.Sleep(2 * time.Second)
				require.False(t, found("message has expired"), "should not have expiration log")
				require.False(t, found("message should be retried"), "should not have retry log")
			}
		})
	}
}
