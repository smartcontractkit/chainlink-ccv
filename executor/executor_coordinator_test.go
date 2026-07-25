package executor_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"go.uber.org/zap/zapcore"

	ccvcommon "github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"
)

func TestNewCoordinator_DefaultDataNotReadyRetryInterval(t *testing.T) {
	t.Parallel()

	ec, err := executor.NewCoordinator(
		logger.Test(t),
		"",
		mocks.NewMockExecutor(t),
		mocks.NewMockMessageSubscriber(t),
		mocks.NewMockLeaderElector(t),
		monitoring.NewNoopExecutorMonitoring(),
		time.Hour,
		mocks.NewMockTimeProvider(t),
		1,
		0,
	)
	require.NoError(t, err)
	require.NotNil(t, ec)
}

func TestConstructor(t *testing.T) {
	lggr := logger.Test(t)

	type args struct {
		lggr         logger.Logger
		exec         executor.Executor
		sub          executor.MessageSubscriber
		le           executor.LeaderElector
		mon          executor.Monitoring
		timeProvider any
		workerCount  int
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
				lggr:         lggr,
				exec:         mocks.NewMockExecutor(t),
				sub:          mocks.NewMockMessageSubscriber(t),
				le:           mocks.NewMockLeaderElector(t),
				mon:          monitoring.NewNoopExecutorMonitoring(),
				timeProvider: mocks.NewMockTimeProvider(t),
				workerCount:  100,
			},
			expectErr: false,
		},
		{
			name: "missing executor",
			args: args{
				lggr:         lggr,
				sub:          mocks.NewMockMessageSubscriber(t),
				le:           mocks.NewMockLeaderElector(t),
				mon:          monitoring.NewNoopExecutorMonitoring(),
				timeProvider: mocks.NewMockTimeProvider(t),
				workerCount:  100,
			},
			expectErr: true,
		},
		{
			name: "missing logger",
			args: args{
				exec:         mocks.NewMockExecutor(t),
				sub:          mocks.NewMockMessageSubscriber(t),
				le:           mocks.NewMockLeaderElector(t),
				mon:          monitoring.NewNoopExecutorMonitoring(),
				timeProvider: mocks.NewMockTimeProvider(t),
				workerCount:  100,
			},
			expectErr: true,
		},
		{
			name: "missing leaderElector",
			args: args{
				lggr:         lggr,
				exec:         mocks.NewMockExecutor(t),
				sub:          mocks.NewMockMessageSubscriber(t),
				mon:          monitoring.NewNoopExecutorMonitoring(),
				timeProvider: mocks.NewMockTimeProvider(t),
				workerCount:  100,
			},
			expectErr: true,
		},
		{
			name: "missing MessageSubscriber",
			args: args{
				lggr:         lggr,
				exec:         mocks.NewMockExecutor(t),
				le:           mocks.NewMockLeaderElector(t),
				mon:          monitoring.NewNoopExecutorMonitoring(),
				timeProvider: mocks.NewMockTimeProvider(t),
				workerCount:  100,
			},
			expectErr: true,
		},
		{
			name: "missing Monitoring",
			args: args{
				lggr:         lggr,
				exec:         mocks.NewMockExecutor(t),
				sub:          mocks.NewMockMessageSubscriber(t),
				le:           mocks.NewMockLeaderElector(t),
				timeProvider: mocks.NewMockTimeProvider(t),
				workerCount:  100,
			},
			expectErr: true,
		},
		{
			name: "missing timeProvider",
			args: args{
				lggr:         lggr,
				exec:         mocks.NewMockExecutor(t),
				sub:          mocks.NewMockMessageSubscriber(t),
				le:           mocks.NewMockLeaderElector(t),
				mon:          monitoring.NewNoopExecutorMonitoring(),
				timeProvider: nil,
				workerCount:  100,
			},
			expectErr: true,
		},
		{
			name: "workerCount zero",
			args: args{
				lggr:         lggr,
				exec:         mocks.NewMockExecutor(t),
				sub:          mocks.NewMockMessageSubscriber(t),
				le:           mocks.NewMockLeaderElector(t),
				mon:          monitoring.NewNoopExecutorMonitoring(),
				timeProvider: mocks.NewMockTimeProvider(t),
				workerCount:  0,
			},
			expectErr: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var tp ccvcommon.TimeProvider
			if tc.args.timeProvider != nil {
				tp = tc.args.timeProvider.(ccvcommon.TimeProvider)
			}
			_, err := executor.NewCoordinator(tc.args.lggr, "", tc.args.exec, tc.args.sub, tc.args.le, tc.args.mon, 8*time.Hour, tp, tc.args.workerCount, time.Second)

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

	ccvDataReader := mocks.NewMockMessageSubscriber(t)
	ccvDataReader.EXPECT().Start(mock.Anything).Return(nil, nil, nil)

	executorMock := mocks.NewMockExecutor(t)
	executorMock.EXPECT().Start(mock.Anything).Return(nil)
	executorMock.EXPECT().Close().Return(nil)

	ec, err := executor.NewCoordinator(
		lggr,
		"",
		executorMock,
		ccvDataReader,
		mocks.NewMockLeaderElector(t),
		monitoring.NewNoopExecutorMonitoring(),
		8*time.Hour,
		mocks.NewMockTimeProvider(t),
		100,
		time.Second,
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
	messageSubscriber := mocks.NewMockMessageSubscriber(t)
	sentinelError := fmt.Errorf("lilo & stitch")
	messageSubscriber.EXPECT().Start(mock.Anything).Return(nil, nil, sentinelError)
	timeProvider := mocks.NewMockTimeProvider(t)
	timeProvider.EXPECT().GetTime().Return(time.Now().UTC()).Maybe()

	mockExecutor := mocks.NewMockExecutor(t)
	mockExecutor.EXPECT().Start(mock.Anything).Return(nil)
	mockExecutor.EXPECT().Close().Return(nil)

	ec, err := executor.NewCoordinator(
		lggr,
		"",
		mockExecutor,
		messageSubscriber,
		mocks.NewMockLeaderElector(t),
		monitoring.NewNoopExecutorMonitoring(),
		8*time.Hour,
		timeProvider,
		100,
		time.Second,
	)
	require.NoError(t, err)
	require.NotNil(t, ec)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	require.NoError(t, ec.Start(ctx))
	defer func() { require.NoError(t, ec.Close()) }()

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
		"",
		mocks.NewMockExecutor(t),
		mocks.NewMockMessageSubscriber(t),
		mocks.NewMockLeaderElector(t),
		monitoring.NewNoopExecutorMonitoring(),
		8*time.Hour,
		mocks.NewMockTimeProvider(t),
		100,
		time.Second,
	)
	require.NoError(t, err)
	require.NotNil(t, ec)

	require.ErrorContains(t, ec.Close(), "has not been started")
}

func TestMessageExpiration(t *testing.T) {
	testcases := []struct {
		name string
		// How long before a message will expire.
		expiryDuration time.Duration
		// retry delay from the turn taking algorithm.
		retryDelay time.Duration
		// The initial delay to emulate turn taking for other executors in the pool.
		initialReadyDelay time.Duration
		// The value (after now) that is returned by the time provider when GetTime() is called.
		mockedTimeDifference time.Duration
		// The return value from the executor.GetMessageStatus() call.
		messageStatusResults executor.MessageStatusResults
		// Whether we should see the message logs to determine if the flow is correct.
		shouldRetry  bool
		shouldExpire bool
	}{
		{
			name:                 "message expires when retry time exceeds expiry",
			expiryDuration:       1 * time.Second,
			retryDelay:           3 * time.Second,      // retry after 3 s
			initialReadyDelay:    1 * time.Millisecond, // ready immediately
			mockedTimeDifference: 2 * time.Second,
			messageStatusResults: executor.MessageStatusResults{
				ShouldRetry:   true,
				ShouldExecute: false,
			},
			shouldRetry:  false, // because message is expired, we should not see retry log
			shouldExpire: true,  // because message is expired, we should see expire log
		},
		{
			name:                 "message does not retry when shouldRetry is false",
			expiryDuration:       2 * time.Second,
			retryDelay:           3 * time.Second,
			initialReadyDelay:    0 * time.Second,
			mockedTimeDifference: 1 * time.Second,
			messageStatusResults: executor.MessageStatusResults{
				ShouldRetry:   false,
				ShouldExecute: false,
			},
			shouldRetry:  false, // because message status returns no retry, we should not see retry log
			shouldExpire: false, // because message is not yet expired, we should not see expire log
		},
		{
			name:                 "message should execute when within expiry and shouldExecute is true",
			expiryDuration:       10 * time.Second,
			retryDelay:           1 * time.Second,
			initialReadyDelay:    0 * time.Second,
			mockedTimeDifference: 1 * time.Second,
			messageStatusResults: executor.MessageStatusResults{
				ShouldRetry:   false,
				ShouldExecute: true,
			},
			shouldRetry:  false, // no retry
			shouldExpire: false, // should not expire
		},
		{
			name:                 "message should not execute, not retry, and not expire (future time)",
			expiryDuration:       30 * time.Second,
			retryDelay:           2 * time.Second,
			initialReadyDelay:    7 * time.Second,
			mockedTimeDifference: 1 * time.Second,
			messageStatusResults: executor.MessageStatusResults{
				ShouldRetry:   false,
				ShouldExecute: false,
			},
			shouldRetry:  false,
			shouldExpire: false,
		},
		{
			name:                 "message expired but shouldExecute is true, should still expire not execute",
			expiryDuration:       1 * time.Second,
			retryDelay:           1 * time.Second,
			initialReadyDelay:    0 * time.Second,
			mockedTimeDifference: 2 * time.Second,
			messageStatusResults: executor.MessageStatusResults{
				ShouldRetry:   false,
				ShouldExecute: true,
			},
			shouldRetry:  false,
			shouldExpire: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a new observed logger for each test case
			lggr, hook := logger.TestObserved(t, zapcore.DebugLevel)

			currentTime := time.Now().UTC()
			mockTimeProvider := mocks.NewMockTimeProvider(t)
			mockTimeProvider.EXPECT().GetTime().Return(currentTime.Add(tc.mockedTimeDifference)).Maybe()

			// Create a test message
			testMessage := common.MessageWithMetadata{
				Message: protocol.Message{
					DestChainSelector:   1,
					SourceChainSelector: 2,
					SequenceNumber:      1,
				},
				Metadata: common.MessageMetadata{
					IngestionTimestamp: currentTime,
				},
			}

			// Set up message subscriber to send one message
			messageSubscriber := mocks.NewMockMessageSubscriber(t)
			results := make(chan common.MessageWithMetadata)

			messageSubscriber.EXPECT().Start(mock.Anything).Return(results, nil, nil).Run(func(ctx context.Context) {
				// Send the test message to the channel
				go func() {
					results <- testMessage
				}()
			})

			// Set up executor mock
			mockExecutor := mocks.NewMockExecutor(t)
			mockExecutor.EXPECT().Start(mock.Anything).Return(nil)
			mockExecutor.EXPECT().Close().Return(nil)
			mockExecutor.EXPECT().CheckValidMessage(mock.Anything, mock.Anything).Return(nil).Maybe()
			mockExecutor.EXPECT().HandleMessage(mock.Anything, mock.Anything).Return(false, nil).Maybe()

			// Set up leader elector mock
			leaderElector := mocks.NewMockLeaderElector(t)
			leaderElector.EXPECT().IsExecutorForChain(mock.Anything).Return(true).Maybe()
			leaderElector.EXPECT().GetReadyTimestamp(mock.Anything, mock.Anything, mock.Anything).Return(currentTime.Add(tc.initialReadyDelay), nil).Maybe()
			leaderElector.EXPECT().GetRetryDelay(mock.Anything).Return(tc.retryDelay, nil).Maybe()

			// Create coordinator with test expiry duration
			ec, err := executor.NewCoordinator(
				lggr,
				"",
				mockExecutor,
				messageSubscriber,
				leaderElector,
				monitoring.NewNoopExecutorMonitoring(),
				tc.expiryDuration,
				mockTimeProvider,
				100,
				time.Second,
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

			if !tc.shouldExpire && !tc.shouldRetry {
				require.Eventuallyf(t, func() bool {
					if tc.initialReadyDelay > tc.mockedTimeDifference {
						return found("found messages ready for processing")
					}
					return found("processing message with ID")
				}, 3*time.Second, 100*time.Millisecond, "timed out waiting for coordinator activity")
			}

			// Only assert on retry and expire, not on execute.
			if tc.shouldExpire {
				require.Eventuallyf(t, func() bool {
					return found("message has expired")
				}, 3*time.Second, 1*time.Second, "expected to find 'message has expired' log entry")
			} else {
				require.False(t, found("message has expired"), "should not have expire log")
			}

			if tc.shouldRetry {
				require.Eventuallyf(t, func() bool {
					return found("message should be retried")
				}, 3*time.Second, 1*time.Second, "expected to find 'message should be retried' log entry")
			} else {
				require.False(t, found("message should be retried"), "should not have retry log")
			}
		})
	}
}

func TestDuplicateMessageIDFromStreamWhileInFlight_IsSkippedAndHandleMessageCalledOnce(t *testing.T) {
	lggr, hook := logger.TestObserved(t, zapcore.DebugLevel)
	currentTime := time.Now().UTC()
	mockTimeProvider := mocks.NewMockTimeProvider(t)
	mockTimeProvider.EXPECT().GetTime().Return(currentTime).Maybe()

	testMessage := common.MessageWithMetadata{
		Message: protocol.Message{
			DestChainSelector:   1,
			SourceChainSelector: 2,
			SequenceNumber:      1,
		},
		Metadata: common.MessageMetadata{
			IngestionTimestamp: currentTime,
		},
	}

	results := make(chan common.MessageWithMetadata)
	messageSubscriber := mocks.NewMockMessageSubscriber(t)
	messageSubscriber.EXPECT().Start(mock.Anything).Return(results, nil, nil)

	unblockHandle := make(chan struct{})
	handleStarted := make(chan struct{})
	mockExecutor := mocks.NewMockExecutor(t)
	mockExecutor.EXPECT().Start(mock.Anything).Return(nil)
	mockExecutor.EXPECT().Close().Return(nil)
	mockExecutor.EXPECT().CheckValidMessage(mock.Anything, mock.Anything).Return(nil).Maybe()
	mockExecutor.EXPECT().HandleMessage(mock.Anything, mock.Anything).Run(func(context.Context, protocol.Message) {
		close(handleStarted)
		<-unblockHandle
	}).Return(false, nil).Once()

	leaderElector := mocks.NewMockLeaderElector(t)
	leaderElector.EXPECT().IsExecutorForChain(mock.Anything).Return(true).Maybe()
	leaderElector.EXPECT().GetReadyTimestamp(mock.Anything, mock.Anything, mock.Anything).Return(currentTime, nil).Maybe()
	leaderElector.EXPECT().GetRetryDelay(mock.Anything).Return(time.Second, nil).Maybe()

	ec, err := executor.NewCoordinator(
		lggr,
		"",
		mockExecutor,
		messageSubscriber,
		leaderElector,
		monitoring.NewNoopExecutorMonitoring(),
		8*time.Hour,
		mockTimeProvider,
		1,
		time.Second,
	)
	require.NoError(t, err)
	require.NotNil(t, ec)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	require.NoError(t, ec.Start(ctx))

	found := func(s string) bool {
		for _, entry := range hook.All() {
			if strings.Contains(fmt.Sprintf("%+v", entry), s) {
				return true
			}
		}
		return false
	}

	results <- testMessage
	require.Eventuallyf(t, func() bool {
		select {
		case <-handleStarted:
			return true
		default:
			return false
		}
	}, 3*time.Second, 50*time.Millisecond, "timed out waiting for HandleMessage to start")

	results <- testMessage
	require.Eventuallyf(t, func() bool {
		return found("message already in flight, skipping")
	}, 3*time.Second, 50*time.Millisecond, "expected skip log for duplicate in-flight message")

	close(unblockHandle)

	require.NoError(t, ec.Close())
	require.True(t, mock.AssertExpectationsForObjects(t, mockExecutor))
}

func TestClose_StopsReportingTickerOnContextDone(t *testing.T) {
	defer goleak.VerifyNone(t,
		goleak.IgnoreCurrent(),
	)

	lggr := logger.Test(t)
	mockTimeProvider := mocks.NewMockTimeProvider(t)
	mockTimeProvider.EXPECT().GetTime().Return(time.Now().UTC()).Maybe()

	messageSubscriber := mocks.NewMockMessageSubscriber(t)
	messageSubscriber.EXPECT().Start(mock.Anything).Return(nil, nil, nil)

	mockExecutor := mocks.NewMockExecutor(t)
	mockExecutor.EXPECT().Start(mock.Anything).Return(nil)
	mockExecutor.EXPECT().Close().Return(nil)

	ec, err := executor.NewCoordinator(
		lggr,
		"",
		mockExecutor,
		messageSubscriber,
		mocks.NewMockLeaderElector(t),
		monitoring.NewNoopExecutorMonitoring(),
		8*time.Hour,
		mockTimeProvider,
		1,
		time.Second,
	)
	require.NoError(t, err)
	require.NotNil(t, ec)

	require.NoError(t, ec.Start(t.Context()))
	require.NoError(t, ec.Ready())
	require.NoError(t, ec.Close())

	require.Eventuallyf(t, func() bool {
		return ec.Ready() != nil
	}, 2*time.Second, 50*time.Millisecond, "coordinator did not stop in time")
}

func TestDuplicateMessageIDFromStreamWhenAlreadyInHeap_IsSkippedByHeapAndHandleMessageCalledOnce(t *testing.T) {
	lggr := logger.Test(t)
	currentTime := time.Now().UTC()
	mockTimeProvider := mocks.NewMockTimeProvider(t)
	mockTimeProvider.EXPECT().GetTime().Return(currentTime).Maybe()

	testMessage := common.MessageWithMetadata{
		Message: protocol.Message{
			DestChainSelector:   1,
			SourceChainSelector: 2,
			SequenceNumber:      1,
		},
		Metadata: common.MessageMetadata{
			IngestionTimestamp: currentTime,
		},
	}

	results := make(chan common.MessageWithMetadata)
	messageSubscriber := mocks.NewMockMessageSubscriber(t)
	messageSubscriber.EXPECT().Start(mock.Anything).Return(results, nil, nil).Run(func(context.Context) {
		go func() {
			results <- testMessage
			results <- testMessage
		}()
	})

	mockExecutor := mocks.NewMockExecutor(t)
	mockExecutor.EXPECT().Start(mock.Anything).Return(nil)
	mockExecutor.EXPECT().Close().Return(nil)
	mockExecutor.EXPECT().CheckValidMessage(mock.Anything, mock.Anything).Return(nil).Maybe()
	handleCalled := make(chan struct{}, 1)
	mockExecutor.EXPECT().HandleMessage(mock.Anything, mock.Anything).Run(func(context.Context, protocol.Message) {
		handleCalled <- struct{}{}
	}).Return(false, nil).Once()

	leaderElector := mocks.NewMockLeaderElector(t)
	leaderElector.EXPECT().IsExecutorForChain(mock.Anything).Return(true).Maybe()
	leaderElector.EXPECT().GetReadyTimestamp(mock.Anything, mock.Anything, mock.Anything).Return(currentTime, nil).Maybe()
	leaderElector.EXPECT().GetRetryDelay(mock.Anything).Return(time.Second, nil).Maybe()

	ec, err := executor.NewCoordinator(
		lggr,
		"",
		mockExecutor,
		messageSubscriber,
		leaderElector,
		monitoring.NewNoopExecutorMonitoring(),
		8*time.Hour,
		mockTimeProvider,
		1,
		time.Second,
	)
	require.NoError(t, err)
	require.NotNil(t, ec)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	require.NoError(t, ec.Start(ctx))

	require.Eventuallyf(t, func() bool {
		select {
		case <-handleCalled:
			return true
		default:
			return false
		}
	}, 3*time.Second, 50*time.Millisecond, "timed out waiting for HandleMessage")

	require.NoError(t, ec.Close())
	require.True(t, mock.AssertExpectationsForObjects(t, mockExecutor))
}

func TestCoordinator_MessageSkippedWhenNotExecutorForChain_DoesNotCallGetReadyTimestamp(t *testing.T) {
	lggr := logger.Test(t)
	currentTime := time.Now().UTC()
	mockTimeProvider := mocks.NewMockTimeProvider(t)
	mockTimeProvider.EXPECT().GetTime().Return(currentTime).Maybe()

	testMessage := common.MessageWithMetadata{
		Message: protocol.Message{
			DestChainSelector:   1,
			SourceChainSelector: 2,
			SequenceNumber:      1,
		},
		Metadata: common.MessageMetadata{
			IngestionTimestamp: currentTime,
		},
	}

	results := make(chan common.MessageWithMetadata, 1)
	results <- testMessage
	messageSubscriber := mocks.NewMockMessageSubscriber(t)
	messageSubscriber.EXPECT().Start(mock.Anything).Return(results, nil, nil)

	mockExecutor := mocks.NewMockExecutor(t)
	mockExecutor.EXPECT().Start(mock.Anything).Return(nil)
	mockExecutor.EXPECT().Close().Return(nil)
	mockExecutor.EXPECT().CheckValidMessage(mock.Anything, mock.Anything).Return(nil).Maybe()

	leaderElector := mocks.NewMockLeaderElector(t)
	messageEvaluated := make(chan struct{}, 1)
	leaderElector.EXPECT().IsExecutorForChain(protocol.ChainSelector(1)).Run(func(protocol.ChainSelector) {
		messageEvaluated <- struct{}{}
	}).Return(false).Once()

	ec, err := executor.NewCoordinator(
		lggr,
		"",
		mockExecutor,
		messageSubscriber,
		leaderElector,
		monitoring.NewNoopExecutorMonitoring(),
		8*time.Hour,
		mockTimeProvider,
		1,
		time.Second,
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	require.NoError(t, ec.Start(ctx))
	require.Eventuallyf(t, func() bool {
		select {
		case <-messageEvaluated:
			return true
		default:
			return false
		}
	}, 3*time.Second, 50*time.Millisecond, "timed out waiting for message stream processing")
	require.NoError(t, ec.Close())

	leaderElector.AssertNotCalled(t, "GetReadyTimestamp")
	leaderElector.AssertNotCalled(t, "GetRetryDelay")
}

// TestGracefulShutdown tests that when Close() is called while a message is being processed, the processing loop will
// shut down gracefully. This state is simulated by blocking the HandleMessage() call until Close() is called, and then
// asserting that we logged the message about dropping a payload to exit.
func TestGracefulShutdown(t *testing.T) {
	lggr, hook := logger.TestObserved(t, zapcore.InfoLevel)
	currentTime := time.Now().UTC()
	mockTimeProvider := mocks.NewMockTimeProvider(t)
	mockTimeProvider.EXPECT().GetTime().Return(currentTime).Maybe()

	seqNum := uint64(0)
	messageGenerator := func() common.MessageWithMetadata {
		seqNum++
		return common.MessageWithMetadata{
			Message: protocol.Message{
				DestChainSelector:   1,
				SourceChainSelector: 2,
				SequenceNumber:      protocol.SequenceNumber(seqNum),
			},
			Metadata: common.MessageMetadata{
				IngestionTimestamp: currentTime,
			},
		}
	}

	results := make(chan common.MessageWithMetadata, 1)
	go func() {
		results <- messageGenerator() // will be blocked in HandleMessage.
		results <- messageGenerator() // will be stuck in the executor heap and trigger the "dropping payload" log.
	}()
	messageSubscriber := mocks.NewMockMessageSubscriber(t)
	messageSubscriber.EXPECT().Start(mock.Anything).Return(results, nil, nil)

	handlerBlockedHandle := make(chan struct{})
	mockExecutor := mocks.NewMockExecutor(t)
	mockExecutor.EXPECT().Start(mock.Anything).Return(nil)
	mockExecutor.EXPECT().Close().Return(nil)
	mockExecutor.EXPECT().CheckValidMessage(mock.Anything, mock.Anything).Return(nil).Maybe()
	mockExecutor.EXPECT().HandleMessage(mock.Anything, mock.Anything).Run(func(ctx context.Context, msg protocol.Message) {
		close(handlerBlockedHandle)
		<-ctx.Done() // the coordinator will cancel the context when Close() is called, which will unblock this
	}).Return(false, context.Canceled)

	leaderElector := mocks.NewMockLeaderElector(t)
	leaderElector.EXPECT().IsExecutorForChain(mock.Anything).Return(true).Maybe()
	leaderElector.EXPECT().GetReadyTimestamp(mock.Anything, mock.Anything, mock.Anything).Return(currentTime, nil).Maybe()
	leaderElector.EXPECT().GetRetryDelay(mock.Anything).Return(time.Second, nil).Maybe()

	ec, err := executor.NewCoordinator(
		lggr,
		"",
		mockExecutor,
		messageSubscriber,
		leaderElector,
		monitoring.NewNoopExecutorMonitoring(),
		8*time.Hour,
		mockTimeProvider,
		1,
		time.Second,
	)
	require.NoError(t, err)
	require.NotNil(t, ec)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	require.NoError(t, ec.Start(ctx))

	// Wait for the handler to be blocked to ensure we are in the state we want before calling Close().
	require.Eventuallyf(t, func() bool {
		select {
		case <-handlerBlockedHandle:
			return true
		default:
			return false
		}
	}, tests.WaitTimeout(t), 50*time.Millisecond, "timed out waiting for handler to block")

	require.NoError(t, ec.Close())

	// Assert that we logged the message about dropping a payload.
	found := func() bool {
		for _, entry := range hook.All() {
			entryStr := fmt.Sprintf("%+v", entry)
			if strings.Contains(entryStr, "Processing loop dropping payload to exit") {
				return true
			}
		}
		return false
	}
	require.Eventuallyf(t, found, tests.WaitTimeout(t), 100*time.Millisecond, "dropped payload log never seen")
}

func TestRetry_DataNotReadyReattemptsBeforeStaggerInterval(t *testing.T) {
	lggr := logger.Test(t)
	var (
		currentTimeMu sync.Mutex
		currentTime   = time.Now().UTC()
	)
	advanceTime := func(d time.Duration) {
		currentTimeMu.Lock()
		currentTime = currentTime.Add(d)
		currentTimeMu.Unlock()
	}
	getTime := func() time.Time {
		currentTimeMu.Lock()
		defer currentTimeMu.Unlock()
		return currentTime
	}

	mockTimeProvider := mocks.NewMockTimeProvider(t)
	mockTimeProvider.EXPECT().GetTime().RunAndReturn(func() time.Time {
		return getTime()
	}).Maybe()

	testMessage := common.MessageWithMetadata{
		Message: protocol.Message{
			DestChainSelector:   1,
			SourceChainSelector: 2,
			SequenceNumber:      1,
		},
		Metadata: common.MessageMetadata{
			IngestionTimestamp: getTime(),
		},
	}

	results := make(chan common.MessageWithMetadata, 1)
	messageSubscriber := mocks.NewMockMessageSubscriber(t)
	messageSubscriber.EXPECT().Start(mock.Anything).Return(results, nil, nil)

	handleCalls := make(chan struct{}, 2)
	mockExecutor := mocks.NewMockExecutor(t)
	mockExecutor.EXPECT().Start(mock.Anything).Return(nil)
	mockExecutor.EXPECT().Close().Return(nil)
	mockExecutor.EXPECT().CheckValidMessage(mock.Anything, mock.Anything).Return(nil).Maybe()
	mockExecutor.EXPECT().HandleMessage(mock.Anything, mock.Anything).Run(func(context.Context, protocol.Message) {
		handleCalls <- struct{}{}
		advanceTime(2 * time.Second)
	}).Return(true, fmt.Errorf("not ready")).Once()
	mockExecutor.EXPECT().HandleMessage(mock.Anything, mock.Anything).Run(func(context.Context, protocol.Message) {
		handleCalls <- struct{}{}
	}).Return(false, nil).Once()

	staggerInterval := 30 * time.Second
	leaderElector := mocks.NewMockLeaderElector(t)
	leaderElector.EXPECT().IsExecutorForChain(mock.Anything).Return(true).Maybe()
	leaderElector.EXPECT().GetReadyTimestamp(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(
		func(protocol.Bytes32, protocol.ChainSelector, time.Time) (time.Time, error) {
			return getTime(), nil
		},
	).Maybe()
	leaderElector.EXPECT().GetRetryDelay(mock.Anything).Return(staggerInterval, nil).Maybe()

	ec, err := executor.NewCoordinator(
		lggr,
		"",
		mockExecutor,
		messageSubscriber,
		leaderElector,
		monitoring.NewNoopExecutorMonitoring(),
		8*time.Hour,
		mockTimeProvider,
		1,
		time.Second,
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, ec.Start(ctx))

	results <- testMessage

	require.Eventuallyf(t, func() bool {
		select {
		case <-handleCalls:
			return true
		default:
			return false
		}
	}, 3*time.Second, 50*time.Millisecond, "timed out waiting for first HandleMessage call")

	// First HandleMessage already advanced mock time by 2s; retry is scheduled 1s later.
	// Advance past that ready time so the next processing tick can re-attempt.
	advanceTime(2 * time.Second)

	require.Eventuallyf(t, func() bool {
		select {
		case <-handleCalls:
			return true
		default:
			return false
		}
	}, 3*time.Second, 50*time.Millisecond, "timed out waiting for data-not-ready retry before stagger interval")

	require.NoError(t, ec.Close())
}
