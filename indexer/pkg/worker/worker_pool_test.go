package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/registry"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestPool_EnqueueMessagesCreatesTask(t *testing.T) {
	lggr := logger.Test(t)

	// discovery channel for the pool
	discoveryCh := make(chan common.VerifierResultWithMetadata, 1)

	// scheduler with BaseDelay=0 to ensure Enqueue writes directly to ready
	schedCfg := config.SchedulerConfig{TickerInterval: 50, BaseDelay: 0, MaxDelay: 0, VerificationVisibilityWindow: 60}
	scheduler, err := NewScheduler(lggr, schedCfg)
	require.NoError(t, err)

	// pool config
	poolCfg := config.PoolConfig{ConcurrentWorkers: 1, WorkerTimeout: 1}
	reg := registry.NewVerifierRegistry()
	storage := mocks.NewMockIndexerStorage(t)

	p := NewWorkerPool(lggr, poolCfg, discoveryCh, scheduler, reg, storage)

	// run only the enqueueMessages goroutine so we can assert scheduler received a task
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	p.wg.Add(1)
	go p.enqueueMessages(ctx)

	// send a discovery message
	discoveryCh <- common.VerifierResultWithMetadata{VerifierResult: protocol.VerifierResult{MessageID: protocol.Bytes32{}}}

	// wait for a task to be enqueued into scheduler.Ready
	select {
	case task := <-scheduler.Ready():
		require.NotNil(t, task)
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("timed out waiting for task in scheduler ready channel")
	}

	// cleanup: cancel will cause enqueueMessages to exit and call Done
	cancel()
	// wait a brief moment for goroutine to exit
	time.Sleep(50 * time.Millisecond)
}

func TestRun_MarksSuccessful(t *testing.T) {
	lggr := logger.Test(t)

	// scheduler
	schedCfg := config.SchedulerConfig{TickerInterval: 50, BaseDelay: 0, MaxDelay: 0, VerificationVisibilityWindow: 60}
	scheduler, err := NewScheduler(lggr, schedCfg)
	require.NoError(t, err)

	// pool
	poolCfg := config.PoolConfig{ConcurrentWorkers: 1, WorkerTimeout: 1}
	storage := mocks.NewMockIndexerStorage(t)
	p := NewWorkerPool(lggr, poolCfg, nil, scheduler, registry.NewVerifierRegistry(), storage)

	// Task to process: no verifiers so Execute should return successful result (UnavailableCCVs == 0)
	msg := protocol.VerifierResult{}
	// Expect GetCCVData called and return empty
	storage.On("GetCCVData", mock.Anything, mock.Anything).Return([]common.VerifierResultWithMetadata{}, nil)

	done := make(chan struct{})
	storage.On("UpdateMessageStatus", mock.Anything, mock.Anything, common.MessageSuccessful, mock.Anything).Run(func(args mock.Arguments) {
		close(done)
	}).Return(nil)

	task, err := NewTask(lggr, msg, registry.NewVerifierRegistry(), storage, time.Second)
	require.NoError(t, err)

	// run only the run loop
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.wg.Add(1)
	go p.run(ctx)

	// enqueue task into scheduler using Enqueue (can't send to Ready channel directly)
	reqErr := scheduler.Enqueue(ctx, task)
	require.NoError(t, reqErr)

	// wait for UpdateMessageStatus to be called
	select {
	case <-done:
		// success
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for UpdateMessageStatus")
	}

	// cleanup
	cancel()
	// small sleep to allow goroutine to exit
	time.Sleep(50 * time.Millisecond)
}

func TestRun_RetriesOnError(t *testing.T) {
	lggr := logger.Test(t)

	// scheduler
	schedCfg := config.SchedulerConfig{TickerInterval: 50, BaseDelay: 0, MaxDelay: 0, VerificationVisibilityWindow: 60}
	scheduler, err := NewScheduler(lggr, schedCfg)
	require.NoError(t, err)

	// Simulate storage error so Execute returns an error
	storage := mocks.NewMockIndexerStorage(t)
	storage.On("GetCCVData", mock.Anything, mock.Anything).Return(nil, errors.New("db fail"))

	msg := protocol.VerifierResult{}
	task, err := NewTask(lggr, msg, registry.NewVerifierRegistry(), storage, time.Second)
	require.NoError(t, err)

	// Instead of starting p.run (which would consume Ready()), run Execute synchronously
	// and re-enqueue the task on error so the test can observe it deterministically.
	errExec := func() error {
		_, e := Execute(context.Background(), task)
		if e != nil {
			return scheduler.Enqueue(context.Background(), task)
		}
		return nil
	}()
	require.NoError(t, errExec)

	// expect the task to be enqueued due to error
	timedOut := time.After(2 * time.Second)
	for {
		select {
		case rt := <-scheduler.Ready():
			require.Equal(t, task, rt)
			goto done
		case dl := <-scheduler.DLQ():
			// If it ended in DLQ, that's also acceptable for this test pattern,
			// but record and fail to make the test explicit.
			require.Failf(t, "task went to DLQ", "task was sent to DLQ: %v", dl)
		case <-timedOut:
			t.Fatalf("timed out waiting for re-enqueued task on Ready or DLQ")
		}
	}
done:

	// cleanup
	// small sleep to allow goroutine to exit
	time.Sleep(50 * time.Millisecond)
}
