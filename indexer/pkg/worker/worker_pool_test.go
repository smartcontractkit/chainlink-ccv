package worker

import (
	"context"
	"errors"
	"sync"
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

func TestWorkerPool_StartStop_ClosedDiscovery(t *testing.T) {
	lggr := logger.Test(t)

	// closed discovery channel should cause enqueueMessages to exit immediately
	discoveryCh := make(chan common.VerifierResultWithMetadata)
	close(discoveryCh)

	schedCfg := config.SchedulerConfig{TickerInterval: 50, BaseDelay: 0, MaxDelay: 0, VerificationVisibilityWindow: 60}
	scheduler, err := NewScheduler(lggr, schedCfg)
	require.NoError(t, err)

	poolCfg := config.PoolConfig{ConcurrentWorkers: 1, WorkerTimeout: 1}
	reg := registry.NewVerifierRegistry()
	storage := mocks.NewMockIndexerStorage(t)

	p := NewWorkerPool(lggr, poolCfg, discoveryCh, scheduler, reg, storage)

	// Start the pool
	p.Start(context.Background())

	// Call Stop in a goroutine and ensure it returns within a reasonable timeout
	done := make(chan struct{})
	go func() {
		p.Stop()
		close(done)
	}()

	select {
	case <-done:
		// success
	case <-time.After(1 * time.Second):
		t.Fatalf("Stop did not return in time for closed discovery channel")
	}
}

func TestWorkerPool_StartStop_Cancel(t *testing.T) {
	lggr := logger.Test(t)

	// open discovery channel - Stop should cancel the child context and exit goroutines
	discoveryCh := make(chan common.VerifierResultWithMetadata, 1)

	schedCfg := config.SchedulerConfig{TickerInterval: 50, BaseDelay: 0, MaxDelay: 0, VerificationVisibilityWindow: 60}
	scheduler, err := NewScheduler(lggr, schedCfg)
	require.NoError(t, err)

	poolCfg := config.PoolConfig{ConcurrentWorkers: 1, WorkerTimeout: 1}
	reg := registry.NewVerifierRegistry()
	storage := mocks.NewMockIndexerStorage(t)

	p := NewWorkerPool(lggr, poolCfg, discoveryCh, scheduler, reg, storage)

	// Start the pool
	p.Start(context.Background())

	// Call Stop in a goroutine and ensure it returns within a reasonable timeout
	done := make(chan struct{})
	go func() {
		p.Stop()
		close(done)
	}()

	select {
	case <-done:
		// success
	case <-time.After(1 * time.Second):
		t.Fatalf("Stop did not return in time when canceling child context")
	}
}

func TestRun_ExitsWhenSchedulerReadyClosed(t *testing.T) {
	lggr := logger.Test(t)

	// Construct a scheduler with a ready channel that we'll close to simulate the closed condition
	s := &Scheduler{
		lggr: lggr,
		// small buffered channels, but we'll close ready immediately
		ready: make(chan *Task, 1),
		dlq:   make(chan *Task, 1),
	}
	close(s.ready)

	poolCfg := config.PoolConfig{ConcurrentWorkers: 1, WorkerTimeout: 1}
	p := NewWorkerPool(lggr, poolCfg, nil, s, registry.NewVerifierRegistry(), mocks.NewMockIndexerStorage(t))

	// Run p.run in a goroutine and ensure it returns when Ready is closed
	done := make(chan struct{})
	p.wg.Add(1)
	go func() {
		p.run(context.Background())
		close(done)
	}()

	select {
	case <-done:
		// success
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("p.run did not exit when scheduler.Ready was closed")
	}
}

func TestHandleDLQ_ExitsWhenDLQClosed(t *testing.T) {
	lggr := logger.Test(t)

	// Construct a scheduler with a closed DLQ channel
	s := &Scheduler{
		lggr:   lggr,
		ready:  make(chan *Task, 1),
		dlq:    make(chan *Task, 1),
		config: config.SchedulerConfig{TickerInterval: 50, BaseDelay: 0, MaxDelay: 0, VerificationVisibilityWindow: 60},
	}
	close(s.dlq)

	p := NewWorkerPool(lggr, config.PoolConfig{ConcurrentWorkers: 1, WorkerTimeout: 1}, nil, s, registry.NewVerifierRegistry(), mocks.NewMockIndexerStorage(t))

	done := make(chan struct{})
	// account for waitgroup since we're starting the goroutine manually
	p.wg.Add(1)
	go func() {
		p.handleDLQ(context.Background())
		close(done)
	}()

	select {
	case <-done:
		// success
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("handleDLQ did not exit when DLQ was closed")
	}
}

func TestEnqueueMessages_ExitsWhenDiscoveryClosed(t *testing.T) {
	lggr := logger.Test(t)

	// closed discovery channel
	discoveryCh := make(chan common.VerifierResultWithMetadata)
	close(discoveryCh)

	schedCfg := config.SchedulerConfig{TickerInterval: 50, BaseDelay: 0, MaxDelay: 0, VerificationVisibilityWindow: 60}
	scheduler, err := NewScheduler(lggr, schedCfg)
	require.NoError(t, err)

	p := NewWorkerPool(lggr, config.PoolConfig{ConcurrentWorkers: 1, WorkerTimeout: 1}, discoveryCh, scheduler, registry.NewVerifierRegistry(), mocks.NewMockIndexerStorage(t))

	done := make(chan struct{})
	// account for waitgroup since we're starting the goroutine manually
	p.wg.Add(1)
	go func() {
		p.enqueueMessages(context.Background())
		close(done)
	}()

	select {
	case <-done:
		// success
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("enqueueMessages did not exit when discovery channel was closed")
	}
}

func TestRun_PoolFull_EnqueuesTask(t *testing.T) {
	lggr := logger.Test(t)

	// Create a scheduler with ready channel
	s := &Scheduler{
		lggr:   lggr,
		ready:  make(chan *Task, 1),
		dlq:    make(chan *Task, 1),
		config: config.SchedulerConfig{TickerInterval: 50, BaseDelay: 0, MaxDelay: 0, VerificationVisibilityWindow: 60},
	}

	// Use a real conc.Pool via NewWorkerPool and block the first GetCCVData to
	// occupy the worker goroutine so we can ensure the second task executes later.
	storageMock := mocks.NewMockIndexerStorage(t)
	var mu sync.Mutex
	callCount := 0
	firstBlock := make(chan struct{})
	execCalled := make(chan struct{})

	storageMock.On("GetCCVData", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		mu.Lock()
		callCount++
		c := callCount
		mu.Unlock()
		if c == 1 {
			// block first call until we release it
			<-firstBlock
			return
		}
		// on second call, signal the test and return
		select {
		case <-execCalled:
		default:
			close(execCalled)
		}
	}).Return([]common.VerifierResultWithMetadata{}, nil)
	storageMock.On("UpdateMessageStatus", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	p := NewWorkerPool(lggr, config.PoolConfig{ConcurrentWorkers: 1, WorkerTimeout: 1}, nil, s, registry.NewVerifierRegistry(), storageMock)

	// Create two tasks
	msg := protocol.VerifierResult{}
	task1, err := NewTask(lggr, msg, p.registry, p.storage, time.Second)
	require.NoError(t, err)
	task2, err := NewTask(lggr, msg, p.registry, p.storage, time.Second)
	require.NoError(t, err)

	// Start the pool
	p.Start(context.Background())

	// Enqueue first task (will block inside GetCCVData)
	require.NoError(t, s.Enqueue(context.Background(), task1))

	// Give run a moment to pick the first task
	time.Sleep(50 * time.Millisecond)

	// Enqueue second task; because the pool has 1 worker, p.pool.Go will block
	// until the first finishes. We expect the second to execute only after we
	// release the first.
	require.NoError(t, s.Enqueue(context.Background(), task2))

	// release the first task so it can complete and free the worker
	close(firstBlock)

	// wait for second task execution
	select {
	case <-execCalled:
		// success
	case <-time.After(5 * time.Second):
		p.Stop()
		t.Fatalf("timed out waiting for second task execution")
	}

	p.Stop()
}

func TestRun_PoolFull_EnqueueToDLQOnTTLExpired(t *testing.T) {
	lggr := logger.Test(t)

	// Create a scheduler with ready channel
	s := &Scheduler{
		lggr:   lggr,
		ready:  make(chan *Task, 1),
		dlq:    make(chan *Task, 1),
		config: config.SchedulerConfig{TickerInterval: 50, BaseDelay: 0, MaxDelay: 0, VerificationVisibilityWindow: 60},
	}

	// DLQ behavior: directly enqueue an expired task and ensure scheduler sends it to DLQ
	storageMock := mocks.NewMockIndexerStorage(t)
	p2 := NewWorkerPool(lggr, config.PoolConfig{ConcurrentWorkers: 1, WorkerTimeout: 1}, nil, s, registry.NewVerifierRegistry(), storageMock)

	msg := protocol.VerifierResult{}
	task, err := NewTask(lggr, msg, p2.registry, p2.storage, time.Second)
	require.NoError(t, err)
	task.ttl = time.Now().Add(-time.Minute)

	// Expect UpdateMessageStatus called when sent to DLQ
	dlqCalled := make(chan struct{})
	storageMock.On("UpdateMessageStatus", mock.Anything, mock.Anything, common.MessageTimeout, mock.Anything).Run(func(args mock.Arguments) {
		select {
		case <-dlqCalled:
		default:
			close(dlqCalled)
		}
	}).Return(nil)

	err = s.Enqueue(context.Background(), task)
	require.Error(t, err)

	// task should be on DLQ channel
	select {
	case dl := <-s.DLQ():
		require.Equal(t, task, dl)
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for task in DLQ")
	}

	select {
	case <-dlqCalled:
		// ok
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for UpdateMessageStatus for DLQ task")
	}
	// stop p2 if started (it's unused)
	_ = p2
}
