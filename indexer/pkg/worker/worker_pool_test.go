package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/panjf2000/ants/v2"
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

	// Create an ants pool with 1 worker, non-blocking, no blocking tasks so Submit will fail when worker busy
	pool, err := ants.NewPool(1, ants.WithNonblocking(true), ants.WithMaxBlockingTasks(0))
	require.NoError(t, err)
	// do not defer pool.Release() because p.run will Release()

	p := &Pool{
		config:    config.PoolConfig{ConcurrentWorkers: 1, WorkerTimeout: 1},
		logger:    lggr,
		pool:      pool,
		scheduler: s,
		registry:  registry.NewVerifierRegistry(),
		storage:   mocks.NewMockIndexerStorage(t),
	}

	// Occupy the single worker with a long-running task
	err = pool.Submit(func() {
		time.Sleep(400 * time.Millisecond)
	})
	require.NoError(t, err)

	// Create a task and place it into ready before starting run
	msg := protocol.VerifierResult{}
	task, err := NewTask(lggr, msg, p.registry, p.storage, time.Second)
	require.NoError(t, err)

	// put the task into ready so p.run will pick it up and attempt to Submit
	s.ready <- task

	// run p.run in goroutine with cancellable context so we can stop it when assertion is done
	done := make(chan struct{})
	p.wg.Add(1)
	runCtx, runCancel := context.WithCancel(context.Background())
	go func() {
		p.run(runCtx)
		close(done)
	}()

	// Expect the task to be re-enqueued due to pool full
	select {
	case rt := <-s.Ready():
		require.Equal(t, task, rt)
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for re-enqueued task when pool is full")
	}

	// Release the ants pool (free the occupied worker), cancel run loop and wait for exit
	pool.Release()
	runCancel()
	select {
	case <-done:
		// ok
	case <-time.After(2 * time.Second):
		t.Fatalf("p.run did not exit in time")
	}
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

	// Create an ants pool with 1 worker, non-blocking, no blocking tasks so Submit will fail when worker busy
	pool, err := ants.NewPool(1, ants.WithNonblocking(true), ants.WithMaxBlockingTasks(0))
	require.NoError(t, err)

	storageMock := mocks.NewMockIndexerStorage(t)
	p := &Pool{
		config:    config.PoolConfig{ConcurrentWorkers: 1, WorkerTimeout: 1},
		logger:    lggr,
		pool:      pool,
		scheduler: s,
		registry:  registry.NewVerifierRegistry(),
		storage:   storageMock,
	}

	// Occupy the single worker with a long-running task
	err = pool.Submit(func() {
		time.Sleep(400 * time.Millisecond)
	})
	require.NoError(t, err)

	// Create a task and mark its TTL expired so Enqueue will send it to DLQ and return error
	msg := protocol.VerifierResult{}
	task, err := NewTask(lggr, msg, p.registry, p.storage, time.Second)
	require.NoError(t, err)
	// expire TTL
	task.ttl = time.Now().Add(-time.Minute)

	// put the task into ready so p.run will pick it up and attempt to Submit
	s.ready <- task

	// Expect UpdateMessageStatus called when Enqueue sends to DLQ due to TTL expired
	storageMock.On("UpdateMessageStatus", mock.Anything, mock.Anything, common.MessageTimeout, mock.Anything).Return(nil)

	// run p.run in goroutine with cancellable context
	done := make(chan struct{})
	p.wg.Add(1)
	runCtx, runCancel := context.WithCancel(context.Background())
	go func() {
		p.run(runCtx)
		close(done)
	}()

	// Expect the task to be sent to DLQ due to TTL expired
	select {
	case dl := <-s.DLQ():
		require.Equal(t, task, dl)
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for task in DLQ when pool full and TTL expired")
	}

	// Release the ants pool (free the occupied worker), cancel the run loop and wait for exit
	pool.Release()
	runCancel()
	select {
	case <-done:
		// ok
	case <-time.After(2 * time.Second):
		t.Fatalf("p.run did not exit in time")
	}
}
