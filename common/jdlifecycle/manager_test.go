package jdlifecycle

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	pb "github.com/smartcontractkit/chainlink-protos/orchestrator/feedsmanager"

	"github.com/smartcontractkit/chainlink-ccv/common/jobstore"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// testSetup holds common test dependencies.
type testSetup struct {
	jdClient   *mocks.MockClientInterface
	jobStore   *mocks.MockStoreInterface
	runner     *mocks.MockJobRunner
	lggr       logger.Logger
	proposalCh chan *pb.ProposeJobRequest
	deleteCh   chan *pb.DeleteJobRequest
	revokeCh   chan *pb.RevokeJobRequest
}

func newTestSetup(t *testing.T) *testSetup {
	lggr, err := logger.New()
	require.NoError(t, err)

	return &testSetup{
		jdClient:   mocks.NewMockClientInterface(t),
		jobStore:   mocks.NewMockStoreInterface(t),
		runner:     mocks.NewMockJobRunner(t),
		lggr:       lggr,
		proposalCh: make(chan *pb.ProposeJobRequest, 10),
		deleteCh:   make(chan *pb.DeleteJobRequest, 10),
		revokeCh:   make(chan *pb.RevokeJobRequest, 10),
	}
}

func (ts *testSetup) newManager() *Manager {
	return NewManager(Config{
		JDClient: ts.jdClient,
		JobStore: ts.jobStore,
		Runner:   ts.runner,
		Logger:   ts.lggr,
	})
}

func (ts *testSetup) setupChannelMocks() {
	ts.jdClient.EXPECT().JobProposalCh().Return(ts.proposalCh).Maybe()
	ts.jdClient.EXPECT().DeleteJobCh().Return(ts.deleteCh).Maybe()
	ts.jdClient.EXPECT().RevokeJobCh().Return(ts.revokeCh).Maybe()
}

// =============================================================================
// State Management Tests
// =============================================================================

func TestNewManager_InitialState(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)

	manager := ts.newManager()

	assert.Equal(t, StateWaitingForJob, manager.GetState())
	assert.Nil(t, manager.GetCurrentJob())
}

func TestGetState_ThreadSafe(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	manager := ts.newManager()

	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			_ = manager.GetState()
		})
	}
	wg.Wait()
	// If we get here without race detector complaints, test passes
}

func TestGetCurrentJob_ReturnsNilWhenNoJob(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	manager := ts.newManager()

	job := manager.GetCurrentJob()

	assert.Nil(t, job)
}

func TestGetCurrentJob_ReturnsCopy(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	manager := ts.newManager()

	// Manually set a job via internal state (for testing purposes)
	manager.mu.Lock()
	manager.currentJob = &jobstore.Job{
		ProposalID: "test-id",
		Version:    1,
		Spec:       "test-spec",
	}
	manager.state = StateRunning
	manager.mu.Unlock()

	// Get copy
	job1 := manager.GetCurrentJob()
	job2 := manager.GetCurrentJob()

	// Verify they are equal
	assert.Equal(t, job1.ProposalID, job2.ProposalID)

	// Modify one
	job1.ProposalID = "modified"

	// Verify the other is unchanged
	assert.Equal(t, "test-id", job2.ProposalID)
	assert.Equal(t, "test-id", manager.GetCurrentJob().ProposalID)
}

func TestState_String(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "WaitingForJob", StateWaitingForJob.String())
	assert.Equal(t, "Running", StateRunning.String())
	assert.Equal(t, "Unknown", State(99).String())
}

// =============================================================================
// Cached Job Recovery Tests
// =============================================================================

func TestRun_WithCachedJob_StartsImmediately(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	manager := ts.newManager()

	cachedJob := &jobstore.Job{
		ProposalID: "cached-job-1",
		Version:    1,
		Spec:       "cached-spec",
	}

	// Setup expectations
	ts.jobStore.EXPECT().LoadJob(mock.Anything).Return(cachedJob, nil).Once()
	ts.runner.EXPECT().StartJob(mock.Anything, "cached-spec").Return(nil).Once()
	ts.jdClient.EXPECT().Connect(mock.Anything).Return(nil).Once()
	ts.setupChannelMocks()
	ts.jdClient.EXPECT().Close().Return(nil).Once()
	ts.runner.EXPECT().StopJob(mock.Anything).Return(nil).Once()

	// Run manager in goroutine
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- manager.Run(ctx)
	}()

	// Wait for state to become Running
	require.Eventually(t, func() bool {
		return manager.GetState() == StateRunning
	}, time.Second, 10*time.Millisecond)

	// Verify job is set
	job := manager.GetCurrentJob()
	require.NotNil(t, job)
	assert.Equal(t, "cached-job-1", job.ProposalID)

	// Shutdown
	cancel()
	err := <-errCh
	assert.NoError(t, err)
}

func TestRun_WithCachedJob_FailsIfStartFails(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	manager := ts.newManager()

	cachedJob := &jobstore.Job{
		ProposalID: "cached-job-1",
		Version:    1,
		Spec:       "cached-spec",
	}

	// Setup expectations
	ts.jobStore.EXPECT().LoadJob(mock.Anything).Return(cachedJob, nil).Once()
	ts.runner.EXPECT().StartJob(mock.Anything, "cached-spec").Return(errors.New("start failed")).Once()

	// Run should fail
	ctx := context.Background()
	err := manager.Run(ctx)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to start cached job")
}

func TestRun_NoCachedJob_WaitsForProposal(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	manager := ts.newManager()

	// Setup expectations - no cached job
	ts.jobStore.EXPECT().LoadJob(mock.Anything).Return(nil, jobstore.ErrNoJob).Once()
	ts.jdClient.EXPECT().Connect(mock.Anything).Return(nil).Once()
	ts.setupChannelMocks()
	ts.jdClient.EXPECT().Close().Return(nil).Once()

	// Run manager in goroutine
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- manager.Run(ctx)
	}()

	// Wait a bit for manager to start
	time.Sleep(50 * time.Millisecond)

	// Should still be waiting for job
	assert.Equal(t, StateWaitingForJob, manager.GetState())
	assert.Nil(t, manager.GetCurrentJob())

	// Shutdown
	cancel()
	err := <-errCh
	assert.NoError(t, err)
}

func TestRun_LoadJobError_ReturnsError(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	manager := ts.newManager()

	// Setup expectations - DB error
	ts.jobStore.EXPECT().LoadJob(mock.Anything).Return(nil, errors.New("db connection failed")).Once()

	// Run should fail
	ctx := context.Background()
	err := manager.Run(ctx)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load cached job")
}

// =============================================================================
// JD Connection Tests
// =============================================================================

func TestRun_JDConnectionFails_WithCachedJob_Continues(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	manager := ts.newManager()

	cachedJob := &jobstore.Job{
		ProposalID: "cached-job-1",
		Version:    1,
		Spec:       "cached-spec",
	}

	// Setup expectations
	ts.jobStore.EXPECT().LoadJob(mock.Anything).Return(cachedJob, nil).Once()
	ts.runner.EXPECT().StartJob(mock.Anything, "cached-spec").Return(nil).Once()
	ts.jdClient.EXPECT().Connect(mock.Anything).Return(errors.New("connection failed")).Once()
	ts.setupChannelMocks()
	ts.jdClient.EXPECT().Close().Return(nil).Once()
	ts.runner.EXPECT().StopJob(mock.Anything).Return(nil).Once()

	// Run manager in goroutine
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- manager.Run(ctx)
	}()

	// Wait for state to become Running (job should still start despite JD failure)
	require.Eventually(t, func() bool {
		return manager.GetState() == StateRunning
	}, time.Second, 10*time.Millisecond)

	// Shutdown
	cancel()
	err := <-errCh
	assert.NoError(t, err)
}

func TestRun_JDConnectionFails_NoCachedJob_ReturnsError(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	manager := ts.newManager()

	// Setup expectations - no cached job, JD fails
	ts.jobStore.EXPECT().LoadJob(mock.Anything).Return(nil, jobstore.ErrNoJob).Once()
	ts.jdClient.EXPECT().Connect(mock.Anything).Return(errors.New("connection failed")).Once()

	// Run should fail
	ctx := context.Background()
	err := manager.Run(ctx)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to connect to JD")
}

// =============================================================================
// Job Proposal Handling Tests
// =============================================================================

func TestHandleProposal_FirstJob_StartsAndPersists(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	manager := ts.newManager()

	// Setup expectations
	ts.jobStore.EXPECT().LoadJob(mock.Anything).Return(nil, jobstore.ErrNoJob).Once()
	ts.jdClient.EXPECT().Connect(mock.Anything).Return(nil).Once()
	ts.setupChannelMocks()
	ts.runner.EXPECT().StartJob(mock.Anything, "new-spec").Return(nil).Once()
	ts.jobStore.EXPECT().SaveJob(mock.Anything, "proposal-1", int64(1), "new-spec").Return(nil).Once()
	ts.jdClient.EXPECT().ApproveJob(mock.Anything, "proposal-1", int64(1)).Return(nil).Once()
	ts.jdClient.EXPECT().Close().Return(nil).Once()
	ts.runner.EXPECT().StopJob(mock.Anything).Return(nil).Once()

	// Run manager in goroutine
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- manager.Run(ctx)
	}()

	// Wait for manager to be ready
	time.Sleep(50 * time.Millisecond)

	// Send proposal
	ts.proposalCh <- &pb.ProposeJobRequest{
		Id:      "proposal-1",
		Version: 1,
		Spec:    "new-spec",
	}

	// Wait for state to become Running
	require.Eventually(t, func() bool {
		return manager.GetState() == StateRunning
	}, time.Second, 10*time.Millisecond)

	// Verify job is set
	job := manager.GetCurrentJob()
	require.NotNil(t, job)
	assert.Equal(t, "proposal-1", job.ProposalID)
	assert.Equal(t, int64(1), job.Version)

	// Shutdown
	cancel()
	err := <-errCh
	assert.NoError(t, err)
}

func TestHandleProposal_ReplacementJob_StopsOldStartsNew(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	manager := ts.newManager()

	cachedJob := &jobstore.Job{
		ProposalID: "old-job",
		Version:    1,
		Spec:       "old-spec",
	}

	// Setup expectations for cached job
	ts.jobStore.EXPECT().LoadJob(mock.Anything).Return(cachedJob, nil).Once()
	ts.runner.EXPECT().StartJob(mock.Anything, "old-spec").Return(nil).Once()
	ts.jdClient.EXPECT().Connect(mock.Anything).Return(nil).Once()
	ts.setupChannelMocks()

	// Expectations for replacement job
	ts.runner.EXPECT().StopJob(mock.Anything).Return(nil).Once() // Stop old job
	ts.runner.EXPECT().StartJob(mock.Anything, "new-spec").Return(nil).Once()
	ts.jobStore.EXPECT().SaveJob(mock.Anything, "new-job", int64(2), "new-spec").Return(nil).Once()
	ts.jdClient.EXPECT().ApproveJob(mock.Anything, "new-job", int64(2)).Return(nil).Once()

	// Shutdown expectations
	ts.jdClient.EXPECT().Close().Return(nil).Once()
	ts.runner.EXPECT().StopJob(mock.Anything).Return(nil).Once()

	// Run manager in goroutine
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- manager.Run(ctx)
	}()

	// Wait for state to become Running with old job
	require.Eventually(t, func() bool {
		return manager.GetState() == StateRunning
	}, time.Second, 10*time.Millisecond)

	// Send replacement proposal
	ts.proposalCh <- &pb.ProposeJobRequest{
		Id:      "new-job",
		Version: 2,
		Spec:    "new-spec",
	}

	// Wait for new job to be set
	require.Eventually(t, func() bool {
		job := manager.GetCurrentJob()
		return job != nil && job.ProposalID == "new-job"
	}, time.Second, 10*time.Millisecond)

	// Shutdown
	cancel()
	err := <-errCh
	assert.NoError(t, err)
}

func TestHandleProposal_StartFails_TransitionsToWaiting(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	manager := ts.newManager()

	// Setup expectations
	ts.jobStore.EXPECT().LoadJob(mock.Anything).Return(nil, jobstore.ErrNoJob).Once()
	ts.jdClient.EXPECT().Connect(mock.Anything).Return(nil).Once()
	ts.setupChannelMocks()
	ts.runner.EXPECT().StartJob(mock.Anything, "bad-spec").Return(errors.New("invalid spec")).Once()
	ts.jdClient.EXPECT().Close().Return(nil).Once()

	// Run manager in goroutine
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- manager.Run(ctx)
	}()

	// Wait for manager to be ready
	time.Sleep(50 * time.Millisecond)

	// Send proposal that will fail
	ts.proposalCh <- &pb.ProposeJobRequest{
		Id:      "bad-proposal",
		Version: 1,
		Spec:    "bad-spec",
	}

	// Wait a bit for processing
	time.Sleep(100 * time.Millisecond)

	// Should still be waiting (failure should not crash manager)
	assert.Equal(t, StateWaitingForJob, manager.GetState())
	assert.Nil(t, manager.GetCurrentJob())

	// Shutdown
	cancel()
	err := <-errCh
	assert.NoError(t, err)
}

func TestHandleProposal_PersistFails_ContinuesAnyway(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	manager := ts.newManager()

	// Setup expectations
	ts.jobStore.EXPECT().LoadJob(mock.Anything).Return(nil, jobstore.ErrNoJob).Once()
	ts.jdClient.EXPECT().Connect(mock.Anything).Return(nil).Once()
	ts.setupChannelMocks()
	ts.runner.EXPECT().StartJob(mock.Anything, "new-spec").Return(nil).Once()
	ts.jobStore.EXPECT().SaveJob(mock.Anything, "proposal-1", int64(1), "new-spec").Return(errors.New("db error")).Once()
	ts.jdClient.EXPECT().ApproveJob(mock.Anything, "proposal-1", int64(1)).Return(nil).Once()
	ts.jdClient.EXPECT().Close().Return(nil).Once()
	ts.runner.EXPECT().StopJob(mock.Anything).Return(nil).Once()

	// Run manager in goroutine
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- manager.Run(ctx)
	}()

	// Wait for manager to be ready
	time.Sleep(50 * time.Millisecond)

	// Send proposal
	ts.proposalCh <- &pb.ProposeJobRequest{
		Id:      "proposal-1",
		Version: 1,
		Spec:    "new-spec",
	}

	// Wait for state to become Running (should succeed despite DB failure)
	require.Eventually(t, func() bool {
		return manager.GetState() == StateRunning
	}, time.Second, 10*time.Millisecond)

	// Shutdown
	cancel()
	err := <-errCh
	assert.NoError(t, err)
}

// =============================================================================
// Job Deletion Tests
// =============================================================================

func TestHandleDelete_CurrentJob_StopsAndClears(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	manager := ts.newManager()

	cachedJob := &jobstore.Job{
		ProposalID: "job-to-delete",
		Version:    1,
		Spec:       "spec",
	}

	// Setup expectations
	ts.jobStore.EXPECT().LoadJob(mock.Anything).Return(cachedJob, nil).Once()
	ts.runner.EXPECT().StartJob(mock.Anything, "spec").Return(nil).Once()
	ts.jdClient.EXPECT().Connect(mock.Anything).Return(nil).Once()
	ts.setupChannelMocks()

	// Expectations for delete
	ts.runner.EXPECT().StopJob(mock.Anything).Return(nil).Once()
	ts.jobStore.EXPECT().DeleteJob(mock.Anything).Return(nil).Once()

	// Shutdown expectations
	ts.jdClient.EXPECT().Close().Return(nil).Once()

	// Run manager in goroutine
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- manager.Run(ctx)
	}()

	// Wait for state to become Running
	require.Eventually(t, func() bool {
		return manager.GetState() == StateRunning
	}, time.Second, 10*time.Millisecond)

	// Send delete request
	ts.deleteCh <- &pb.DeleteJobRequest{
		Id: "job-to-delete",
	}

	// Wait for state to become WaitingForJob
	require.Eventually(t, func() bool {
		return manager.GetState() == StateWaitingForJob
	}, time.Second, 10*time.Millisecond)

	// Verify job is cleared
	assert.Nil(t, manager.GetCurrentJob())

	// Shutdown
	cancel()
	err := <-errCh
	assert.NoError(t, err)
}

func TestHandleDelete_NoJobRunning_Ignores(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	manager := ts.newManager()

	// Setup expectations - no cached job
	ts.jobStore.EXPECT().LoadJob(mock.Anything).Return(nil, jobstore.ErrNoJob).Once()
	ts.jdClient.EXPECT().Connect(mock.Anything).Return(nil).Once()
	ts.setupChannelMocks()
	ts.jdClient.EXPECT().Close().Return(nil).Once()

	// Run manager in goroutine
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- manager.Run(ctx)
	}()

	// Wait for manager to be ready
	time.Sleep(50 * time.Millisecond)

	// Send delete request (should be ignored)
	ts.deleteCh <- &pb.DeleteJobRequest{
		Id: "some-job",
	}

	// Wait a bit
	time.Sleep(100 * time.Millisecond)

	// Should still be waiting
	assert.Equal(t, StateWaitingForJob, manager.GetState())

	// Shutdown
	cancel()
	err := <-errCh
	assert.NoError(t, err)
}

func TestHandleDelete_DifferentJob_Ignores(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	manager := ts.newManager()

	cachedJob := &jobstore.Job{
		ProposalID: "current-job",
		Version:    1,
		Spec:       "spec",
	}

	// Setup expectations
	ts.jobStore.EXPECT().LoadJob(mock.Anything).Return(cachedJob, nil).Once()
	ts.runner.EXPECT().StartJob(mock.Anything, "spec").Return(nil).Once()
	ts.jdClient.EXPECT().Connect(mock.Anything).Return(nil).Once()
	ts.setupChannelMocks()
	ts.jdClient.EXPECT().Close().Return(nil).Once()
	ts.runner.EXPECT().StopJob(mock.Anything).Return(nil).Once()

	// Run manager in goroutine
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- manager.Run(ctx)
	}()

	// Wait for state to become Running
	require.Eventually(t, func() bool {
		return manager.GetState() == StateRunning
	}, time.Second, 10*time.Millisecond)

	// Send delete request for different job
	ts.deleteCh <- &pb.DeleteJobRequest{
		Id: "different-job",
	}

	// Wait a bit
	time.Sleep(100 * time.Millisecond)

	// Should still be running with original job
	assert.Equal(t, StateRunning, manager.GetState())
	assert.Equal(t, "current-job", manager.GetCurrentJob().ProposalID)

	// Shutdown
	cancel()
	err := <-errCh
	assert.NoError(t, err)
}

// =============================================================================
// Revoke Tests
// =============================================================================

func TestHandleRevoke_IsIgnored(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	manager := ts.newManager()

	// Setup expectations
	ts.jobStore.EXPECT().LoadJob(mock.Anything).Return(nil, jobstore.ErrNoJob).Once()
	ts.jdClient.EXPECT().Connect(mock.Anything).Return(nil).Once()
	ts.setupChannelMocks()
	ts.jdClient.EXPECT().Close().Return(nil).Once()

	// Run manager in goroutine
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- manager.Run(ctx)
	}()

	// Wait for manager to be ready
	time.Sleep(50 * time.Millisecond)

	// Send revoke request (should be logged and ignored)
	ts.revokeCh <- &pb.RevokeJobRequest{
		Id: "some-proposal",
	}

	// Wait a bit
	time.Sleep(100 * time.Millisecond)

	// Should still be waiting (revoke is a no-op)
	assert.Equal(t, StateWaitingForJob, manager.GetState())

	// Shutdown
	cancel()
	err := <-errCh
	assert.NoError(t, err)
}

// =============================================================================
// Shutdown Tests
// =============================================================================

func TestShutdown_WithRunningJob_StopsJob(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	manager := ts.newManager()

	cachedJob := &jobstore.Job{
		ProposalID: "job-1",
		Version:    1,
		Spec:       "spec",
	}

	// Setup expectations
	ts.jobStore.EXPECT().LoadJob(mock.Anything).Return(cachedJob, nil).Once()
	ts.runner.EXPECT().StartJob(mock.Anything, "spec").Return(nil).Once()
	ts.jdClient.EXPECT().Connect(mock.Anything).Return(nil).Once()
	ts.setupChannelMocks()
	ts.runner.EXPECT().StopJob(mock.Anything).Return(nil).Once()
	ts.jdClient.EXPECT().Close().Return(nil).Once()

	// Run manager in goroutine
	ctx := context.Background()
	errCh := make(chan error, 1)
	go func() {
		errCh <- manager.Run(ctx)
	}()

	// Wait for state to become Running
	require.Eventually(t, func() bool {
		return manager.GetState() == StateRunning
	}, time.Second, 10*time.Millisecond)

	// Trigger shutdown via Shutdown() method
	manager.Shutdown()

	err := <-errCh
	assert.NoError(t, err)
}

func TestShutdown_NoRunningJob_JustClosesJD(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	manager := ts.newManager()

	// Setup expectations
	ts.jobStore.EXPECT().LoadJob(mock.Anything).Return(nil, jobstore.ErrNoJob).Once()
	ts.jdClient.EXPECT().Connect(mock.Anything).Return(nil).Once()
	ts.setupChannelMocks()
	ts.jdClient.EXPECT().Close().Return(nil).Once()

	// Run manager in goroutine
	ctx := context.Background()
	errCh := make(chan error, 1)
	go func() {
		errCh <- manager.Run(ctx)
	}()

	// Wait for manager to be ready
	time.Sleep(50 * time.Millisecond)

	// Trigger shutdown
	manager.Shutdown()

	err := <-errCh
	assert.NoError(t, err)
}

func TestShutdown_Idempotent(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	manager := ts.newManager()

	// Setup expectations
	ts.jobStore.EXPECT().LoadJob(mock.Anything).Return(nil, jobstore.ErrNoJob).Once()
	ts.jdClient.EXPECT().Connect(mock.Anything).Return(nil).Once()
	ts.setupChannelMocks()
	ts.jdClient.EXPECT().Close().Return(nil).Once()

	// Run manager in goroutine
	ctx := context.Background()
	errCh := make(chan error, 1)
	go func() {
		errCh <- manager.Run(ctx)
	}()

	// Wait for manager to be ready
	time.Sleep(50 * time.Millisecond)

	// Call Shutdown multiple times
	manager.Shutdown()
	manager.Shutdown()
	manager.Shutdown()

	err := <-errCh
	assert.NoError(t, err)
}

func TestShutdown_ViaContextCancellation(t *testing.T) {
	t.Parallel()
	ts := newTestSetup(t)
	manager := ts.newManager()

	cachedJob := &jobstore.Job{
		ProposalID: "job-1",
		Version:    1,
		Spec:       "spec",
	}

	// Setup expectations
	ts.jobStore.EXPECT().LoadJob(mock.Anything).Return(cachedJob, nil).Once()
	ts.runner.EXPECT().StartJob(mock.Anything, "spec").Return(nil).Once()
	ts.jdClient.EXPECT().Connect(mock.Anything).Return(nil).Once()
	ts.setupChannelMocks()
	ts.runner.EXPECT().StopJob(mock.Anything).Return(nil).Once()
	ts.jdClient.EXPECT().Close().Return(nil).Once()

	// Run manager in goroutine
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- manager.Run(ctx)
	}()

	// Wait for state to become Running
	require.Eventually(t, func() bool {
		return manager.GetState() == StateRunning
	}, time.Second, 10*time.Millisecond)

	// Trigger shutdown via context cancellation
	cancel()

	err := <-errCh
	assert.NoError(t, err)
}
