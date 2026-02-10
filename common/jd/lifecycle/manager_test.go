package lifecycle

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	pb "github.com/smartcontractkit/chainlink-protos/orchestrator/feedsmanager"

	"github.com/smartcontractkit/chainlink-ccv/common/jd/client"
	"github.com/smartcontractkit/chainlink-ccv/common/jd/store"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"
)

func TestState_String(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "WaitingForJob", StateWaitingForJob.String())
	assert.Equal(t, "Running", StateRunning.String())
	assert.Equal(t, "Unknown", State(99).String())
}

func TestNewManager(t *testing.T) {
	t.Parallel()

	jdClient := mocks.NewMockClientInterface(t)
	jobStore := mocks.NewMockStoreInterface(t)
	runner := mocks.NewMockJobRunner(t)
	lggr := logger.Test(t)

	cfg := Config{
		JDClient: jdClient,
		JobStore: jobStore,
		Runner:   runner,
		Logger:   lggr,
	}

	m, err := NewManager(cfg)
	require.NoError(t, err)
	require.NotNil(t, m)
	assert.Equal(t, StateWaitingForJob, m.GetState())
}

func TestNewManager_ReturnsError_WhenRequiredFieldIsNil(t *testing.T) {
	t.Parallel()

	jdClient := mocks.NewMockClientInterface(t)
	jobStore := mocks.NewMockStoreInterface(t)
	runner := mocks.NewMockJobRunner(t)
	lggr := logger.Test(t)

	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{"nil JDClient", Config{JDClient: nil, JobStore: jobStore, Runner: runner, Logger: lggr}, "JD client is required"},
		{"nil JobStore", Config{JDClient: jdClient, JobStore: nil, Runner: runner, Logger: lggr}, "job store is required"},
		{"nil Runner", Config{JDClient: jdClient, JobStore: jobStore, Runner: nil, Logger: lggr}, "runner is required"},
		{"nil Logger", Config{JDClient: jdClient, JobStore: jobStore, Runner: runner, Logger: nil}, "logger is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewManager(tt.cfg)
			require.Error(t, err)
			require.Nil(t, m)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestManager_GetState(t *testing.T) {
	t.Parallel()

	m, err := NewManager(Config{
		JDClient: mocks.NewMockClientInterface(t),
		JobStore: mocks.NewMockStoreInterface(t),
		Runner:   mocks.NewMockJobRunner(t),
		Logger:   logger.Test(t),
	})
	require.NoError(t, err)
	assert.Equal(t, StateWaitingForJob, m.GetState())
}

// chanClient wraps a ClientInterface mock and exposes the same channels for every Ch() call
// so the event loop can receive from them.
type chanClient struct {
	*mocks.MockClientInterface
	proposalCh chan *pb.ProposeJobRequest
	deleteCh   chan *pb.DeleteJobRequest
	revokeCh   chan *pb.RevokeJobRequest
}

func newChanClient(t *testing.T) *chanClient {
	t.Helper()
	m := mocks.NewMockClientInterface(t)
	proposalCh := make(chan *pb.ProposeJobRequest, 10)
	deleteCh := make(chan *pb.DeleteJobRequest, 10)
	revokeCh := make(chan *pb.RevokeJobRequest, 10)
	m.EXPECT().JobProposalCh().Return(proposalCh).Maybe()
	m.EXPECT().DeleteJobCh().Return(deleteCh).Maybe()
	m.EXPECT().RevokeJobCh().Return(revokeCh).Maybe()
	return &chanClient{
		MockClientInterface: m,
		proposalCh:          proposalCh,
		deleteCh:            deleteCh,
		revokeCh:            revokeCh,
	}
}

func (c *chanClient) JobProposalCh() <-chan *pb.ProposeJobRequest { return c.proposalCh }
func (c *chanClient) DeleteJobCh() <-chan *pb.DeleteJobRequest    { return c.deleteCh }
func (c *chanClient) RevokeJobCh() <-chan *pb.RevokeJobRequest    { return c.revokeCh }

// Ensure chanClient implements client.ClientInterface (channels are read-only when returned).
var _ client.ClientInterface = (*chanClient)(nil)

func TestManager_Start_NoCachedJob_ConnectFails(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	jdClient := newChanClient(t)
	jdClient.EXPECT().Connect(mock.Anything).Return(errors.New("connect failed"))

	jobStore := mocks.NewMockStoreInterface(t)
	jobStore.EXPECT().LoadJob(mock.Anything).Return(nil, store.ErrNoJob)

	runner := mocks.NewMockJobRunner(t)

	m, err := NewManager(Config{
		JDClient: jdClient,
		JobStore: jobStore,
		Runner:   runner,
		Logger:   logger.Test(t),
	})
	require.NoError(t, err)
	err = m.Start(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to connect to JD")
	assert.Equal(t, StateWaitingForJob, m.GetState())
}

func TestManager_Start_LoadJobError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	jdClient := newChanClient(t)

	jobStore := mocks.NewMockStoreInterface(t)
	jobStore.EXPECT().LoadJob(mock.Anything).Return(nil, errors.New("db error"))

	runner := mocks.NewMockJobRunner(t)

	m, err := NewManager(Config{
		JDClient: jdClient,
		JobStore: jobStore,
		Runner:   runner,
		Logger:   logger.Test(t),
	})
	require.NoError(t, err)
	err = m.Start(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load cached job")
}

func TestManager_Start_CachedJob_StartJobFails(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	jdClient := newChanClient(t)

	cachedJob := &store.Job{
		ProposalID: "cached-id",
		Version:    1,
		Spec:       `{"job":"cached"}`,
	}
	jobStore := mocks.NewMockStoreInterface(t)
	jobStore.EXPECT().LoadJob(mock.Anything).Return(cachedJob, nil)

	runner := mocks.NewMockJobRunner(t)
	runner.EXPECT().StartJob(mock.Anything, cachedJob.Spec).Return(errors.New("start failed"))

	m, err := NewManager(Config{
		JDClient: jdClient,
		JobStore: jobStore,
		Runner:   runner,
		Logger:   logger.Test(t),
	})
	require.NoError(t, err)
	err = m.Start(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to start cached job")
}

func TestManager_Start_NoCachedJob_ConnectSuccess(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	jdClient := newChanClient(t)
	jdClient.EXPECT().Connect(mock.Anything).Return(nil)
	jdClient.EXPECT().Close().Return(nil).Maybe()

	jobStore := mocks.NewMockStoreInterface(t)
	jobStore.EXPECT().LoadJob(mock.Anything).Return(nil, store.ErrNoJob)

	runner := mocks.NewMockJobRunner(t)

	m, err := NewManager(Config{
		JDClient: jdClient,
		JobStore: jobStore,
		Runner:   runner,
		Logger:   logger.Test(t),
	})
	require.NoError(t, err)
	err = m.Start(ctx)
	require.NoError(t, err)
	assert.Equal(t, StateWaitingForJob, m.GetState())

	// Stop to clean up event loop
	err = m.Stop()
	require.NoError(t, err)
}

func TestManager_Start_CachedJob_ConnectFails_Continues(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	jdClient := newChanClient(t)
	jdClient.EXPECT().Connect(mock.Anything).Return(errors.New("network error"))
	jdClient.EXPECT().Close().Return(nil).Maybe()

	cachedJob := &store.Job{
		ProposalID: "cached-id",
		Version:    1,
		Spec:       `{"job":"cached"}`,
	}
	jobStore := mocks.NewMockStoreInterface(t)
	jobStore.EXPECT().LoadJob(mock.Anything).Return(cachedJob, nil)

	runner := mocks.NewMockJobRunner(t)
	runner.EXPECT().StartJob(mock.Anything, cachedJob.Spec).Return(nil)
	runner.EXPECT().StopJob(mock.Anything).Return(nil).Maybe()

	m, err := NewManager(Config{
		JDClient: jdClient,
		JobStore: jobStore,
		Runner:   runner,
		Logger:   logger.Test(t),
	})
	require.NoError(t, err)
	err = m.Start(ctx)
	require.NoError(t, err)
	assert.Equal(t, StateRunning, m.GetState())

	err = m.Stop()
	require.NoError(t, err)
}

func TestManager_Start_CachedJob_ConnectSuccess(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	jdClient := newChanClient(t)
	jdClient.EXPECT().Connect(mock.Anything).Return(nil)
	jdClient.EXPECT().Close().Return(nil).Maybe()

	cachedJob := &store.Job{
		ProposalID: "cached-id",
		Version:    1,
		Spec:       `{"job":"cached"}`,
	}
	jobStore := mocks.NewMockStoreInterface(t)
	jobStore.EXPECT().LoadJob(mock.Anything).Return(cachedJob, nil)

	runner := mocks.NewMockJobRunner(t)
	runner.EXPECT().StartJob(mock.Anything, cachedJob.Spec).Return(nil)
	runner.EXPECT().StopJob(mock.Anything).Return(nil).Maybe()

	m, err := NewManager(Config{
		JDClient: jdClient,
		JobStore: jobStore,
		Runner:   runner,
		Logger:   logger.Test(t),
	})
	require.NoError(t, err)
	err = m.Start(ctx)
	require.NoError(t, err)
	assert.Equal(t, StateRunning, m.GetState())

	err = m.Stop()
	require.NoError(t, err)
}

func TestManager_EventLoop_Proposal_StartsJobAndApproves(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	jdClient := newChanClient(t)
	jdClient.EXPECT().Connect(mock.Anything).Return(nil)
	jdClient.EXPECT().Close().Return(nil).Maybe()
	jdClient.EXPECT().ApproveJob(mock.Anything, "proposal-1", int64(2)).Return(nil).Maybe()

	jobStore := mocks.NewMockStoreInterface(t)
	jobStore.EXPECT().LoadJob(mock.Anything).Return(nil, store.ErrNoJob)
	jobStore.EXPECT().SaveJob(mock.Anything, "proposal-1", int64(2), `{"spec":"new"}`).Return(nil).Maybe()

	runner := mocks.NewMockJobRunner(t)
	runner.EXPECT().StartJob(mock.Anything, `{"spec":"new"}`).Return(nil).Maybe()
	runner.EXPECT().StopJob(mock.Anything).Return(nil).Maybe()

	m, err := NewManager(Config{
		JDClient: jdClient,
		JobStore: jobStore,
		Runner:   runner,
		Logger:   logger.Test(t),
	})
	require.NoError(t, err)
	err = m.Start(ctx)
	require.NoError(t, err)

	// Send a proposal
	jdClient.proposalCh <- &pb.ProposeJobRequest{
		Id:      "proposal-1",
		Version: 2,
		Spec:    `{"spec":"new"}`,
	}

	// Give event loop time to process
	require.Eventually(t, func() bool { return m.GetState() == StateRunning }, tests.WaitTimeout(t), 50*time.Millisecond)

	err = m.Stop()
	require.NoError(t, err)
}

func TestManager_EventLoop_Delete_StopsJobAndClearsState(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	jdClient := newChanClient(t)
	jdClient.EXPECT().Connect(mock.Anything).Return(nil)
	jdClient.EXPECT().Close().Return(nil).Maybe()
	jdClient.EXPECT().ApproveJob(mock.Anything, "proposal-1", int64(1)).Return(nil).Maybe()

	jobStore := mocks.NewMockStoreInterface(t)
	jobStore.EXPECT().LoadJob(mock.Anything).Return(nil, store.ErrNoJob)
	jobStore.EXPECT().SaveJob(mock.Anything, "proposal-1", int64(1), `{"spec":"job1"}`).Return(nil).Maybe()
	jobStore.EXPECT().DeleteJob(mock.Anything).Return(nil).Maybe()

	runner := mocks.NewMockJobRunner(t)
	runner.EXPECT().StartJob(mock.Anything, `{"spec":"job1"}`).Return(nil).Maybe()
	runner.EXPECT().StopJob(mock.Anything).Return(nil).Maybe()

	m, err := NewManager(Config{
		JDClient: jdClient,
		JobStore: jobStore,
		Runner:   runner,
		Logger:   logger.Test(t),
	})
	require.NoError(t, err)
	err = m.Start(ctx)
	require.NoError(t, err)

	jdClient.proposalCh <- &pb.ProposeJobRequest{
		Id:      "proposal-1",
		Version: 1,
		Spec:    `{"spec":"job1"}`,
	}
	require.Eventually(t, func() bool { return m.GetState() == StateRunning }, tests.WaitTimeout(t), 50*time.Millisecond)

	// Send delete for current job
	jdClient.deleteCh <- &pb.DeleteJobRequest{Id: "proposal-1"}

	require.Eventually(t, func() bool { return m.GetState() == StateWaitingForJob }, tests.WaitTimeout(t), 50*time.Millisecond)

	err = m.Stop()
	require.NoError(t, err)
}

func TestManager_EventLoop_Delete_DifferentJob_Ignored(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	jdClient := newChanClient(t)
	jdClient.EXPECT().Connect(mock.Anything).Return(nil)
	jdClient.EXPECT().Close().Return(nil).Maybe()
	jdClient.EXPECT().ApproveJob(mock.Anything, "proposal-1", int64(1)).Return(nil).Maybe()

	jobStore := mocks.NewMockStoreInterface(t)
	jobStore.EXPECT().LoadJob(mock.Anything).Return(nil, store.ErrNoJob)
	jobStore.EXPECT().SaveJob(mock.Anything, "proposal-1", int64(1), `{"spec":"job1"}`).Return(nil).Maybe()
	// DeleteJob should not be called (delete was for different id)

	runner := mocks.NewMockJobRunner(t)
	runner.EXPECT().StartJob(mock.Anything, `{"spec":"job1"}`).Return(nil).Maybe()
	runner.EXPECT().StopJob(mock.Anything).Return(nil).Maybe() // called on Stop() during shutdown

	m, err := NewManager(Config{
		JDClient: jdClient,
		JobStore: jobStore,
		Runner:   runner,
		Logger:   logger.Test(t),
	})
	require.NoError(t, err)
	err = m.Start(ctx)
	require.NoError(t, err)

	jdClient.proposalCh <- &pb.ProposeJobRequest{
		Id:      "proposal-1",
		Version: 1,
		Spec:    `{"spec":"job1"}`,
	}
	require.Eventually(t, func() bool { return m.GetState() == StateRunning }, tests.WaitTimeout(t), 50*time.Millisecond)

	// Delete for different job - should be ignored, state stays Running
	jdClient.deleteCh <- &pb.DeleteJobRequest{Id: "other-id"}

	require.Eventually(t, func() bool { return m.GetState() == StateRunning }, tests.WaitTimeout(t), 50*time.Millisecond)

	err = m.Stop()
	require.NoError(t, err)
}

func TestManager_Stop_WithoutStart_ReturnsError(t *testing.T) {
	t.Parallel()

	m, err := NewManager(Config{
		JDClient: mocks.NewMockClientInterface(t),
		JobStore: mocks.NewMockStoreInterface(t),
		Runner:   mocks.NewMockJobRunner(t),
		Logger:   logger.Test(t),
	})
	require.NoError(t, err)
	err = m.Stop()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot stop unstarted service")
}

func TestManager_Stop_AfterStart_Succeeds(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	jdClient := newChanClient(t)
	jdClient.EXPECT().Connect(mock.Anything).Return(nil)
	jdClient.EXPECT().Close().Return(nil).Maybe()

	jobStore := mocks.NewMockStoreInterface(t)
	jobStore.EXPECT().LoadJob(mock.Anything).Return(nil, store.ErrNoJob)

	runner := mocks.NewMockJobRunner(t)

	m, err := NewManager(Config{
		JDClient: jdClient,
		JobStore: jobStore,
		Runner:   runner,
		Logger:   logger.Test(t),
	})
	require.NoError(t, err)
	require.NoError(t, m.Start(ctx))
	err = m.Stop()
	require.NoError(t, err)
	// Second Stop returns error (StopOnce contract)
	err = m.Stop()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already stopped")
}

func TestManager_Start_StartOncePreventsSecondStart(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	jdClient := newChanClient(t)
	jdClient.EXPECT().Connect(mock.Anything).Return(nil).Times(1)
	jdClient.EXPECT().Close().Return(nil).Maybe()

	jobStore := mocks.NewMockStoreInterface(t)
	jobStore.EXPECT().LoadJob(mock.Anything).Return(nil, store.ErrNoJob).Times(1)

	runner := mocks.NewMockJobRunner(t)

	m, err := NewManager(Config{
		JDClient: jdClient,
		JobStore: jobStore,
		Runner:   runner,
		Logger:   logger.Test(t),
	})
	require.NoError(t, err)
	err = m.Start(ctx)
	require.NoError(t, err)
	err = m.Start(ctx)
	require.Error(t, err) // second Start returns error (StartOnce contract)
	assert.Contains(t, err.Error(), "already been started")

	require.NoError(t, m.Stop())
}
