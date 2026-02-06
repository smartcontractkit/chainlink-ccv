package jdclient

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/smartcontractkit/chainlink-protos/orchestrator/feedsmanager"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestHandlers_ProposeJob(t *testing.T) {
	t.Parallel()

	lggr, err := logger.New()
	require.NoError(t, err)

	proposalCh := make(chan *JobProposal, 10)
	handlers := NewHandlers(proposalCh, lggr)

	ctx := context.Background()
	req := &pb.ProposeJobRequest{
		Id:      "test-job-id",
		Version: 1,
		Spec:    "verifier_id = \"test-verifier\"",
	}

	resp, err := handlers.ProposeJob(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Verify the proposal was sent to the channel
	select {
	case proposal := <-proposalCh:
		assert.Equal(t, "test-job-id", proposal.ID)
		assert.Equal(t, int64(1), proposal.Version)
		assert.Equal(t, "verifier_id = \"test-verifier\"", proposal.Spec)
	case <-time.After(time.Second):
		t.Fatal("No proposal received")
	}
}

func TestHandlers_ProposeJob_ContextCancelled(t *testing.T) {
	t.Parallel()

	lggr, err := logger.New()
	require.NoError(t, err)

	// Use unbuffered channel that will block
	proposalCh := make(chan *JobProposal)
	handlers := NewHandlers(proposalCh, lggr)

	// Create a canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	req := &pb.ProposeJobRequest{
		Id:      "test-job-id",
		Version: 1,
		Spec:    "test spec",
	}

	_, err = handlers.ProposeJob(ctx, req)
	require.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

func TestHandlers_DeleteJob(t *testing.T) {
	t.Parallel()

	lggr, err := logger.New()
	require.NoError(t, err)

	proposalCh := make(chan *JobProposal, 10)
	handlers := NewHandlers(proposalCh, lggr)

	ctx := context.Background()
	req := &pb.DeleteJobRequest{
		Id: "test-job-id",
	}

	resp, err := handlers.DeleteJob(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	// Delete is a no-op for standalone verifiers
}

func TestHandlers_RevokeJob(t *testing.T) {
	t.Parallel()

	lggr, err := logger.New()
	require.NoError(t, err)

	proposalCh := make(chan *JobProposal, 10)
	handlers := NewHandlers(proposalCh, lggr)

	ctx := context.Background()
	req := &pb.RevokeJobRequest{
		Id: "test-job-id",
	}

	resp, err := handlers.RevokeJob(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	// Revoke is a no-op for standalone verifiers
}

func TestHandlers_GetJobRuns(t *testing.T) {
	t.Parallel()

	lggr, err := logger.New()
	require.NoError(t, err)

	proposalCh := make(chan *JobProposal, 10)
	handlers := NewHandlers(proposalCh, lggr)

	ctx := context.Background()
	req := &pb.GetJobRunsRequest{
		Id: "test-job-id",
	}

	resp, err := handlers.GetJobRuns(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	// Returns empty list for standalone verifiers
	assert.Empty(t, resp.Runs)
}

func TestHandlers_ImplementsInterface(t *testing.T) {
	t.Parallel()

	lggr, err := logger.New()
	require.NoError(t, err)

	proposalCh := make(chan *JobProposal, 10)
	handlers := NewHandlers(proposalCh, lggr)

	// Verify it implements the interface
	var _ pb.NodeServiceServer = handlers
}
