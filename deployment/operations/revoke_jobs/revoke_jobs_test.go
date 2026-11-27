package revoke_jobs

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	jobv1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/job"

	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

type retryJDClient struct {
	shared.JDClient
	err   error
	calls int
}

func (c *retryJDClient) RevokeJob(_ context.Context, _ *jobv1.RevokeJobRequest, _ ...grpc.CallOption) (*jobv1.RevokeJobResponse, error) {
	c.calls++
	if c.err != nil {
		return nil, c.err
	}
	return &jobv1.RevokeJobResponse{}, nil
}

func TestRevokeJobsRetriesAfterTransientFailure(t *testing.T) {
	client := &retryJDClient{err: errors.New("temporary JD failure")}
	lggr := logger.Test(t)
	bundle := operations.NewBundle(t.Context, lggr, operations.NewMemoryReporter())
	deps := RevokeJobsDeps{JDClient: client, Logger: lggr, NodeIDs: []string{"node-1"}}
	input := RevokeJobsInput{Jobs: []shared.JobInfo{{
		JobID: "job-1", JDJobID: "jd-job-1", NodeID: "node-1", NOPAlias: "nop-1",
	}}}

	_, err := operations.ExecuteOperation(bundle, RevokeJobs, deps, input)
	require.ErrorContains(t, err, "temporary JD failure")
	require.Equal(t, 1, client.calls)

	client.err = nil
	report, err := operations.ExecuteOperation(bundle, RevokeJobs, deps, input)
	require.NoError(t, err)
	require.Equal(t, 2, client.calls, "a failed operation must not be reused as a successful report")
	require.Len(t, report.Output.RevokedJobs, 1)
	require.Empty(t, report.Output.Errors)
}
