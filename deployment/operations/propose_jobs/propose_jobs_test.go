package propose_jobs

import (
	"context"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	jobv1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/job"
	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"

	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

type recordingJDClient struct {
	shared.JDClient
	nodes     []*nodev1.Node
	proposals []*jobv1.ProposeJobRequest
}

func (c *recordingJDClient) ListNodes(_ context.Context, req *nodev1.ListNodesRequest, _ ...grpc.CallOption) (*nodev1.ListNodesResponse, error) {
	var nodes []*nodev1.Node
	for _, node := range c.nodes {
		if len(req.GetFilter().GetIds()) == 0 || slices.Contains(req.GetFilter().GetIds(), node.GetId()) {
			nodes = append(nodes, node)
		}
	}
	return &nodev1.ListNodesResponse{Nodes: nodes}, nil
}

func (c *recordingJDClient) ProposeJob(_ context.Context, req *jobv1.ProposeJobRequest, _ ...grpc.CallOption) (*jobv1.ProposeJobResponse, error) {
	c.proposals = append(c.proposals, req)
	return &jobv1.ProposeJobResponse{Proposal: &jobv1.Proposal{
		Id:       "proposal-1",
		JobId:    "jd-job-1",
		Revision: 1,
		Spec:     req.GetSpec(),
	}}, nil
}

func TestProposeJobsNodeTargeting(t *testing.T) {
	const (
		alias          = shared.NOPAlias("chainlink-ccv-staging-0")
		verifierNodeID = "node_verifier"
		executorNodeID = "node_executor"
	)
	jobID := shared.NewExecutorJobID(alias, shared.ExecutorJobScope{ExecutorQualifier: "default"}).ToJobID()

	tests := []struct {
		name       string
		nodeID     string
		wantNodeID string
		wantError  string
	}{
		{name: "explicit standalone node", nodeID: executorNodeID, wantNodeID: executorNodeID},
		{name: "CL node from NOP alias", wantNodeID: verifierNodeID},
		{name: "unknown explicit node fails without fallback", nodeID: "node_missing", wantError: `node ID "node_missing" not found`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &recordingJDClient{nodes: []*nodev1.Node{
				{Id: verifierNodeID, Name: string(alias)},
				{Id: executorNodeID, Name: "executor-evm-0"},
			}}
			lggr := logger.Test(t)
			bundle := operations.NewBundle(
				func() context.Context { return t.Context() },
				lggr,
				operations.NewMemoryReporter(),
			)

			report, err := operations.ExecuteOperation(
				bundle,
				ProposeJobs,
				ProposeJobsDeps{
					JDClient: client,
					Logger:   lggr,
					NodeIDs:  []string{verifierNodeID, executorNodeID},
				},
				ProposeJobsInput{JobSpecs: []JobSpecInput{{
					NOPAlias:      alias,
					InternalJobID: jobID,
					Spec:          "job-spec",
					NodeID:        tt.nodeID,
				}}},
			)
			if tt.wantError != "" {
				require.ErrorContains(t, err, tt.wantError)
				require.Empty(t, client.proposals)
				return
			}
			require.NoError(t, err)
			require.Len(t, client.proposals, 1)
			require.Equal(t, tt.wantNodeID, client.proposals[0].GetNodeId())
			require.Equal(t, "job-spec", client.proposals[0].GetSpec())
			require.Len(t, report.Output.ProposedJobs, 1)
			require.Equal(t, tt.wantNodeID, report.Output.ProposedJobs[0].NodeID)
		})
	}
}
