package shared

import (
	"context"

	"google.golang.org/grpc"

	jobv1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/job"
	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"
)

// JDClient defines the Job Distributor client methods used by CCV deployment operations.
// This interface is a subset of offchain.Client, containing only the methods required for CCV.
// Method signatures mirror offchain.Client from chainlink-deployments-framework.
type JDClient interface {
	// ListNodes returns nodes matching the filter criteria.
	ListNodes(ctx context.Context, in *nodev1.ListNodesRequest, opts ...grpc.CallOption) (*nodev1.ListNodesResponse, error)
	// ListNodeChainConfigs returns chain configurations for nodes.
	ListNodeChainConfigs(ctx context.Context, in *nodev1.ListNodeChainConfigsRequest, opts ...grpc.CallOption) (*nodev1.ListNodeChainConfigsResponse, error)
	// ProposeJob submits a job proposal to a node.
	ProposeJob(ctx context.Context, in *jobv1.ProposeJobRequest, opts ...grpc.CallOption) (*jobv1.ProposeJobResponse, error)
	// RevokeJob revokes an existing job proposal.
	RevokeJob(ctx context.Context, in *jobv1.RevokeJobRequest, opts ...grpc.CallOption) (*jobv1.RevokeJobResponse, error)
	// ListProposals returns proposals matching the filter criteria.
	ListProposals(ctx context.Context, in *jobv1.ListProposalsRequest, opts ...grpc.CallOption) (*jobv1.ListProposalsResponse, error)
}
