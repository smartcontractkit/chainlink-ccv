package shared

import (
	"context"

	"google.golang.org/grpc"

	jobv1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/job"
	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"
)

// JDClient defines the Job Distributor client methods used by CCV deployment operations.
// This interface is a subset of offchain.Client, containing only the methods required for CCV.
// The framework's offchain.Client satisfies this interface automatically.
type JDClient interface {
	// ListNodes returns the nodes registered with the Job Distributor matching the request filter.
	ListNodes(ctx context.Context, in *nodev1.ListNodesRequest, opts ...grpc.CallOption) (*nodev1.ListNodesResponse, error)
	// ListNodeChainConfigs returns the per-chain configurations registered for nodes in the Job Distributor.
	ListNodeChainConfigs(ctx context.Context, in *nodev1.ListNodeChainConfigsRequest, opts ...grpc.CallOption) (*nodev1.ListNodeChainConfigsResponse, error)
	// ProposeJob submits a job proposal to the Job Distributor.
	ProposeJob(ctx context.Context, in *jobv1.ProposeJobRequest, opts ...grpc.CallOption) (*jobv1.ProposeJobResponse, error)
	// RevokeJob revokes a previously submitted job proposal.
	RevokeJob(ctx context.Context, in *jobv1.RevokeJobRequest, opts ...grpc.CallOption) (*jobv1.RevokeJobResponse, error)
	// ListProposals returns job proposals registered with the Job Distributor matching the request filter.
	ListProposals(ctx context.Context, in *jobv1.ListProposalsRequest, opts ...grpc.CallOption) (*jobv1.ListProposalsResponse, error)
}
