package changesets

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	foffchain "github.com/smartcontractkit/chainlink-deployments-framework/offchain"
	jobv1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/job"
	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
	"github.com/smartcontractkit/chainlink-ccv/executor"
)

const (
	standaloneTestAlias          = shared.NOPAlias("chainlink-ccv-staging-0")
	standaloneTestVerifierNodeID = "node_verifier"
	standaloneTestExecutorNodeID = "node_executor"
)

type standaloneExecutorTestAdapter struct {
	selectors []uint64
}

func (a *standaloneExecutorTestAdapter) GetDeployedChains(datastore.DataStore, string) []uint64 {
	return a.selectors
}

func (a *standaloneExecutorTestAdapter) ResolveExecutorAddress(datastore.DataStore, uint64, string) (string, error) {
	return "0xexecutor", nil
}

func (a *standaloneExecutorTestAdapter) BuildChainConfig(datastore.DataStore, uint64, string) (executor.ChainConfiguration, error) {
	return executor.ChainConfiguration{}, nil
}

func (a *standaloneExecutorTestAdapter) RequiresNodeChainSupportInJD() bool {
	return false
}

type standaloneRoutingJDClient struct {
	foffchain.Client
	nodes     []*nodev1.Node
	proposals []*jobv1.ProposeJobRequest
}

func (c *standaloneRoutingJDClient) ListNodes(_ context.Context, req *nodev1.ListNodesRequest, _ ...grpc.CallOption) (*nodev1.ListNodesResponse, error) {
	var nodes []*nodev1.Node
	for _, node := range c.nodes {
		if len(req.GetFilter().GetIds()) == 0 || slices.Contains(req.GetFilter().GetIds(), node.GetId()) {
			nodes = append(nodes, node)
		}
	}
	return &nodev1.ListNodesResponse{Nodes: nodes}, nil
}

func (c *standaloneRoutingJDClient) ListNodeChainConfigs(context.Context, *nodev1.ListNodeChainConfigsRequest, ...grpc.CallOption) (*nodev1.ListNodeChainConfigsResponse, error) {
	return &nodev1.ListNodeChainConfigsResponse{}, nil
}

func (c *standaloneRoutingJDClient) ProposeJob(_ context.Context, req *jobv1.ProposeJobRequest, _ ...grpc.CallOption) (*jobv1.ProposeJobResponse, error) {
	c.proposals = append(c.proposals, req)
	return &jobv1.ProposeJobResponse{Proposal: &jobv1.Proposal{
		Id:       "proposal-new",
		JobId:    "jd-job-new",
		Revision: 2,
		Spec:     req.GetSpec(),
	}}, nil
}

func TestApplyExecutorConfigStandaloneNodeRouting(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	adapters.GetExecutorRegistry().Register(chainsel.FamilyEVM, &standaloneExecutorTestAdapter{selectors: []uint64{sel}})

	tests := []struct {
		name           string
		seedMetadata   bool
		explicitNodeID string
	}{
		{name: "reconciled standalone executor", seedMetadata: true},
		{name: "initial standalone provisioning with explicit node", explicitNodeID: standaloneTestExecutorNodeID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &standaloneRoutingJDClient{nodes: []*nodev1.Node{
				{Id: standaloneTestVerifierNodeID, Name: string(standaloneTestAlias)},
				{Id: standaloneTestExecutorNodeID, Name: "executor-evm-0"},
			}}
			env := newTestEnvForApply(t, string(standaloneTestAlias), []uint64{sel})
			env.Offchain = client
			env.NodeIDs = []string{standaloneTestVerifierNodeID, standaloneTestExecutorNodeID}
			ds := datastore.NewMemoryDataStore()
			if tt.seedMetadata {
				require.NoError(t, ccvdeployment.SaveJob(ds, standaloneExecutorTestJobInfo()))
			}
			env.DataStore = ds.Seal()
			cfg := standaloneExecutorTestInput(sel)
			cfg.NOPs[0].ExecutorNodeID = tt.explicitNodeID

			require.NoError(t, ApplyExecutorConfig().VerifyPreconditions(env, cfg))
			out, err := ApplyExecutorConfig().Apply(env, cfg)
			require.NoError(t, err)
			require.Len(t, client.proposals, 1)
			require.Equal(t, standaloneTestExecutorNodeID, client.proposals[0].GetNodeId())
			require.Contains(t, client.proposals[0].GetSpec(), "appConfig = '''")
			require.NotContains(t, client.proposals[0].GetSpec(), "executorConfig = '''")

			jobID := shared.NewExecutorJobID(standaloneTestAlias, shared.ExecutorJobScope{
				ExecutorQualifier: testExecutorQualifier,
			}).ToJobID()
			job, err := ccvdeployment.GetJob(out.DataStore.Seal(), standaloneTestAlias, jobID)
			require.NoError(t, err)
			require.Equal(t, standaloneTestExecutorNodeID, job.NodeID)
			require.Equal(t, "jd-job-new", job.JDJobID)
			require.Equal(t, shared.NOPModeStandalone, job.Mode)
			require.Equal(t, client.proposals[0].GetSpec(), job.LatestProposal().Spec)
		})
	}
}

func TestStandaloneExecutorJobNodeIDsValidation(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	adapters.GetExecutorRegistry().Register(chainsel.FamilyEVM, &standaloneExecutorTestAdapter{selectors: []uint64{sel}})

	tests := []struct {
		name           string
		mutateMetadata func(*shared.JobInfo)
		omitMetadata   bool
		explicitNodeID string
		mode           shared.NOPMode
		nodeIDs        []string
		wantError      string
	}{
		{name: "reconciled metadata"},
		{name: "initial provisioning uses explicit node", omitMetadata: true, explicitNodeID: standaloneTestExecutorNodeID},
		{name: "missing metadata fails closed", omitMetadata: true, wantError: "has no JD metadata"},
		{name: "CL metadata fails closed", mutateMetadata: func(job *shared.JobInfo) { job.Mode = shared.NOPModeCL }, wantError: `"cl"-mode JD metadata`},
		{name: "missing JD job ID fails", mutateMetadata: func(job *shared.JobInfo) { job.JDJobID = "" }, wantError: "incomplete JD metadata"},
		{name: "wrong external job ID fails", mutateMetadata: func(job *shared.JobInfo) { job.ExternalJobID = "wrong" }, wantError: "incomplete JD metadata"},
		{name: "explicit node conflicts with reconciled metadata", explicitNodeID: "node_other", nodeIDs: []string{standaloneTestVerifierNodeID, standaloneTestExecutorNodeID, "node_other"}, wantError: "conflicts with reconciled node ID"},
		{name: "target must belong to environment", nodeIDs: []string{standaloneTestVerifierNodeID}, wantError: "outside the environment node list"},
		{name: "CL mode remains alias routed", omitMetadata: true, mode: shared.NOPModeCL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds := datastore.NewMemoryDataStore()
			if !tt.omitMetadata {
				job := standaloneExecutorTestJobInfo()
				if tt.mutateMetadata != nil {
					tt.mutateMetadata(&job)
				}
				require.NoError(t, ccvdeployment.SaveJob(ds, job))
			}
			nodeIDs := tt.nodeIDs
			if nodeIDs == nil {
				nodeIDs = []string{standaloneTestVerifierNodeID, standaloneTestExecutorNodeID}
			}
			env := deployment.Environment{
				DataStore: ds.Seal(),
				Offchain:  &standaloneRoutingJDClient{},
				NodeIDs:   nodeIDs,
			}
			cfg := standaloneExecutorTestInput(sel)
			cfg.NOPs[0].ExecutorNodeID = tt.explicitNodeID
			if tt.mode != "" {
				cfg.NOPs[0].Mode = tt.mode
			}

			nodeIDMap, err := standaloneExecutorJobNodeIDs(env, cfg)
			if tt.wantError != "" {
				require.ErrorContains(t, err, tt.wantError)
				return
			}
			require.NoError(t, err)
			if cfg.NOPs[0].Mode == shared.NOPModeCL {
				require.Empty(t, nodeIDMap)
			} else {
				jobID := shared.NewExecutorJobID(standaloneTestAlias, shared.ExecutorJobScope{
					ExecutorQualifier: testExecutorQualifier,
				}).ToJobID()
				require.Equal(t, standaloneTestExecutorNodeID, nodeIDMap[jobID])
			}
		})
	}
}

func TestApplyVerifierExecutorConfigRejectsMissingStandaloneRouting(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerEVMOnchain(&stubOnchainAdapter{})
	adapters.GetExecutorRegistry().Register(chainsel.FamilyEVM, &standaloneExecutorTestAdapter{selectors: []uint64{sel}})
	cfg := validCombinedVerifierExecutorInput(sel)
	cfg.NOPs[0].Mode = shared.NOPModeStandalone

	err := ApplyVerifierExecutorConfig().VerifyPreconditions(deployment.Environment{
		Offchain:  nopOffchainClient{},
		NodeIDs:   []string{standaloneTestExecutorNodeID},
		DataStore: datastore.NewMemoryDataStore().Seal(),
	}, cfg)
	require.ErrorContains(t, err, "executor:")
	require.ErrorContains(t, err, "has no JD metadata")
}

func standaloneExecutorTestInput(sel uint64) ApplyExecutorConfigInput {
	return ApplyExecutorConfigInput{
		ExecutorQualifier: testExecutorQualifier,
		NOPs: []NOPInput{{
			Alias: standaloneTestAlias,
			Mode:  shared.NOPModeStandalone,
		}},
		Pool:           sampleExecutorPool(sel, standaloneTestAlias),
		IndexerAddress: []string{"indexer:1234"},
	}
}

func standaloneExecutorTestJobInfo() shared.JobInfo {
	jobID := shared.NewExecutorJobID(standaloneTestAlias, shared.ExecutorJobScope{
		ExecutorQualifier: testExecutorQualifier,
	}).ToJobID()
	spec := fmt.Sprintf(`schemaVersion = 1
type = "ccvexecutor"
name = %q
externalJobID = %q
appConfig = '''
executor_id = %q
'''
`, jobID, jobID.ToExternalJobID(), standaloneTestAlias)
	return shared.JobInfo{
		JobID:            jobID,
		JDJobID:          "jd-job-old",
		ExternalJobID:    jobID.ToExternalJobID(),
		NOPAlias:         standaloneTestAlias,
		NodeID:           standaloneTestExecutorNodeID,
		Mode:             shared.NOPModeStandalone,
		Spec:             spec,
		ActiveProposalID: "proposal-old",
		Proposals: map[string]shared.ProposalRevision{
			"proposal-old": {
				ProposalID: "proposal-old",
				Revision:   1,
				Status:     shared.JobProposalStatusApproved,
				Spec:       spec,
			},
		},
	}
}
