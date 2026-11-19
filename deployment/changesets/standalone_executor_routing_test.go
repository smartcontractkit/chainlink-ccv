package changesets

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
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
	standaloneTestAlias            = shared.NOPAlias("chainlink-ccv-staging-0")
	standaloneTestVerifierNodeID   = "node_verifier"
	standaloneTestExecutorNodeID   = "node_executor"
	standaloneTestExecutorNodeName = "executor-evm-0"
)

type standaloneExecutorTestAdapter struct {
	selectors             []uint64
	requireJDChainSupport bool
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
	return a.requireJDChainSupport
}

// standaloneRoutingJDClient models JD closely enough for routing: one JD job per node, and
// each proposal to a node adds a revision to that node's job.
type standaloneRoutingJDClient struct {
	foffchain.Client
	nodes        []*nodev1.Node
	inventoryErr error
	chainConfigs []*nodev1.ChainConfig
	proposals    []*jobv1.ProposeJobRequest
	jdJobs       map[string]string // node ID -> JD job ID
	jdJobUUIDs   map[string]string // JD job ID -> external job ID
	jdProposals  []*jobv1.Proposal
}

var externalJobIDPattern = regexp.MustCompile(`externalJobID = "([^"]+)"`)

func newStandaloneRoutingJDClient() *standaloneRoutingJDClient {
	return &standaloneRoutingJDClient{nodes: []*nodev1.Node{
		ccvTestNode(standaloneTestVerifierNodeID, string(standaloneTestAlias), "test", ""),
		ccvTestNode(standaloneTestExecutorNodeID, standaloneTestExecutorNodeName, "test", standaloneTestExecutorNodeName),
	}}
}

func (c *standaloneRoutingJDClient) seedJDJob(nodeID, jdJobID, externalJobID string, proposals ...*jobv1.Proposal) {
	c.recordJDJob(nodeID, jdJobID, externalJobID)
	for _, p := range proposals {
		p.JobId = jdJobID
		c.jdProposals = append(c.jdProposals, p)
	}
}

func (c *standaloneRoutingJDClient) recordJDJob(nodeID, jdJobID, externalJobID string) {
	if c.jdJobs == nil {
		c.jdJobs = make(map[string]string)
		c.jdJobUUIDs = make(map[string]string)
	}
	c.jdJobs[nodeID] = jdJobID
	c.jdJobUUIDs[jdJobID] = externalJobID
}

func (c *standaloneRoutingJDClient) ListJobs(_ context.Context, req *jobv1.ListJobsRequest, _ ...grpc.CallOption) (*jobv1.ListJobsResponse, error) {
	var jobs []*jobv1.Job
	for nodeID, jdJobID := range c.jdJobs {
		if slices.Contains(req.GetFilter().GetNodeIds(), nodeID) {
			jobs = append(jobs, &jobv1.Job{Id: jdJobID, NodeId: nodeID, Uuid: c.jdJobUUIDs[jdJobID]})
		}
	}
	return &jobv1.ListJobsResponse{Jobs: jobs}, nil
}

func (c *standaloneRoutingJDClient) ListNodes(_ context.Context, req *nodev1.ListNodesRequest, _ ...grpc.CallOption) (*nodev1.ListNodesResponse, error) {
	if c.inventoryErr != nil && len(req.GetFilter().GetIds()) == 0 {
		return nil, c.inventoryErr
	}
	var nodes []*nodev1.Node
	for _, node := range c.nodes {
		if len(req.GetFilter().GetIds()) == 0 || slices.Contains(req.GetFilter().GetIds(), node.GetId()) {
			nodes = append(nodes, node)
		}
	}
	return &nodev1.ListNodesResponse{Nodes: nodes}, nil
}

func (c *standaloneRoutingJDClient) ListNodeChainConfigs(_ context.Context, req *nodev1.ListNodeChainConfigsRequest, _ ...grpc.CallOption) (*nodev1.ListNodeChainConfigsResponse, error) {
	var configs []*nodev1.ChainConfig
	for _, cfg := range c.chainConfigs {
		if slices.Contains(req.GetFilter().GetNodeIds(), cfg.GetNodeId()) {
			configs = append(configs, cfg)
		}
	}
	return &nodev1.ListNodeChainConfigsResponse{ChainConfigs: configs}, nil
}

func (c *standaloneRoutingJDClient) ProposeJob(_ context.Context, req *jobv1.ProposeJobRequest, _ ...grpc.CallOption) (*jobv1.ProposeJobResponse, error) {
	c.proposals = append(c.proposals, req)
	jdJobID, ok := c.jdJobs[req.GetNodeId()]
	if !ok {
		jdJobID = "jd-job-" + req.GetNodeId()
		var externalJobID string
		if m := externalJobIDPattern.FindStringSubmatch(req.GetSpec()); m != nil {
			externalJobID = m[1]
		}
		c.recordJDJob(req.GetNodeId(), jdJobID, externalJobID)
	}
	revision := int64(1)
	for _, p := range c.jdProposals {
		if p.GetJobId() == jdJobID && p.GetRevision() >= revision {
			revision = p.GetRevision() + 1
		}
	}
	proposal := &jobv1.Proposal{
		Id:       fmt.Sprintf("%s-rev-%d", jdJobID, revision),
		JobId:    jdJobID,
		Revision: revision,
		Status:   jobv1.ProposalStatus_PROPOSAL_STATUS_PROPOSED,
		Spec:     req.GetSpec(),
	}
	c.jdProposals = append(c.jdProposals, proposal)
	return &jobv1.ProposeJobResponse{Proposal: proposal}, nil
}

func (c *standaloneRoutingJDClient) ListProposals(_ context.Context, req *jobv1.ListProposalsRequest, _ ...grpc.CallOption) (*jobv1.ListProposalsResponse, error) {
	var proposals []*jobv1.Proposal
	for _, p := range c.jdProposals {
		if slices.Contains(req.GetFilter().GetJobIds(), p.GetJobId()) {
			proposals = append(proposals, p)
		}
	}
	return &jobv1.ListProposalsResponse{Proposals: proposals}, nil
}

func (c *standaloneRoutingJDClient) setStatus(proposalID string, status jobv1.ProposalStatus) {
	for _, p := range c.jdProposals {
		if p.GetId() == proposalID {
			p.Status = status
		}
	}
}

// standaloneApplier runs ApplyExecutorConfig repeatedly, carrying the datastore between runs.
type standaloneApplier struct {
	t      *testing.T
	sel    uint64
	client *standaloneRoutingJDClient
	ds     datastore.DataStore
}

func newStandaloneApplier(t *testing.T, adapter *standaloneExecutorTestAdapter) *standaloneApplier {
	t.Helper()
	sel := chainsel.TEST_90000001.Selector
	adapter.selectors = []uint64{sel}
	adapters.GetExecutorRegistry().Register(chainsel.FamilyEVM, adapter)
	return &standaloneApplier{t: t, sel: sel, client: newStandaloneRoutingJDClient(), ds: datastore.NewMemoryDataStore().Seal()}
}

func (a *standaloneApplier) seedJobs(jobs ...shared.JobInfo) {
	a.t.Helper()
	ds := datastore.NewMemoryDataStore()
	require.NoError(a.t, ds.Merge(a.ds))
	require.NoError(a.t, ccvdeployment.SaveJobs(ds, jobs))
	a.ds = ds.Seal()
}

func (a *standaloneApplier) apply(withJD bool, mutate func(*NOPInput)) error {
	a.t.Helper()
	env := newTestEnvForApply(a.t, string(standaloneTestAlias), []uint64{a.sel})
	env.GetContext = a.t.Context
	env.Offchain = nil
	if withJD {
		env.Offchain = a.client
	}
	env.NodeIDs = []string{standaloneTestVerifierNodeID, standaloneTestExecutorNodeID}
	env.DataStore = a.ds
	cfg := standaloneExecutorTestInput(a.sel)
	if mutate != nil {
		mutate(&cfg.NOPs[0])
	}
	if err := ApplyExecutorConfig().VerifyPreconditions(env, cfg); err != nil {
		return err
	}
	out, err := ApplyExecutorConfig().Apply(env, cfg)
	if err != nil {
		return err
	}
	a.ds = out.DataStore.Seal()
	return nil
}

func (a *standaloneApplier) job() *shared.JobInfo {
	a.t.Helper()
	job, err := ccvdeployment.GetJob(a.ds, standaloneTestAlias, standaloneExecutorTestJobID())
	require.NoError(a.t, err)
	return job
}

func byName(nop *NOPInput) { nop.ExecutorNodeName = standaloneTestExecutorNodeName }

func TestApplyExecutorConfigStandaloneNodeRouting(t *testing.T) {
	tests := []struct {
		name         string
		seed         bool
		mutate       func(*NOPInput)
		wantJDJobID  string
		wantRevision int64
	}{
		{name: "reconciled standalone executor", seed: true, wantJDJobID: "jd-job-old", wantRevision: 2},
		{name: "initial provisioning by node ID", mutate: func(nop *NOPInput) { nop.ExecutorNodeID = standaloneTestExecutorNodeID }, wantJDJobID: "jd-job-node_executor", wantRevision: 1},
		{name: "initial provisioning by node name", mutate: byName, wantJDJobID: "jd-job-node_executor", wantRevision: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newStandaloneApplier(t, &standaloneExecutorTestAdapter{})
			if tt.seed {
				seeded := standaloneExecutorTestJobInfo()
				a.seedJobs(seeded)
				a.client.seedJDJob(standaloneTestExecutorNodeID, seeded.JDJobID, seeded.ExternalJobID, &jobv1.Proposal{
					Id: "proposal-old", Revision: 1, Status: jobv1.ProposalStatus_PROPOSAL_STATUS_APPROVED, Spec: seeded.Spec,
				})
			}

			require.NoError(t, a.apply(true, tt.mutate))
			require.Len(t, a.client.proposals, 1)
			require.Equal(t, standaloneTestExecutorNodeID, a.client.proposals[0].GetNodeId())
			require.Contains(t, a.client.proposals[0].GetSpec(), "appConfig = '''")
			require.NotContains(t, a.client.proposals[0].GetSpec(), "executorConfig = '''")

			job := a.job()
			require.Equal(t, standaloneTestExecutorNodeID, job.NodeID)
			require.Equal(t, tt.wantJDJobID, job.JDJobID)
			require.Equal(t, shared.NOPModeStandalone, job.Mode)
			require.Equal(t, a.client.proposals[0].GetSpec(), job.Spec)
			require.Equal(t, tt.wantRevision, job.LatestProposal().Revision)
			require.Equal(t, shared.JobProposalStatusPending, job.LatestStatus())
			require.Empty(t, job.LatestProposal().Spec)

			nodes, err := ccvdeployment.GetJDNodes(a.ds)
			require.NoError(t, err)
			require.Len(t, nodes, 2)
			require.Equal(t, standaloneTestExecutorNodeName, nodes[standaloneTestExecutorNodeID].Name)
			require.Equal(t, "csa-"+standaloneTestExecutorNodeID, nodes[standaloneTestExecutorNodeID].CSAKey)
			require.Equal(t, standaloneTestExecutorNodeName, nodes[standaloneTestExecutorNodeID].Labels["target"])
		})
	}
}

func TestApplyExecutorConfigDoesNotProposeWhenNodeInventorySyncFails(t *testing.T) {
	a := newStandaloneApplier(t, &standaloneExecutorTestAdapter{})
	a.client.inventoryErr = errors.New("inventory unavailable")

	require.ErrorContains(t, a.apply(true, byName), "failed to sync JD node inventory")
	require.Empty(t, a.client.proposals)
}

func TestApplyExecutorConfigMovesCLJobToExecutorNode(t *testing.T) {
	a := newStandaloneApplier(t, &standaloneExecutorTestAdapter{})
	jobID := standaloneExecutorTestJobID()
	a.seedJobs(shared.JobInfo{
		JobID: jobID, JDJobID: "jd-job-cl", ExternalJobID: jobID.ToExternalJobID(), NOPAlias: standaloneTestAlias,
		NodeID: standaloneTestVerifierNodeID, Mode: shared.NOPModeCL, Spec: "cl-spec", ActiveProposalID: "p-cl",
		Proposals: map[string]shared.ProposalRevision{"p-cl": {ProposalID: "p-cl", Revision: 7, Status: shared.JobProposalStatusApproved}},
	})
	a.client.seedJDJob(standaloneTestVerifierNodeID, "jd-job-cl", jobID.ToExternalJobID(), &jobv1.Proposal{
		Id: "p-cl", Revision: 7, Status: jobv1.ProposalStatus_PROPOSAL_STATUS_APPROVED, Spec: "cl-spec",
	})

	require.ErrorContains(t, a.apply(true, nil), `recorded in "cl" mode`)
	require.NoError(t, a.apply(true, byName))

	require.Len(t, a.client.proposals, 1)
	require.Equal(t, standaloneTestExecutorNodeID, a.client.proposals[0].GetNodeId())
	job := a.job()
	require.Equal(t, "jd-job-node_executor", job.JDJobID)
	require.Equal(t, standaloneTestExecutorNodeID, job.NodeID)
	require.Len(t, job.Proposals, 1, "the previous JD job's proposals must not carry over")
	require.Empty(t, job.ActiveProposalID)
	require.False(t, job.IsRunning())
	require.Equal(t, shared.JobProposalStatusPending, job.LatestStatus())
}

func TestApplyExecutorConfigAdoptsJobAlreadyOnExecutorNode(t *testing.T) {
	fresh := newStandaloneApplier(t, &standaloneExecutorTestAdapter{})
	require.NoError(t, fresh.apply(true, byName))
	desired := fresh.client.proposals[0].GetSpec()

	a := newStandaloneApplier(t, &standaloneExecutorTestAdapter{})
	jobID := standaloneExecutorTestJobID()
	a.seedJobs(shared.JobInfo{
		JobID: jobID, JDJobID: "jd-job-cl", ExternalJobID: jobID.ToExternalJobID(), NOPAlias: standaloneTestAlias,
		NodeID: standaloneTestVerifierNodeID, Mode: shared.NOPModeCL, Spec: "cl-spec",
	})
	a.client.seedJDJob(standaloneTestVerifierNodeID, "jd-job-cl", jobID.ToExternalJobID(), &jobv1.Proposal{
		Id: "p-cl", Revision: 7, Status: jobv1.ProposalStatus_PROPOSAL_STATUS_APPROVED, Spec: "cl-spec",
	})
	a.client.seedJDJob(standaloneTestExecutorNodeID, "jd-manual", jobID.ToExternalJobID(), &jobv1.Proposal{
		Id: "manual-1", Revision: 1, Status: jobv1.ProposalStatus_PROPOSAL_STATUS_APPROVED, Spec: desired,
	})

	require.NoError(t, a.apply(true, byName))
	require.Empty(t, a.client.proposals, "a job already proposed on the executor node is adopted, not proposed again")
	job := a.job()
	require.Equal(t, "jd-manual", job.JDJobID)
	require.Equal(t, standaloneTestExecutorNodeID, job.NodeID)
	require.Equal(t, shared.NOPModeStandalone, job.Mode)
	require.Equal(t, "manual-1", job.ActiveProposalID)
	require.Equal(t, shared.JobProposalStatusApproved, job.LatestStatus())
}

func TestApplyExecutorConfigMovesAliasRoutedJob(t *testing.T) {
	a := newStandaloneApplier(t, &standaloneExecutorTestAdapter{})
	misrouted := standaloneExecutorTestJobInfo()
	misrouted.NodeID = standaloneTestVerifierNodeID
	a.seedJobs(misrouted, shared.JobInfo{
		JobID: "chainlink-ccv-staging-0-default-verifier", NOPAlias: standaloneTestAlias, NodeID: standaloneTestVerifierNodeID,
	})
	a.client.seedJDJob(standaloneTestVerifierNodeID, misrouted.JDJobID, misrouted.ExternalJobID, &jobv1.Proposal{
		Id: "proposal-old", Revision: 1, Status: jobv1.ProposalStatus_PROPOSAL_STATUS_APPROVED, Spec: misrouted.Spec,
	})

	require.ErrorContains(t, a.apply(true, nil), `already runs job "chainlink-ccv-staging-0-default-verifier"`)
	require.NoError(t, a.apply(true, byName))
	require.Len(t, a.client.proposals, 1)
	require.Equal(t, standaloneTestExecutorNodeID, a.client.proposals[0].GetNodeId())
	require.Equal(t, standaloneTestExecutorNodeID, a.job().NodeID)
	require.Equal(t, "jd-job-node_executor", a.job().JDJobID)
}

func TestApplyExecutorConfigNoJDThenJD(t *testing.T) {
	a := newStandaloneApplier(t, &standaloneExecutorTestAdapter{})
	require.NoError(t, a.apply(false, nil))
	require.Empty(t, a.job().JDJobID)

	require.ErrorContains(t, a.apply(true, nil), "has no JD node")
	require.NoError(t, a.apply(true, byName))
	require.Len(t, a.client.proposals, 1)
	require.Equal(t, standaloneTestExecutorNodeID, a.job().NodeID)
	require.Equal(t, "jd-job-node_executor", a.job().JDJobID)
}

func TestApplyExecutorConfigKeepsJDInSync(t *testing.T) {
	a := newStandaloneApplier(t, &standaloneExecutorTestAdapter{})
	require.NoError(t, a.apply(true, byName))
	require.Len(t, a.client.proposals, 1)
	desired := a.client.proposals[0].GetSpec()

	// An approval in JD is reflected without a separate sync, and nothing is re-proposed.
	a.client.setStatus("jd-job-node_executor-rev-1", jobv1.ProposalStatus_PROPOSAL_STATUS_APPROVED)
	require.NoError(t, a.apply(true, byName))
	require.Len(t, a.client.proposals, 1)
	require.Equal(t, shared.JobProposalStatusApproved, a.job().LatestStatus())
	require.Equal(t, "jd-job-node_executor-rev-1", a.job().ActiveProposalID)

	// A revision proposed outside the changeset is replaced with the desired spec.
	a.client.jdProposals = append(a.client.jdProposals, &jobv1.Proposal{
		Id: "manual", JobId: "jd-job-node_executor", Revision: 2, Status: jobv1.ProposalStatus_PROPOSAL_STATUS_APPROVED, Spec: "manual-spec",
	})
	require.NoError(t, a.apply(true, byName))
	require.Len(t, a.client.proposals, 2)
	require.Equal(t, desired, a.client.proposals[1].GetSpec())
	job := a.job()
	require.Equal(t, int64(3), job.LatestProposal().Revision)
	require.Equal(t, "manual", job.ActiveProposalID)
}

func TestApplyExecutorConfigChecksChainSupportOnExecutorNode(t *testing.T) {
	registerEVMChainTypeForIdentities()
	chainID := strconv.FormatUint(chainsel.TEST_90000001.EvmChainID, 10)
	chainConfig := func(nodeID string) *nodev1.ChainConfig {
		return &nodev1.ChainConfig{NodeId: nodeID, Chain: &nodev1.Chain{Id: chainID, Type: nodev1.ChainType_CHAIN_TYPE_EVM}}
	}

	t.Run("executor node supports the chain", func(t *testing.T) {
		a := newStandaloneApplier(t, &standaloneExecutorTestAdapter{requireJDChainSupport: true})
		a.client.chainConfigs = []*nodev1.ChainConfig{chainConfig(standaloneTestExecutorNodeID)}
		require.NoError(t, a.apply(true, byName))
	})

	t.Run("only the verifier node supports the chain", func(t *testing.T) {
		a := newStandaloneApplier(t, &standaloneExecutorTestAdapter{requireJDChainSupport: true})
		a.client.chainConfigs = []*nodev1.ChainConfig{chainConfig(standaloneTestVerifierNodeID)}
		require.ErrorContains(t, a.apply(true, byName), "missing chain configs")
		require.Empty(t, a.client.proposals)
	})
}

func TestStandaloneExecutorNodeIDsValidation(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	adapters.GetExecutorRegistry().Register(chainsel.FamilyEVM, &standaloneExecutorTestAdapter{selectors: []uint64{sel}})
	const otherNodeID = "node_other"

	tests := []struct {
		name           string
		mutateMetadata func(*shared.JobInfo)
		omitMetadata   bool
		extraJobs      []shared.JobInfo
		mutateNOP      func(*NOPInput)
		nodeIDs        []string
		wantNodeID     string
		wantError      string
	}{
		{name: "reconciled metadata", wantNodeID: standaloneTestExecutorNodeID},
		{name: "initial provisioning by node ID", omitMetadata: true, mutateNOP: func(nop *NOPInput) { nop.ExecutorNodeID = standaloneTestExecutorNodeID }, wantNodeID: standaloneTestExecutorNodeID},
		{name: "initial provisioning by node name", omitMetadata: true, mutateNOP: byName, wantNodeID: standaloneTestExecutorNodeID},
		{name: "missing metadata fails closed", omitMetadata: true, wantError: "has no JD node"},
		{name: "never-proposed metadata fails closed", mutateMetadata: neverProposed, wantError: "has no JD node"},
		{name: "never-proposed metadata takes the declared node", mutateMetadata: neverProposed, mutateNOP: byName, wantNodeID: standaloneTestExecutorNodeID},
		{name: "CL metadata fails closed", mutateMetadata: func(job *shared.JobInfo) { job.Mode = shared.NOPModeCL }, wantError: `recorded in "cl" mode`},
		{name: "CL metadata moves to the declared node", mutateMetadata: func(job *shared.JobInfo) { job.Mode = shared.NOPModeCL }, mutateNOP: byName, wantNodeID: standaloneTestExecutorNodeID},
		{name: "missing JD job ID fails", mutateMetadata: func(job *shared.JobInfo) { job.JDJobID = "" }, wantError: "incomplete JD metadata"},
		{name: "wrong external job ID fails", mutateMetadata: func(job *shared.JobInfo) { job.ExternalJobID = "wrong" }, wantError: "incomplete JD metadata"},
		{
			name:       "declared node replaces the recorded node",
			mutateNOP:  func(nop *NOPInput) { nop.ExecutorNodeID = otherNodeID },
			nodeIDs:    []string{standaloneTestVerifierNodeID, standaloneTestExecutorNodeID, otherNodeID},
			wantNodeID: otherNodeID,
		},
		{
			name:      "recorded node that runs a verifier job fails",
			extraJobs: []shared.JobInfo{{JobID: "chainlink-ccv-staging-0-default-verifier", NOPAlias: standaloneTestAlias, NodeID: standaloneTestExecutorNodeID}},
			wantError: `already runs job "chainlink-ccv-staging-0-default-verifier"`,
		},
		{
			name:      "declared node that runs another executor fails",
			mutateNOP: byName,
			extraJobs: []shared.JobInfo{{JobID: "other-default-executor", NOPAlias: "other", NodeID: standaloneTestExecutorNodeID}},
			wantError: `already runs job "other-default-executor"`,
		},
		{name: "unknown node name fails", omitMetadata: true, mutateNOP: func(nop *NOPInput) { nop.ExecutorNodeName = "missing" }, wantError: `executor node "missing" is not a JD node`},
		{
			name:         "node name and ID must agree",
			omitMetadata: true,
			mutateNOP:    func(nop *NOPInput) { byName(nop); nop.ExecutorNodeID = standaloneTestVerifierNodeID },
			wantError:    "not ExecutorNodeID",
		},
		{name: "target must belong to environment", nodeIDs: []string{standaloneTestVerifierNodeID}, wantError: "outside the environment node list"},
		{name: "CL mode remains alias routed", omitMetadata: true, mutateNOP: func(nop *NOPInput) { nop.Mode = shared.NOPModeCL }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds := datastore.NewMemoryDataStore()
			jobs := slices.Clone(tt.extraJobs)
			if !tt.omitMetadata {
				job := standaloneExecutorTestJobInfo()
				if tt.mutateMetadata != nil {
					tt.mutateMetadata(&job)
				}
				jobs = append(jobs, job)
			}
			require.NoError(t, ccvdeployment.SaveJobs(ds, jobs))
			nodeIDs := tt.nodeIDs
			if nodeIDs == nil {
				nodeIDs = []string{standaloneTestVerifierNodeID, standaloneTestExecutorNodeID}
			}
			env := deployment.Environment{
				DataStore:  ds.Seal(),
				Offchain:   newStandaloneRoutingJDClient(),
				NodeIDs:    nodeIDs,
				GetContext: t.Context,
			}
			cfg := standaloneExecutorTestInput(sel)
			if tt.mutateNOP != nil {
				tt.mutateNOP(&cfg.NOPs[0])
			}

			nodeIDMap, err := standaloneExecutorNodeIDs(env, cfg)
			if tt.wantError != "" {
				require.ErrorContains(t, err, tt.wantError)
				return
			}
			require.NoError(t, err)
			if tt.wantNodeID == "" {
				require.Empty(t, nodeIDMap)
				return
			}
			require.Equal(t, map[shared.NOPAlias]string{standaloneTestAlias: tt.wantNodeID}, nodeIDMap)
		})
	}
}

func TestStandaloneExecutorJobsNeedDistinctNodes(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	adapters.GetExecutorRegistry().Register(chainsel.FamilyEVM, &standaloneExecutorTestAdapter{selectors: []uint64{sel}})
	cfg := standaloneExecutorTestInput(sel)
	cfg.NOPs = []NOPInput{
		{Alias: standaloneTestAlias, Mode: shared.NOPModeStandalone, ExecutorNodeID: standaloneTestExecutorNodeID},
		{Alias: "chainlink-ccv-staging-1", Mode: shared.NOPModeStandalone, ExecutorNodeID: standaloneTestExecutorNodeID},
	}
	cfg.Pool = sampleExecutorPool(sel, standaloneTestAlias, "chainlink-ccv-staging-1")

	_, err := standaloneExecutorNodeIDs(deployment.Environment{
		DataStore: datastore.NewMemoryDataStore().Seal(),
		Offchain:  newStandaloneRoutingJDClient(),
		NodeIDs:   []string{standaloneTestVerifierNodeID, standaloneTestExecutorNodeID},
	}, cfg)
	require.ErrorContains(t, err, "both target node")
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
	require.ErrorContains(t, err, "has no JD node")
}

func neverProposed(job *shared.JobInfo) {
	job.JDJobID = ""
	job.NodeID = ""
	job.ActiveProposalID = ""
	job.Proposals = nil
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

func standaloneExecutorTestJobID() shared.JobID {
	return shared.NewExecutorJobID(standaloneTestAlias, shared.ExecutorJobScope{
		ExecutorQualifier: testExecutorQualifier,
	}).ToJobID()
}

func standaloneExecutorTestJobInfo() shared.JobInfo {
	jobID := standaloneExecutorTestJobID()
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
