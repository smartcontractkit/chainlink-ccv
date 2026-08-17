package e2e

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/rs/zerolog"
	chain_selectors "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/deployment/v2_0_0/adapters"
	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	ccdeploy "github.com/smartcontractkit/chainlink-ccv/build/devenv/deploy"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/evm"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/jobs"
	ccvchangesets "github.com/smartcontractkit/chainlink-ccv/deployment/changesets"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	"github.com/smartcontractkit/chainlink-protos/job-distributor/v1/job"
	"github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/stretchr/testify/require"
)

const (
	Node0DefaultVerifierJobName                  = "node-0-default-verifier"
	Node1DefaultVerifierJobName                  = "node-1-default-verifier"
	Node0DefaultVerifierTempOnrampUpgradeJobName = "node-0-default-verifier-temp-onramp-upgrade"
	Node1DefaultVerifierTempOnrampUpgradeJobName = "node-1-default-verifier-temp-onramp-upgrade"
	DefaultVerifierCommitteeQualifier            = "default"
	DefaultVerifierDefaultExecutorQualifier      = "default"
	LegacyOnRampQualifier                        = "legacy"
	OnRampContractType                           = "OnRamp"
	OnRampContractVersion                        = "2.0.0"
	EmptyQualifier                               = ""
)

func Test_OnrampUpgrade(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode; requires a running devenv environment")
	}

	smokeTestConfig := GetSmokeTestConfig()
	in, err := ccv.LoadOutput[ccv.Cfg](smokeTestConfig)
	require.NoError(t, err)
	ctx := ccv.Plog.WithContext(t.Context())
	l := zerolog.Ctx(ctx)

	// Only load EVM chains for now, as more chains become supported we can add them.
	lib, err := ccv.NewLibFromCCVEnv(l, smokeTestConfig, chain_selectors.FamilyEVM)
	require.NoError(t, err)
	chains, err := lib.Chains(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(chains), 2, "expected at least 2 chains for this test in the environment")
	chainMap, err := lib.ChainsMap(ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		_, err := framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()))
		require.NoError(t, err)
	})

	sel0, sel1 := chains[0].Details.ChainSelector, chains[1].Details.ChainSelector
	tmpEnv, err := lib.CLDFEnvironment()
	require.NoError(t, err)
	require.NotNil(t, tmpEnv)
	jdClient := newJDClient(t, in)
	nodeIdsResp, err := jdClient.ListNodes(ctx, &node.ListNodesRequest{})
	require.NoError(t, err)
	nodeIds := make([]string, 0, len(nodeIdsResp.Nodes))
	for _, n := range nodeIdsResp.Nodes {
		nodeIds = append(nodeIds, n.Id)
	}
	env := &deployment.Environment{
		Name:             tmpEnv.Name,
		Logger:           tmpEnv.Logger,
		OperationsBundle: tmpEnv.OperationsBundle,
		BlockChains:      tmpEnv.BlockChains,
		DataStore:        tmpEnv.DataStore,
		Offchain:         jdClient,
		NodeIDs:          nodeIds,
	}
	clientLookup := newCLNodeLookup(t, in)
	allSels := make([]uint64, 0, len(chains))
	for _, c := range chains {
		allSels = append(allSels, c.Details.ChainSelector)
	}
	topology := ccdeploy.BuildEnvironmentTopology(in.EnvironmentTopology, in.Verifier, env, true)
	require.NotNil(t, topology)
	committeeCfg, ok := topology.NOPTopology.Committees["default"]
	require.True(t, ok, "expected default committee to be present in topology")
	nopsFromTopology := ccvchangesets.NOPInputsFromTopology(topology)
	committee := ccvchangesets.CommitteeInputFromTopologyPerFamily(committeeCfg, "evm")

	assertMessageGoesThrough := func(onrampRef datastore.AddressRef, seqNo uint64, useTestRouter bool) {
		sel0Chain := chainMap[sel0]
		sel0ChainSource, ok := sel0Chain.(cciptestinterfaces.ChainAsSource)
		require.True(t, ok, "expected sel0Chain to implement ChainAsSource")

		l.Info().Uint64("SeqNo", seqNo).Msg("Expecting sequence number")
		msg, err := sel0ChainSource.BuildChainMessage(ctx, cciptestinterfaces.MessageFields{
			Receiver: mustGetEOAReceiverAddress(t, chainMap[sel1]),
			Data:     []byte{},
		}, nil)
		require.NoError(t, err)
		msgSentEvent, _, err := sel0ChainSource.SendChainMessage(ctx, sel1, msg, evm.SendOptions{
			UseTestRouter: useTestRouter,
		})
		require.NoError(t, err)
		_, err = chainMap[sel1].ConfirmExecOnDest(ctx, sel0, cciptestinterfaces.MessageEventKey{SeqNum: seqNo}, 30*time.Second)
		require.NoError(t, err)

		require.NoError(t, err)
		msgOnramp := bytes.TrimLeft(msgSentEvent.Message.OnRampAddress.Bytes(), "\x00")
		require.Equal(t, strings.ToLower(strings.TrimPrefix(onrampRef.Address, "0x")), strings.ToLower(hex.EncodeToString(msgOnramp)))
		l.Info().Str("OnRamp", onrampRef.Address).Bool("UseTestRouter", useTestRouter).Str("MessageID", msgSentEvent.Message.MustMessageID().String()).Msg("Message sent through expected OnRamp")
	}

	assertOtherLaneGoesThrough := func(seqNo uint64) {
		sel1Chain := chainMap[sel1]
		sel1ChainSource, ok := sel1Chain.(cciptestinterfaces.ChainAsSource)
		require.True(t, ok, "expected sel1Chain to implement ChainAsSource")

		l.Info().Uint64("SeqNo", seqNo).Msg("Expecting sequence number")
		msg, err := sel1ChainSource.BuildChainMessage(ctx, cciptestinterfaces.MessageFields{
			Receiver: mustGetEOAReceiverAddress(t, chainMap[sel1]),
			Data:     []byte{},
		}, nil)
		require.NoError(t, err)
		_, _, err = sel1ChainSource.SendChainMessage(ctx, sel0, msg, evm.SendOptions{
			UseTestRouter: false,
		})
		require.NoError(t, err)
		_, err = chainMap[sel0].ConfirmExecOnDest(ctx, sel1, cciptestinterfaces.MessageEventKey{SeqNum: seqNo}, 30*time.Second)
		require.NoError(t, err)
	}

	legacyOnRampAddress, err := env.DataStore.Addresses().Get(datastore.NewAddressRefKey(sel0, OnRampContractType, semver.MustParse(OnRampContractVersion), EmptyQualifier))
	require.NoError(t, err)
	assertMessageGoesThrough(legacyOnRampAddress, 1, false)
	assertOtherLaneGoesThrough(1)
	assertJobSpecContainsOnRampAddress(t, Node0DefaultVerifierJobName, legacyOnRampAddress.Address, sel0)
	assertJobSpecContainsOnRampAddress(t, Node1DefaultVerifierJobName, legacyOnRampAddress.Address, sel0)

	upgraderRegistry := adapters.GetOnRampUpgraderRegistry()
	// Simulate Phase 1 upgrade by creating a new address ref for onramp and marking the existing one as legacy
	legacyOnRampAddress.Qualifier = LegacyOnRampQualifier
	require.NoError(t, err)
	newOnrampRef := datastore.AddressRef{
		ChainSelector: legacyOnRampAddress.ChainSelector,
		Type:          legacyOnRampAddress.Type,
		Version:       legacyOnRampAddress.Version,
		Address:       "0x000000000000000000000000000000000000ffff",
		Qualifier:     EmptyQualifier,
	}
	tempDS := datastore.NewMemoryDataStore()
	err = tempDS.Addresses().Add(newOnrampRef)
	require.NoError(t, err)
	err = tempDS.Addresses().Add(legacyOnRampAddress)
	require.NoError(t, err)

	ds := datastore.NewMemoryDataStore()
	ds.Merge(env.DataStore)
	ds.Merge(tempDS.Seal())
	env.DataStore = ds.Seal()

	// Send a message through the normal router and expect the legacy onramp to be used
	assertMessageGoesThrough(legacyOnRampAddress, 2, false)
	assertOtherLaneGoesThrough(2)
	assertJobSpecContainsOnRampAddress(t, Node0DefaultVerifierJobName, legacyOnRampAddress.Address, sel0)
	assertJobSpecContainsOnRampAddress(t, Node1DefaultVerifierJobName, legacyOnRampAddress.Address, sel0)

	// New fresh memory operation bundle
	env.OperationsBundle = operations.NewBundle(func() context.Context { return ctx }, env.Logger, operations.NewMemoryReporter())
	tempJobsCS := ccvchangesets.ApplyOnrampUpgradeVerifierConfig(upgraderRegistry)
	_, err = tempJobsCS.Apply(*env, ccvchangesets.ApplyVerifierConfigOnrampUpgradeInput{
		UpgradedChainSelectors: []uint64{sel0},
		ApplyVerifierConfigInput: ccvchangesets.ApplyVerifierConfigInput{
			CommitteeQualifier:       DefaultVerifierCommitteeQualifier,
			DefaultExecutorQualifier: DefaultVerifierDefaultExecutorQualifier,
			Committee:                committee,
			NOPs:                     nopsFromTopology,
			// Consolidated topology: one verifier job per NOP writing to every aggregator.
			ConsolidateAggregators: true,
		},
	})
	require.NoError(t, err)
	err = jobs.AcceptPendingJobs(ctx, clientLookup)
	require.NoError(t, err)
	time.Sleep(5 * time.Second)

	assertMessageGoesThrough(legacyOnRampAddress, 3, false)
	assertOtherLaneGoesThrough(3)
	assertJobSpecContainsOnRampAddress(t, Node0DefaultVerifierTempOnrampUpgradeJobName, legacyOnRampAddress.Address, sel0)
	assertJobSpecContainsOnRampAddress(t, Node1DefaultVerifierTempOnrampUpgradeJobName, legacyOnRampAddress.Address, sel0)

	env.OperationsBundle = operations.NewBundle(func() context.Context { return ctx }, env.Logger, operations.NewMemoryReporter())
	applyVerifierConfigCS := ccvchangesets.ApplyVerifierConfig()
	_, err = applyVerifierConfigCS.Apply(*env, ccvchangesets.ApplyVerifierConfigInput{
		CommitteeQualifier:       DefaultVerifierCommitteeQualifier,
		DefaultExecutorQualifier: DefaultVerifierDefaultExecutorQualifier,
		Committee:                committee,
		NOPs:                     nopsFromTopology,
		// Consolidated topology: one verifier job per NOP writing to every aggregator.
		ConsolidateAggregators: true,
	})
	require.NoError(t, err)
	err = jobs.AcceptPendingJobs(ctx, clientLookup)
	require.NoError(t, err)
	time.Sleep(5 * time.Second)

	assertJobSpecContainsOnRampAddress(t, Node0DefaultVerifierTempOnrampUpgradeJobName, legacyOnRampAddress.Address, sel0)
	assertJobSpecContainsOnRampAddress(t, Node1DefaultVerifierTempOnrampUpgradeJobName, legacyOnRampAddress.Address, sel0)
	assertJobSpecContainsOnRampAddress(t, Node0DefaultVerifierJobName, newOnrampRef.Address, sel0)
	assertJobSpecContainsOnRampAddress(t, Node1DefaultVerifierJobName, newOnrampRef.Address, sel0)
	assertMessageGoesThrough(legacyOnRampAddress, 4, false)
	assertOtherLaneGoesThrough(4)
}

func assertJobSpecContainsOnRampAddress(t *testing.T, jobSpecId string, onrampAddress string, chainSelector uint64) {
	p := getProposalByName(t, jobSpecId)
	require.NotNil(t, p, "expected to find a proposal for the job spec %s", jobSpecId)
	require.Contains(t, p.Spec, fmt.Sprintf("%d = \"%s\"", chainSelector, onrampAddress), "expected job spec to contain the onramp address for chain selector %d", chainSelector)
}

func getAllProposal(t *testing.T) []*job.Proposal {
	smokeTestConfig := GetSmokeTestConfig()
	in, err := ccv.LoadOutput[ccv.Cfg](smokeTestConfig)
	require.NoError(t, err)
	ctx := ccv.Plog.WithContext(t.Context())
	jdClient := newJDClient(t, in)

	proposals := make([]*job.Proposal, 0)
	resp, err := jdClient.ListJobs(ctx, &job.ListJobsRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp)

	for _, j := range resp.Jobs {
		resp2, err := jdClient.GetJob(ctx, &job.GetJobRequest{IdOneof: &job.GetJobRequest_Id{Id: j.Id}})
		require.NoError(t, err)
		require.NotNil(t, resp2)

		var latestProposal *job.Proposal = nil
		for _, p := range resp2.Job.ProposalIds {
			resp3, err := jdClient.GetProposal(ctx, &job.GetProposalRequest{Id: p})
			require.NoError(t, err)
			require.NotNil(t, resp3)
			if latestProposal == nil || resp3.Proposal.CreatedAt.AsTime().After(latestProposal.CreatedAt.AsTime()) {
				latestProposal = resp3.Proposal
			}
		}
		if latestProposal != nil {
			proposals = append(proposals, latestProposal)
		}
	}
	return proposals
}

func getProposalByName(t *testing.T, name string) *job.Proposal {
	var newestProposalMatch *job.Proposal = nil
	proposals := getAllProposal(t)
	for _, p := range proposals {
		if strings.Contains(p.Spec, fmt.Sprintf("name = \"%s\"", name)) {
			if newestProposalMatch == nil || p.CreatedAt.AsTime().After(newestProposalMatch.CreatedAt.AsTime()) {
				newestProposalMatch = p
			}
		}
	}
	return newestProposalMatch
}
