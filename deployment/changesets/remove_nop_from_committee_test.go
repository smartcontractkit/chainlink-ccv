package changesets

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	jobv1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/job"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	"github.com/smartcontractkit/chainlink-ccv/deployment/inventory"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

// ---- pure helper: buildRemoveSignerChange ----

func TestBuildRemoveSignerChange_RemovesSigner(t *testing.T) {
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: []string{"0xAAA", "0xBBB", "0xCCC"}, Threshold: 2},
		},
	}
	change, err := buildRemoveSignerChange(state, "0xBBB", 0, []uint64{1})
	require.NoError(t, err)
	require.Len(t, change.NewConfigs, 1)
	assert.Equal(t, []string{"0xAAA", "0xCCC"}, change.NewConfigs[0].Signers)
	assert.Equal(t, uint8(2), change.NewConfigs[0].Threshold)
}

func TestBuildRemoveSignerChange_ReplacesThresholdWhenNonZero(t *testing.T) {
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: []string{"0xAAA", "0xBBB", "0xCCC"}, Threshold: 3},
		},
	}
	change, err := buildRemoveSignerChange(state, "0xCCC", 2, []uint64{1})
	require.NoError(t, err)
	assert.Equal(t, uint8(2), change.NewConfigs[0].Threshold)
}

func TestBuildRemoveSignerChange_KeepsThresholdWhenZero(t *testing.T) {
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: []string{"0xAAA", "0xBBB"}, Threshold: 1},
		},
	}
	change, err := buildRemoveSignerChange(state, "0xBBB", 0, []uint64{1})
	require.NoError(t, err)
	assert.Equal(t, uint8(1), change.NewConfigs[0].Threshold)
}

func TestBuildRemoveSignerChange_ErrorsIfSignerNotFound(t *testing.T) {
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: []string{"0xAAA", "0xBBB"}, Threshold: 1},
		},
	}
	_, err := buildRemoveSignerChange(state, "0xCCC", 0, []uint64{1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found in committee")
}

func TestBuildRemoveSignerChange_CaseInsensitiveMatch(t *testing.T) {
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: []string{"0xabc", "0xDEF"}, Threshold: 1},
		},
	}
	change, err := buildRemoveSignerChange(state, "0xABC", 0, []uint64{1})
	require.NoError(t, err)
	assert.Equal(t, []string{"0xDEF"}, change.NewConfigs[0].Signers)
}

func TestBuildRemoveSignerChange_ErrorsOnLastSigner(t *testing.T) {
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: []string{"0xAAA"}, Threshold: 1},
		},
	}
	_, err := buildRemoveSignerChange(state, "0xAAA", 0, []uint64{1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot remove the last signer")
}

func TestBuildRemoveSignerChange_ErrorsWhenThresholdExceedsRemaining(t *testing.T) {
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: []string{"0xAAA", "0xBBB", "0xCCC"}, Threshold: 2},
		},
	}
	_, err := buildRemoveSignerChange(state, "0xCCC", 3, []uint64{1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "threshold 3 exceeds remaining signer count 2")
}

func TestBuildRemoveSignerChange_CurrentThresholdExceedsRemainingIsAlsoCaught(t *testing.T) {
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: []string{"0xAAA", "0xBBB"}, Threshold: 2},
		},
	}
	_, err := buildRemoveSignerChange(state, "0xBBB", 0, []uint64{1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "threshold 2 exceeds remaining signer count 1")
}

func TestBuildRemoveSignerChange_MultipleSourceChains(t *testing.T) {
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: []string{"0xAAA", "0xBBB"}, Threshold: 1},
			{SourceChainSelector: 2, Signers: []string{"0xAAA", "0xBBB"}, Threshold: 1},
		},
	}
	change, err := buildRemoveSignerChange(state, "0xAAA", 0, []uint64{1, 2})
	require.NoError(t, err)
	require.Len(t, change.NewConfigs, 2)
	for _, cfg := range change.NewConfigs {
		assert.Equal(t, []string{"0xBBB"}, cfg.Signers)
	}
}

func TestBuildRemoveSignerChange_OnlyUpdatesRequestedSourceChains(t *testing.T) {
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: []string{"0xAAA", "0xBBB"}, Threshold: 1},
			{SourceChainSelector: 2, Signers: []string{"0xAAA", "0xBBB"}, Threshold: 1},
		},
	}
	// Only request source chain 1 — source chain 2 must not appear in NewConfigs.
	change, err := buildRemoveSignerChange(state, "0xAAA", 0, []uint64{1})
	require.NoError(t, err)
	require.Len(t, change.NewConfigs, 1)
	assert.Equal(t, uint64(1), change.NewConfigs[0].SourceChainSelector)
}

func TestBuildRemoveSignerChange_ReturnsEmptyWhenNoSourceChainsMatch(t *testing.T) {
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: []string{"0xAAA", "0xBBB"}, Threshold: 1},
		},
	}
	change, err := buildRemoveSignerChange(state, "0xAAA", 0, []uint64{99})
	require.NoError(t, err)
	assert.Empty(t, change.NewConfigs)
}

// ---- RemoveNOPFromCommittee validation ----

func TestRemoveNOPFromCommittee_Validation_MissingQualifier(t *testing.T) {
	registerEVMOnchain(&stubOnchainAdapter{})
	cs := RemoveNOPFromCommittee()
	err := cs.VerifyPreconditions(newTestEnvironmentWithOffchain(), RemoveNOPFromCommitteeInput{
		SourceChainSelectors: []uint64{chainsel.TEST_90000001.Selector},
		NOPAlias:             testNOPAlias,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "committee qualifier is required")
}

func TestRemoveNOPFromCommittee_Validation_MissingSourceChainSelectors(t *testing.T) {
	registerEVMOnchain(&stubOnchainAdapter{})
	cs := RemoveNOPFromCommittee()
	err := cs.VerifyPreconditions(newTestEnvironmentWithOffchain(), RemoveNOPFromCommitteeInput{
		CommitteeQualifier: testQualifier,
		NOPAlias:           testNOPAlias,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one source chain selector is required")
}

func TestRemoveNOPFromCommittee_Validation_MissingNOPAlias(t *testing.T) {
	registerEVMOnchain(&stubOnchainAdapter{})
	cs := RemoveNOPFromCommittee()
	err := cs.VerifyPreconditions(newTestEnvironmentWithOffchain(), RemoveNOPFromCommitteeInput{
		CommitteeQualifier:   testQualifier,
		SourceChainSelectors: []uint64{chainsel.TEST_90000001.Selector},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "NOP alias is required")
}

func TestRemoveNOPFromCommittee_Validation_RequiresOffchainClient(t *testing.T) {
	registerEVMOnchain(&stubOnchainAdapter{})
	cs := RemoveNOPFromCommittee()
	err := cs.VerifyPreconditions(deployment.Environment{}, RemoveNOPFromCommitteeInput{
		CommitteeQualifier:   testQualifier,
		SourceChainSelectors: []uint64{chainsel.TEST_90000001.Selector},
		NOPAlias:             testNOPAlias,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "offchain client is required")
}

// ---- RemoveNOPOffchain validation ----

func TestRemoveNOPOffchain_Validation_MissingQualifier(t *testing.T) {
	registerFullEVMAdapters(&stubFullAdapter{})
	cs := RemoveNOPOffchain()
	err := cs.VerifyPreconditions(deployment.Environment{}, RemoveNOPOffchainInput{
		SourceChainSelectors: []uint64{chainsel.TEST_90000001.Selector},
		ServiceIdentifiers:   []string{"svc1"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "committee qualifier is required")
}

func TestRemoveNOPOffchain_Validation_MissingSourceChainSelectors(t *testing.T) {
	registerFullEVMAdapters(&stubFullAdapter{})
	cs := RemoveNOPOffchain()
	err := cs.VerifyPreconditions(deployment.Environment{}, RemoveNOPOffchainInput{
		CommitteeQualifier: testQualifier,
		ServiceIdentifiers: []string{"svc1"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one source chain selector is required")
}

func TestRemoveNOPOffchain_Validation_MissingServiceIdentifiers(t *testing.T) {
	registerFullEVMAdapters(&stubFullAdapter{})
	cs := RemoveNOPOffchain()
	err := cs.VerifyPreconditions(deployment.Environment{}, RemoveNOPOffchainInput{
		CommitteeQualifier:   testQualifier,
		SourceChainSelectors: []uint64{chainsel.TEST_90000001.Selector},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one service identifier is required")
}

func TestRemoveNOPOffchain_Validation_MissingNOPAlias(t *testing.T) {
	registerFullEVMAdapters(&stubFullAdapter{})
	cs := RemoveNOPOffchain()
	err := cs.VerifyPreconditions(deployment.Environment{}, RemoveNOPOffchainInput{
		CommitteeQualifier:   testQualifier,
		SourceChainSelectors: []uint64{chainsel.TEST_90000001.Selector},
		ServiceIdentifiers:   []string{"svc1"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "NOP alias is required for job revocation")
}

// ---- RemoveNOPOffchain backstop validation ----

func TestRemoveNOPOffchain_Validation_BackstopPassesWhenSignerAbsent(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	qualifier := testQualifier
	removedSigner := "0xDEAD"

	adapter := &stubFullAdapter{
		states: map[uint64][]*adapters.CommitteeState{
			sel1: {{
				Qualifier:     qualifier,
				ChainSelector: sel1,
				SignatureConfigs: []adapters.SignatureConfig{
					// removed signer is gone — step-1 has landed
					{SourceChainSelector: sel1, Signers: []string{"0xAAA", "0xBBB"}, Threshold: 1},
				},
			}},
		},
		verifierAddrs: map[uint64]string{sel1: "0x1111"},
	}

	registerFullEVMAdapters(adapter)
	cs := RemoveNOPOffchain()
	env := deployment.Environment{
		BlockChains: newTestBlockChains([]uint64{sel1}),
		DataStore:   datastore.NewMemoryDataStore().Seal(),
		GetContext:  func() context.Context { return context.Background() },
	}

	err := cs.VerifyPreconditions(env, RemoveNOPOffchainInput{
		CommitteeQualifier:   qualifier,
		SourceChainSelectors: []uint64{sel1},
		RemovedSignerAddress: removedSigner,
		ServiceIdentifiers:   []string{"svc1"},
		NOPAlias:             testNOPAlias,
	})
	require.NoError(t, err)
}

func TestRemoveNOPOffchain_Validation_BackstopFailsWhenSignerStillPresent(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	qualifier := testQualifier
	removedSigner := "0xDEAD"

	adapter := &stubFullAdapter{
		states: map[uint64][]*adapters.CommitteeState{
			sel1: {{
				Qualifier:     qualifier,
				ChainSelector: sel1,
				SignatureConfigs: []adapters.SignatureConfig{
					// removed signer still present — step-1 has not landed
					{SourceChainSelector: sel1, Signers: []string{"0xAAA", removedSigner}, Threshold: 1},
				},
			}},
		},
		verifierAddrs: map[uint64]string{sel1: "0x1111"},
	}

	registerFullEVMAdapters(adapter)
	cs := RemoveNOPOffchain()
	env := deployment.Environment{
		BlockChains: newTestBlockChains([]uint64{sel1}),
		DataStore:   datastore.NewMemoryDataStore().Seal(),
		GetContext:  func() context.Context { return context.Background() },
	}

	err := cs.VerifyPreconditions(env, RemoveNOPOffchainInput{
		CommitteeQualifier:   qualifier,
		SourceChainSelectors: []uint64{sel1},
		RemovedSignerAddress: removedSigner,
		ServiceIdentifiers:   []string{"svc1"},
		NOPAlias:             testNOPAlias,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "step-1 (RemoveNOPFromCommittee) may not have been applied")
}

// ---- RemoveNOPOffchain apply ----

func TestRemoveNOPOffchain_Apply_WritesUpdatedAggregatorConfig(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	qualifier := testQualifier
	verifierAddr := testVerifierAddr

	// After removal, committee has 2 signers (0xAAA was removed onchain by step-1).
	adapter := &stubFullAdapter{
		states: map[uint64][]*adapters.CommitteeState{
			sel1: {{
				Qualifier:     qualifier,
				ChainSelector: sel1,
				Address:       verifierAddr,
				SignatureConfigs: []adapters.SignatureConfig{
					{SourceChainSelector: sel1, Signers: []string{"0xBBB", "0xCCC"}, Threshold: 2},
				},
			}},
		},
		verifierAddrs: map[uint64]string{sel1: verifierAddr},
	}

	registerFullEVMAdapters(adapter)
	cs := RemoveNOPOffchain()
	env := deployment.Environment{
		Logger:      logger.Test(t),
		BlockChains: newTestBlockChains([]uint64{sel1}),
		DataStore:   datastore.NewMemoryDataStore().Seal(),
	}

	out, err := cs.Apply(env, RemoveNOPOffchainInput{
		CommitteeQualifier:   qualifier,
		SourceChainSelectors: []uint64{sel1},
		ServiceIdentifiers:   []string{"my-aggregator"},
		NOPAlias:             shared.NOPAlias(testNOPAlias),
	})
	require.NoError(t, err)
	require.NotNil(t, out.DataStore)

	cfg, err := ccvdeployment.GetAggregatorConfig(out.DataStore.Seal(), "my-aggregator")
	require.NoError(t, err)
	signers := cfg.QuorumConfigs[fmt.Sprintf("%d", sel1)].Signers
	require.Len(t, signers, 2, "two signers remain after removal")
}

func TestRemoveNOPOffchain_Apply_PublishesObservedCommittee(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	qualifier := testQualifier
	verifierAddr := testVerifierAddr

	adapter := &stubFullAdapter{
		states: map[uint64][]*adapters.CommitteeState{
			sel1: {{
				Qualifier: qualifier, ChainSelector: sel1, Address: verifierAddr,
				SignatureConfigs: []adapters.SignatureConfig{
					{SourceChainSelector: sel1, Signers: []string{"0xBBB", "0xCCC"}, Threshold: 2},
				},
			}},
		},
		verifierAddrs: map[uint64]string{sel1: verifierAddr},
	}
	registerFullEVMAdapters(adapter)
	env := deployment.Environment{
		Logger:      logger.Test(t),
		BlockChains: newTestBlockChains([]uint64{sel1}),
		DataStore:   datastore.NewMemoryDataStore().Seal(),
	}

	out, err := RemoveNOPOffchain().Apply(env, RemoveNOPOffchainInput{
		CommitteeQualifier:   qualifier,
		SourceChainSelectors: []uint64{sel1},
		ServiceIdentifiers:   []string{"my-aggregator"},
		NOPAlias:             shared.NOPAlias(testNOPAlias),
	})
	require.NoError(t, err)

	inv, err := ccvdeployment.GetInventory(out.DataStore.Seal())
	require.NoError(t, err)
	var onchain []inventory.Committee
	for _, c := range inv.Committees {
		if c.Source == inventory.SourceOnchain {
			onchain = append(onchain, c)
		}
	}
	require.Len(t, onchain, 1, "the removal run itself publishes the observed committee")
	assert.Equal(t, uint8(2), onchain[0].Threshold)
	assert.Equal(t, qualifier, onchain[0].Qualifier, "the qualifier is persisted in the same output, not left to legacy fallback")
	assert.Len(t, onchain[0].Members, 2, "the removed signer is gone from the inventory in the same run, not after another scan")

	var aggregatorCommittees int
	for _, c := range inv.Committees {
		if c.Source == inventory.SourceAggregator {
			aggregatorCommittees++
			assert.Equal(t, qualifier, c.Qualifier, "drift and attribution use the saved qualifier")
		}
	}
	assert.Positive(t, aggregatorCommittees)
}

func TestRemoveNOPOffchain_Apply_UsesAllDiscoveredDestChains(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	sel2 := chainsel.TEST_90000002.Selector
	qualifier := testQualifier
	addr1 := testVerifierAddr
	addr2 := "0x2222222222222222222222222222222222222222"

	adapter := &stubFullAdapter{
		states: map[uint64][]*adapters.CommitteeState{
			sel1: {{
				Qualifier:     qualifier,
				ChainSelector: sel1,
				Address:       addr1,
				SignatureConfigs: []adapters.SignatureConfig{
					{SourceChainSelector: sel1, Signers: []string{"0xBBB"}, Threshold: 1},
				},
			}},
			sel2: {{
				Qualifier:     qualifier,
				ChainSelector: sel2,
				Address:       addr2,
				SignatureConfigs: []adapters.SignatureConfig{
					{SourceChainSelector: sel1, Signers: []string{"0xBBB"}, Threshold: 1},
				},
			}},
		},
		verifierAddrs: map[uint64]string{sel1: addr1, sel2: addr2},
	}

	registerFullEVMAdapters(adapter)
	cs := RemoveNOPOffchain()
	env := deployment.Environment{
		Logger:      logger.Test(t),
		BlockChains: newTestBlockChains([]uint64{sel1, sel2}),
		DataStore:   datastore.NewMemoryDataStore().Seal(),
	}

	out, err := cs.Apply(env, RemoveNOPOffchainInput{
		CommitteeQualifier:   qualifier,
		SourceChainSelectors: []uint64{sel1},
		ServiceIdentifiers:   []string{"my-aggregator"},
		NOPAlias:             shared.NOPAlias(testNOPAlias),
	})
	require.NoError(t, err)

	cfg, err := ccvdeployment.GetAggregatorConfig(out.DataStore.Seal(), "my-aggregator")
	require.NoError(t, err)
	assert.Contains(t, cfg.DestinationVerifiers, fmt.Sprintf("%d", sel1))
	assert.Contains(t, cfg.DestinationVerifiers, fmt.Sprintf("%d", sel2))
}

func TestRemoveNOPOffchain_Apply_ScanError(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector

	// states must have the chain key so GetDeployedChains returns it; the scan itself
	// will then fail with the injected error.
	adapter := &stubFullAdapter{
		states:  map[uint64][]*adapters.CommitteeState{sel1: nil},
		scanErr: fmt.Errorf("node unreachable"),
	}
	registerFullEVMAdapters(adapter)
	cs := RemoveNOPOffchain()
	env := deployment.Environment{
		BlockChains: newTestBlockChains([]uint64{sel1}),
	}

	_, err := cs.Apply(env, RemoveNOPOffchainInput{
		CommitteeQualifier:   testQualifier,
		SourceChainSelectors: []uint64{sel1},
		ServiceIdentifiers:   []string{"svc1"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "node unreachable")
}

func TestRemoveNOPOffchain_Apply_MultipleServiceIdentifiers(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	qualifier := testQualifier
	verifierAddr := testVerifierAddr

	adapter := &stubFullAdapter{
		states: map[uint64][]*adapters.CommitteeState{
			sel1: {{
				Qualifier:     qualifier,
				ChainSelector: sel1,
				Address:       verifierAddr,
				SignatureConfigs: []adapters.SignatureConfig{
					{SourceChainSelector: sel1, Signers: []string{"0xBBB"}, Threshold: 1},
				},
			}},
		},
		verifierAddrs: map[uint64]string{sel1: verifierAddr},
	}

	registerFullEVMAdapters(adapter)
	cs := RemoveNOPOffchain()
	env := deployment.Environment{
		Logger:      logger.Test(t),
		BlockChains: newTestBlockChains([]uint64{sel1}),
		DataStore:   datastore.NewMemoryDataStore().Seal(),
	}

	out, err := cs.Apply(env, RemoveNOPOffchainInput{
		CommitteeQualifier:   qualifier,
		SourceChainSelectors: []uint64{sel1},
		ServiceIdentifiers:   []string{"svc-primary", "svc-secondary"},
		NOPAlias:             shared.NOPAlias(testNOPAlias),
	})
	require.NoError(t, err)
	require.NotNil(t, out.DataStore)
}

func TestRemoveNOPOffchainSyncFailureDoesNotRevoke(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	verifierAddr := testVerifierAddr
	adapter := &stubFullAdapter{
		states: map[uint64][]*adapters.CommitteeState{
			sel1: {{
				Qualifier: testQualifier, ChainSelector: sel1, Address: verifierAddr,
				SignatureConfigs: []adapters.SignatureConfig{
					{SourceChainSelector: sel1, Signers: []string{"0xBBB", "0xCCC"}, Threshold: 2},
				},
			}},
		},
		verifierAddrs: map[uint64]string{sel1: verifierAddr},
	}
	registerFullEVMAdapters(adapter)
	env := newTestEnvForApply(t, testNOPAlias, []uint64{sel1})
	verifierSpec := "type = \"ccvcommitteeverifier\"\n"
	ds := datastore.NewMemoryDataStore()
	require.NoError(t, ccvdeployment.SaveJob(ds, shared.JobInfo{
		JobID: "nop1-default-verifier", JDJobID: "jd-remove", NOPAlias: shared.NOPAlias(testNOPAlias),
		NodeID: "node-nop1", Spec: verifierSpec,
		Proposals: map[string]shared.ProposalRevision{
			"stale": {ProposalID: "stale", Revision: 1, Status: shared.JobProposalStatusPending},
		},
	}))
	env.DataStore = ds.Seal()
	client := env.Offchain.(*stubOffchainClient)
	client.proposalErr = errors.New("unavailable")

	_, err := RemoveNOPOffchain().Apply(env, RemoveNOPOffchainInput{
		CommitteeQualifier:   testQualifier,
		SourceChainSelectors: []uint64{sel1},
		ServiceIdentifiers:   []string{"my-aggregator"},
		NOPAlias:             shared.NOPAlias(testNOPAlias),
	})
	require.ErrorContains(t, err, "failed to sync JD before revoking jobs")
	require.Zero(t, client.revokeCalls)
}

func newRemoveNOPRevocationEnv(t *testing.T, revokeErr error) (deployment.Environment, *stubOffchainClient, datastore.MutableDataStore, RemoveNOPOffchainInput) {
	t.Helper()
	sel := chainsel.TEST_90000001.Selector
	verifierAddr := testVerifierAddr
	registerFullEVMAdapters(&stubFullAdapter{
		states: map[uint64][]*adapters.CommitteeState{
			sel: {{
				Qualifier: testQualifier, ChainSelector: sel, Address: verifierAddr,
				SignatureConfigs: []adapters.SignatureConfig{
					{SourceChainSelector: sel, Signers: []string{genSignerA, genSignerB}, Threshold: 2},
				},
			}},
		},
		verifierAddrs: map[uint64]string{sel: verifierAddr},
	})
	env := newTestEnvForApply(t, testNOPAlias, []uint64{sel})
	env.NodeIDs = nil
	verifierSpec := "type = \"ccvcommitteeverifier\"\n"
	ds := datastore.NewMemoryDataStore()
	require.NoError(t, ccvdeployment.SaveJob(ds, shared.JobInfo{
		JobID: "nop1-default-verifier", JDJobID: "jd-remove", NOPAlias: shared.NOPAlias(testNOPAlias),
		NodeID: "node-nop1", Spec: verifierSpec, ActiveProposalID: "p-approved",
		Proposals: map[string]shared.ProposalRevision{
			"p-approved": {ProposalID: "p-approved", Revision: 1, Status: shared.JobProposalStatusApproved},
			"p-canceled": {ProposalID: "p-canceled", Revision: 2, Status: shared.JobProposalStatusRevoked},
		},
	}))
	env.DataStore = ds.Seal()
	client := env.Offchain.(*stubOffchainClient)
	client.revokeErr = revokeErr
	client.proposals = map[string][]*jobv1.Proposal{
		"jd-remove": {
			{Id: "p-approved", JobId: "jd-remove", Revision: 1, Status: jobv1.ProposalStatus_PROPOSAL_STATUS_APPROVED, Spec: verifierSpec},
			{Id: "p-canceled", JobId: "jd-remove", Revision: 2, Status: jobv1.ProposalStatus_PROPOSAL_STATUS_CANCELLED, Spec: verifierSpec},
		},
	}
	return env, client, ds, RemoveNOPOffchainInput{
		CommitteeQualifier: testQualifier, SourceChainSelectors: []uint64{sel},
		ServiceIdentifiers: []string{"my-aggregator"}, NOPAlias: shared.NOPAlias(testNOPAlias),
	}
}

func TestRemoveNOPOffchainRevokesActiveProposalWithNativeRoster(t *testing.T) {
	env, client, _, input := newRemoveNOPRevocationEnv(t, nil)
	out, err := RemoveNOPOffchain().Apply(env, input)
	require.NoError(t, err)
	require.Equal(t, 1, client.revokeCalls)
	_, err = ccvdeployment.GetJob(out.DataStore.Seal(), shared.NOPAlias(testNOPAlias), "nop1-default-verifier")
	require.Error(t, err)
}

func TestRemoveNOPOffchainRevokeErrorPreservesJob(t *testing.T) {
	env, client, ds, _ := newRemoveNOPRevocationEnv(t, errors.New("revoke failed"))
	env.NodeIDs = []string{"node-nop1"}
	err := revokeVerifierJobsForNOP(env, shared.NOPAlias(testNOPAlias), testQualifier, ds)
	require.ErrorContains(t, err, "revoke failed")
	require.Equal(t, 1, client.revokeCalls)
	job, err := ccvdeployment.GetJob(ds.Seal(), shared.NOPAlias(testNOPAlias), "nop1-default-verifier")
	require.NoError(t, err)
	require.Equal(t, "p-approved", job.ActiveProposalID)
}

func TestRemoveNOPOffchainCleansUpNeverProposedJob(t *testing.T) {
	env, client, ds, input := newRemoveNOPRevocationEnv(t, nil)
	job, err := ccvdeployment.GetJob(ds.Seal(), shared.NOPAlias(testNOPAlias), "nop1-default-verifier")
	require.NoError(t, err)
	job.JDJobID = ""
	job.ActiveProposalID = ""
	job.Proposals = nil
	require.NoError(t, ccvdeployment.SaveJob(ds, *job))
	env.DataStore = ds.Seal()

	out, err := RemoveNOPOffchain().Apply(env, input)
	require.NoError(t, err)
	require.Zero(t, client.revokeCalls)
	_, err = ccvdeployment.GetJob(out.DataStore.Seal(), shared.NOPAlias(testNOPAlias), "nop1-default-verifier")
	require.Error(t, err)
}
