package changesets

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	chainsel "github.com/smartcontractkit/chain-selectors"
	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	cldfevm "github.com/smartcontractkit/chainlink-deployments-framework/chain/evm"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	csav1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/csa"
	jobv1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/job"
	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

const (
	testQualifier    = "default"
	testVerifierAddr = "0x1111111111111111111111111111111111111111"
	testNOPAlias     = "nop1"
	testSignerAddr   = "0xSIGNERADDRESS"
)

// ---- pure helper: buildAddSignerChange ----

func TestBuildAddSignerChange_AppendsSigner(t *testing.T) {
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: []string{"0xAAA", "0xBBB"}, Threshold: 2},
		},
	}
	change, err := buildAddSignerChange(state, "0xCCC", 0, []uint64{1})
	require.NoError(t, err)
	require.Len(t, change.NewConfigs, 1)
	assert.Equal(t, []string{"0xAAA", "0xBBB", "0xCCC"}, change.NewConfigs[0].Signers)
	assert.Equal(t, uint8(2), change.NewConfigs[0].Threshold)
}

func TestBuildAddSignerChange_ReplacesThresholdWhenNonZero(t *testing.T) {
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: []string{"0xAAA"}, Threshold: 1},
		},
	}
	change, err := buildAddSignerChange(state, "0xBBB", 2, []uint64{1})
	require.NoError(t, err)
	assert.Equal(t, uint8(2), change.NewConfigs[0].Threshold)
}

func TestBuildAddSignerChange_KeepsThresholdWhenZero(t *testing.T) {
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: []string{"0xAAA"}, Threshold: 2},
		},
	}
	change, err := buildAddSignerChange(state, "0xBBB", 0, []uint64{1})
	require.NoError(t, err)
	assert.Equal(t, uint8(2), change.NewConfigs[0].Threshold)
}

func TestBuildAddSignerChange_ErrorsWhenThresholdExceedsNewSignerCount(t *testing.T) {
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: []string{"0xAAA"}, Threshold: 1},
		},
	}
	_, err := buildAddSignerChange(state, "0xBBB", 3, []uint64{1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid threshold 3 for 2 signers")
}

func TestBuildAddSignerChange_ErrorsIfAlreadyMember(t *testing.T) {
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: []string{"0xAAA", "0xBBB"}, Threshold: 1},
		},
	}
	_, err := buildAddSignerChange(state, "0xAAA", 0, []uint64{1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already a committee member")
}

func TestBuildAddSignerChange_CaseInsensitiveAlreadyMemberCheck(t *testing.T) {
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: []string{"0xabc"}, Threshold: 1},
		},
	}
	_, err := buildAddSignerChange(state, "0xABC", 0, []uint64{1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already a committee member")
}

func TestBuildAddSignerChange_MultipleSourceChains(t *testing.T) {
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: []string{"0xAAA"}, Threshold: 1},
			{SourceChainSelector: 2, Signers: []string{"0xAAA"}, Threshold: 1},
		},
	}
	change, err := buildAddSignerChange(state, "0xBBB", 0, []uint64{1, 2})
	require.NoError(t, err)
	require.Len(t, change.NewConfigs, 2)
	for _, cfg := range change.NewConfigs {
		assert.Contains(t, cfg.Signers, "0xBBB")
		assert.Len(t, cfg.Signers, 2)
	}
}

func TestBuildAddSignerChange_OnlyUpdatesRequestedSourceChains(t *testing.T) {
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: []string{"0xAAA"}, Threshold: 1},
			{SourceChainSelector: 2, Signers: []string{"0xAAA"}, Threshold: 1},
		},
	}
	// Only request source chain 1 — source chain 2 should not appear in NewConfigs.
	change, err := buildAddSignerChange(state, "0xBBB", 0, []uint64{1})
	require.NoError(t, err)
	require.Len(t, change.NewConfigs, 1)
	assert.Equal(t, uint64(1), change.NewConfigs[0].SourceChainSelector)
}

func TestBuildAddSignerChange_ReturnsEmptyWhenNoSourceChainsMatch(t *testing.T) {
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: []string{"0xAAA"}, Threshold: 1},
		},
	}
	// Source chain 99 is not in the state — result is an empty change (not an error).
	change, err := buildAddSignerChange(state, "0xBBB", 0, []uint64{99})
	require.NoError(t, err)
	assert.Empty(t, change.NewConfigs)
}

func TestBuildAddSignerChange_DoesNotMutateOriginalSigners(t *testing.T) {
	original := []string{"0xAAA"}
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: original, Threshold: 1},
		},
	}
	_, err := buildAddSignerChange(state, "0xBBB", 0, []uint64{1})
	require.NoError(t, err)
	assert.Equal(t, []string{"0xAAA"}, original)
}

// ---- AddNOPToCommittee validation ----

func newEVMRegistry(onchain adapters.CommitteeVerifierOnchainAdapter) *adapters.Registry {
	r := adapters.GetRegistry()
	r.Register(chainsel.FamilyEVM, adapters.ChainAdapters{
		CommitteeVerifierOnchain: onchain,
	})
	return r
}

func newTestEnvironmentWithOffchain() deployment.Environment {
	return deployment.Environment{
		Offchain: &stubOffchainClient{},
	}
}

func TestAddNOPToCommittee_Validation_MissingQualifier(t *testing.T) {
	cs := AddNOPToCommittee(newEVMRegistry(&stubOnchainAdapter{}))
	err := cs.VerifyPreconditions(newTestEnvironmentWithOffchain(), AddNOPToCommitteeInput{
		SourceChainSelectors: []uint64{chainsel.TEST_90000001.Selector},
		NOPAlias:             testNOPAlias,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "committee qualifier is required")
}

func TestAddNOPToCommittee_Validation_MissingSourceChainSelectors(t *testing.T) {
	cs := AddNOPToCommittee(newEVMRegistry(&stubOnchainAdapter{}))
	err := cs.VerifyPreconditions(newTestEnvironmentWithOffchain(), AddNOPToCommitteeInput{
		CommitteeQualifier: testQualifier,
		NOPAlias:           testNOPAlias,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one source chain selector is required")
}

func TestAddNOPToCommittee_Validation_MissingNOPAlias(t *testing.T) {
	cs := AddNOPToCommittee(newEVMRegistry(&stubOnchainAdapter{}))
	err := cs.VerifyPreconditions(newTestEnvironmentWithOffchain(), AddNOPToCommitteeInput{
		CommitteeQualifier:   testQualifier,
		SourceChainSelectors: []uint64{chainsel.TEST_90000001.Selector},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "NOP alias is required")
}

func TestAddNOPToCommittee_Validation_RequiresOffchainClient(t *testing.T) {
	cs := AddNOPToCommittee(newEVMRegistry(&stubOnchainAdapter{}))
	err := cs.VerifyPreconditions(deployment.Environment{}, AddNOPToCommitteeInput{
		CommitteeQualifier:   testQualifier,
		SourceChainSelectors: []uint64{chainsel.TEST_90000001.Selector},
		NOPAlias:             testNOPAlias,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "offchain client is required")
}

// ---- AddNOPOffchain validation ----

func TestAddNOPOffchain_Validation_MissingQualifier(t *testing.T) {
	cs := AddNOPOffchain(newFullEVMRegistry(&stubFullAdapter{}))
	err := cs.VerifyPreconditions(deployment.Environment{}, AddNOPOffchainInput{
		SourceChainSelectors: []uint64{chainsel.TEST_90000001.Selector},
		ServiceIdentifiers:   []string{"svc1"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "committee qualifier is required")
}

func TestAddNOPOffchain_Validation_MissingSourceChainSelectors(t *testing.T) {
	cs := AddNOPOffchain(newFullEVMRegistry(&stubFullAdapter{}))
	err := cs.VerifyPreconditions(deployment.Environment{}, AddNOPOffchainInput{
		CommitteeQualifier: testQualifier,
		ServiceIdentifiers: []string{"svc1"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one source chain selector is required")
}

func TestAddNOPOffchain_Validation_MissingServiceIdentifiers(t *testing.T) {
	cs := AddNOPOffchain(newFullEVMRegistry(&stubFullAdapter{}))
	err := cs.VerifyPreconditions(deployment.Environment{}, AddNOPOffchainInput{
		CommitteeQualifier:   testQualifier,
		SourceChainSelectors: []uint64{chainsel.TEST_90000001.Selector},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one service identifier is required")
}

func TestAddNOPOffchain_Validation_MissingNOPAlias(t *testing.T) {
	cs := AddNOPOffchain(newFullEVMRegistry(&stubFullAdapter{}))
	err := cs.VerifyPreconditions(deployment.Environment{}, AddNOPOffchainInput{
		CommitteeQualifier:   testQualifier,
		SourceChainSelectors: []uint64{chainsel.TEST_90000001.Selector},
		ServiceIdentifiers:   []string{"svc1"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "NOP alias is required for job provisioning")
}

func TestAddNOPOffchain_Validation_MissingAggregators(t *testing.T) {
	cs := AddNOPOffchain(newFullEVMRegistry(&stubFullAdapter{}))
	err := cs.VerifyPreconditions(deployment.Environment{}, AddNOPOffchainInput{
		CommitteeQualifier:   testQualifier,
		SourceChainSelectors: []uint64{chainsel.TEST_90000001.Selector},
		ServiceIdentifiers:   []string{"svc1"},
		NOPAlias:             testNOPAlias,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one aggregator is required for job provisioning")
}

func TestAddNOPOffchain_Validation_MissingExecutorQualifier(t *testing.T) {
	cs := AddNOPOffchain(newFullEVMRegistry(&stubFullAdapter{}))
	err := cs.VerifyPreconditions(deployment.Environment{}, AddNOPOffchainInput{
		CommitteeQualifier:   testQualifier,
		SourceChainSelectors: []uint64{chainsel.TEST_90000001.Selector},
		ServiceIdentifiers:   []string{"svc1"},
		NOPAlias:             testNOPAlias,
		Aggregators:          []AggregatorRef{{Name: "agg", Address: "0xAGG"}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "executor qualifier is required for job provisioning")
}

// ---- AddNOPOffchain backstop validation ----

func TestAddNOPOffchain_Validation_BackstopPassesWhenSignerPresent(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	qualifier := testQualifier
	signer := "0xNEW"

	adapter := &stubFullAdapter{
		states: map[uint64][]*adapters.CommitteeState{
			sel1: {{
				Qualifier:     qualifier,
				ChainSelector: sel1,
				SignatureConfigs: []adapters.SignatureConfig{
					{SourceChainSelector: sel1, Signers: []string{"0xAAA", signer}, Threshold: 1},
				},
			}},
		},
		verifierAddrs: map[uint64]string{sel1: "0x1111"},
	}

	cs := AddNOPOffchain(newFullEVMRegistry(adapter))
	env := deployment.Environment{
		BlockChains: newTestBlockChains([]uint64{sel1}),
		DataStore:   datastore.NewMemoryDataStore().Seal(),
		GetContext:  func() context.Context { return context.Background() },
	}

	err := cs.VerifyPreconditions(env, AddNOPOffchainInput{
		CommitteeQualifier:    qualifier,
		SourceChainSelectors:  []uint64{sel1},
		ExpectedSignerAddress: signer,
		ServiceIdentifiers:    []string{"svc1"},
		NOPAlias:              testNOPAlias,
		Aggregators:           []AggregatorRef{{Name: "agg", Address: "0xAGG"}},
		ExecutorQualifier:     "default-executor",
	})
	require.NoError(t, err)
}

func TestAddNOPOffchain_Validation_BackstopFailsWhenSignerAbsent(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	qualifier := testQualifier

	adapter := &stubFullAdapter{
		states: map[uint64][]*adapters.CommitteeState{
			sel1: {{
				Qualifier:     qualifier,
				ChainSelector: sel1,
				SignatureConfigs: []adapters.SignatureConfig{
					// new signer NOT present — step-1 has not landed
					{SourceChainSelector: sel1, Signers: []string{"0xAAA"}, Threshold: 1},
				},
			}},
		},
		verifierAddrs: map[uint64]string{sel1: "0x1111"},
	}

	cs := AddNOPOffchain(newFullEVMRegistry(adapter))
	env := deployment.Environment{
		BlockChains: newTestBlockChains([]uint64{sel1}),
		DataStore:   datastore.NewMemoryDataStore().Seal(),
		GetContext:  func() context.Context { return context.Background() },
	}

	err := cs.VerifyPreconditions(env, AddNOPOffchainInput{
		CommitteeQualifier:    qualifier,
		SourceChainSelectors:  []uint64{sel1},
		ExpectedSignerAddress: "0xNEW",
		ServiceIdentifiers:    []string{"svc1"},
		NOPAlias:              testNOPAlias,
		Aggregators:           []AggregatorRef{{Name: "agg", Address: "0xAGG"}},
		ExecutorQualifier:     "default-executor",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "step-1 (AddNOPToCommittee) may not have been applied")
}

func TestAddNOPOffchain_Validation_BackstopSkippedWhenAddressEmpty(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	adapter := &stubFullAdapter{
		states:        map[uint64][]*adapters.CommitteeState{sel1: {}},
		verifierAddrs: map[uint64]string{sel1: "0x1111"},
	}
	cs := AddNOPOffchain(newFullEVMRegistry(adapter))
	env := deployment.Environment{
		BlockChains: newTestBlockChains([]uint64{sel1}),
		DataStore:   datastore.NewMemoryDataStore().Seal(),
	}

	// No ExpectedSignerAddress → backstop skipped. All required fields are provided
	// so validation completes without error.
	err := cs.VerifyPreconditions(env, AddNOPOffchainInput{
		CommitteeQualifier:   testQualifier,
		SourceChainSelectors: []uint64{sel1},
		ServiceIdentifiers:   []string{"svc1"},
		NOPAlias:             testNOPAlias,
		Aggregators:          []AggregatorRef{{Name: "agg", Address: "0xAGG"}},
		ExecutorQualifier:    "default-executor",
	})
	require.NoError(t, err)
}

// ---- AddNOPOffchain apply ----

func TestAddNOPOffchain_Apply_WritesAggregatorConfigToDataStore(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	qualifier := testQualifier
	verifierAddr := testVerifierAddr
	nopAlias := testNOPAlias
	signerAddr := testSignerAddr

	adapter := &stubFullAdapter{
		states: map[uint64][]*adapters.CommitteeState{
			sel1: {{
				Qualifier:     qualifier,
				ChainSelector: sel1,
				Address:       verifierAddr,
				SignatureConfigs: []adapters.SignatureConfig{
					{SourceChainSelector: sel1, Signers: []string{"0xAAA", "0xBBB", "0xCCC"}, Threshold: 2},
				},
			}},
		},
		verifierAddrs: map[uint64]string{sel1: verifierAddr},
	}

	r := newFullEVMRegistry(adapter)
	cs := AddNOPOffchain(r)

	env := newTestEnvForApply(t, nopAlias, []uint64{sel1})

	out, err := cs.Apply(env, AddNOPOffchainInput{
		CommitteeQualifier:    qualifier,
		SourceChainSelectors:  []uint64{sel1},
		ServiceIdentifiers:    []string{"my-aggregator"},
		NOPAlias:              shared.NOPAlias(nopAlias),
		Aggregators:           testAggregatorRefs(),
		ExecutorQualifier:     "default-executor",
		ExpectedSignerAddress: signerAddr,
	})
	require.NoError(t, err)
	require.NotNil(t, out.DataStore)

	cfg, err := ccvdeployment.GetAggregatorConfig(out.DataStore.Seal(), "my-aggregator")
	require.NoError(t, err)
	require.Len(t, cfg.QuorumConfigs, 1, "one source chain quorum config expected")
	signers := cfg.QuorumConfigs[fmt.Sprintf("%d", sel1)].Signers
	require.Len(t, signers, 3)
}

func TestAddNOPOffchain_Apply_UsesAllDiscoveredDestChains(t *testing.T) {
	// Two dest chains — both must appear in the aggregator config even though the input only
	// names source chain sel1. The fix for the partial-config truncation bug.
	sel1 := chainsel.TEST_90000001.Selector
	sel2 := chainsel.TEST_90000002.Selector
	qualifier := testQualifier
	addr1 := testVerifierAddr
	addr2 := "0x2222222222222222222222222222222222222222"
	nopAlias := testNOPAlias
	signerAddr := testSignerAddr

	adapter := &stubFullAdapter{
		states: map[uint64][]*adapters.CommitteeState{
			sel1: {{
				Qualifier:     qualifier,
				ChainSelector: sel1,
				Address:       addr1,
				SignatureConfigs: []adapters.SignatureConfig{
					{SourceChainSelector: sel1, Signers: []string{"0xAAA", "0xBBB"}, Threshold: 2},
				},
			}},
			sel2: {{
				Qualifier:     qualifier,
				ChainSelector: sel2,
				Address:       addr2,
				SignatureConfigs: []adapters.SignatureConfig{
					{SourceChainSelector: sel1, Signers: []string{"0xAAA", "0xBBB"}, Threshold: 2},
				},
			}},
		},
		verifierAddrs: map[uint64]string{sel1: addr1, sel2: addr2},
	}

	r := newFullEVMRegistry(adapter)
	cs := AddNOPOffchain(r)

	env := newTestEnvForApply(t, nopAlias, []uint64{sel1, sel2})

	out, err := cs.Apply(env, AddNOPOffchainInput{
		CommitteeQualifier:    qualifier,
		SourceChainSelectors:  []uint64{sel1},
		ServiceIdentifiers:    []string{"my-aggregator"},
		NOPAlias:              shared.NOPAlias(nopAlias),
		Aggregators:           testAggregatorRefs(),
		ExecutorQualifier:     "default-executor",
		ExpectedSignerAddress: signerAddr,
	})
	require.NoError(t, err)

	cfg, err := ccvdeployment.GetAggregatorConfig(out.DataStore.Seal(), "my-aggregator")
	require.NoError(t, err)
	// Both dest chains must appear as destination verifiers.
	assert.Contains(t, cfg.DestinationVerifiers, fmt.Sprintf("%d", sel1))
	assert.Contains(t, cfg.DestinationVerifiers, fmt.Sprintf("%d", sel2))
}

func TestAddNOPOffchain_Apply_ScanError(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector

	// states must have the chain key so GetDeployedChains returns it; the scan itself
	// will then fail with the injected error.
	adapter := &stubFullAdapter{
		states:  map[uint64][]*adapters.CommitteeState{sel1: nil},
		scanErr: fmt.Errorf("rpc timeout"),
	}

	cs := AddNOPOffchain(newFullEVMRegistry(adapter))
	env := deployment.Environment{
		BlockChains: newTestBlockChains([]uint64{sel1}),
	}

	_, err := cs.Apply(env, AddNOPOffchainInput{
		CommitteeQualifier:   testQualifier,
		SourceChainSelectors: []uint64{sel1},
		ServiceIdentifiers:   []string{"svc1"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rpc timeout")
}

func TestAddNOPOffchain_Apply_CommitteeNotFound(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector

	adapter := &stubFullAdapter{
		states: map[uint64][]*adapters.CommitteeState{
			sel1: {}, // no committees
		},
	}

	cs := AddNOPOffchain(newFullEVMRegistry(adapter))
	env := deployment.Environment{
		BlockChains: newTestBlockChains([]uint64{sel1}),
	}

	_, err := cs.Apply(env, AddNOPOffchainInput{
		CommitteeQualifier:   testQualifier,
		SourceChainSelectors: []uint64{sel1},
		ServiceIdentifiers:   []string{"svc1"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `committee "default" not found`)
}

func TestAddNOPOffchain_Apply_PreservesExistingDataStoreEntries(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	qualifier := testQualifier
	verifierAddr := testVerifierAddr
	nopAlias := testNOPAlias
	signerAddr := testSignerAddr

	adapter := &stubFullAdapter{
		states: map[uint64][]*adapters.CommitteeState{
			sel1: {{
				Qualifier:     qualifier,
				ChainSelector: sel1,
				Address:       verifierAddr,
				SignatureConfigs: []adapters.SignatureConfig{
					{SourceChainSelector: sel1, Signers: []string{"0xAAA"}, Threshold: 1},
				},
			}},
		},
		verifierAddrs: map[uint64]string{sel1: verifierAddr},
	}

	r := newFullEVMRegistry(adapter)
	cs := AddNOPOffchain(r)

	env := newTestEnvForApply(t, nopAlias, []uint64{sel1})

	out, err := cs.Apply(env, AddNOPOffchainInput{
		CommitteeQualifier:    qualifier,
		SourceChainSelectors:  []uint64{sel1},
		ServiceIdentifiers:    []string{"svc-a", "svc-b"},
		NOPAlias:              shared.NOPAlias(nopAlias),
		Aggregators:           testAggregatorRefs(),
		ExecutorQualifier:     "default-executor",
		ExpectedSignerAddress: signerAddr,
	})
	require.NoError(t, err)
	require.NotNil(t, out.DataStore)

	sealed := out.DataStore.Seal()
	_, err = ccvdeployment.GetAggregatorConfig(sealed, "svc-a")
	require.NoError(t, err)
	_, err = ccvdeployment.GetAggregatorConfig(sealed, "svc-b")
	require.NoError(t, err)
}

// ---- shared stubs ----

// stubOnchainAdapter satisfies CommitteeVerifierOnchainAdapter.
type stubOnchainAdapter struct {
	states   map[uint64][]*adapters.CommitteeState
	scanErr  error
	applyErr error
	applied  []adapters.SignatureConfigChange
}

// stubOffchainClient satisfies offchain.Client. Only the JDClient methods needed by our test
// flow (ListNodes, ProposeJob) are implemented; all others are left as nil embeddings and
// will panic if unexpectedly called.
type stubOffchainClient struct {
	jobv1.JobServiceClient
	nodev1.NodeServiceClient
	csav1.CSAServiceClient

	// nodes maps nodeID → node name (NOP alias). Used by ListNodes and ProposeJob stubs.
	nodes map[string]string
}

func (s *stubOffchainClient) ListNodes(_ context.Context, in *nodev1.ListNodesRequest, _ ...grpc.CallOption) (*nodev1.ListNodesResponse, error) {
	result := make([]*nodev1.Node, 0, len(s.nodes))
	for id, name := range s.nodes {
		if in.Filter != nil && len(in.Filter.Ids) > 0 {
			found := slices.Contains(in.Filter.Ids, id)
			if !found {
				continue
			}
		}
		result = append(result, &nodev1.Node{Id: id, Name: name})
	}
	return &nodev1.ListNodesResponse{Nodes: result}, nil
}

func (s *stubOffchainClient) ProposeJob(_ context.Context, _ *jobv1.ProposeJobRequest, _ ...grpc.CallOption) (*jobv1.ProposeJobResponse, error) {
	return &jobv1.ProposeJobResponse{
		Proposal: &jobv1.Proposal{Id: "fake-proposal-id", JobId: "fake-jd-job-id"},
	}, nil
}

var _ adapters.CommitteeVerifierOnchainAdapter = (*stubOnchainAdapter)(nil)

func (s *stubOnchainAdapter) ScanCommitteeStates(_ context.Context, _ deployment.Environment, chainSelector uint64) ([]*adapters.CommitteeState, error) {
	if s.scanErr != nil {
		return nil, s.scanErr
	}
	return s.states[chainSelector], nil
}

func (s *stubOnchainAdapter) ApplySignatureConfigs(_ context.Context, _ deployment.Environment, _ uint64, _ string, change adapters.SignatureConfigChange) error {
	if s.applyErr != nil {
		return s.applyErr
	}
	s.applied = append(s.applied, change)
	return nil
}

// stubAggregatorAdapter satisfies AggregatorConfigAdapter.
type stubAggregatorAdapter struct {
	deployedChains []uint64
	verifierAddrs  map[uint64]string
	resolveErr     error
}

var _ adapters.AggregatorConfigAdapter = (*stubAggregatorAdapter)(nil)

func (s *stubAggregatorAdapter) GetDeployedChains(_ datastore.DataStore, _ string) []uint64 {
	return s.deployedChains
}

func (s *stubAggregatorAdapter) ResolveVerifierAddress(_ datastore.DataStore, chainSelector uint64, _ string) (string, error) {
	if s.resolveErr != nil {
		return "", s.resolveErr
	}
	addr, ok := s.verifierAddrs[chainSelector]
	if !ok {
		return "", fmt.Errorf("no verifier address for chain %d", chainSelector)
	}
	return addr, nil
}

// stubFullAdapter combines CommitteeVerifierOnchainAdapter, AggregatorConfigAdapter,
// and VerifierConfigAdapter for offchain-step tests.
// GetDeployedChains returns the keys of the states map, mirroring how a real EVM
// adapter discovers dest chains from the datastore.
type stubFullAdapter struct {
	states        map[uint64][]*adapters.CommitteeState
	scanErr       error
	verifierAddrs map[uint64]string
	resolveErr    error
}

var (
	_ adapters.CommitteeVerifierOnchainAdapter = (*stubFullAdapter)(nil)
	_ adapters.AggregatorConfigAdapter         = (*stubFullAdapter)(nil)
	_ adapters.VerifierConfigAdapter           = (*stubFullAdapter)(nil)
)

func (s *stubFullAdapter) ScanCommitteeStates(_ context.Context, _ deployment.Environment, chainSelector uint64) ([]*adapters.CommitteeState, error) {
	if s.scanErr != nil {
		return nil, s.scanErr
	}
	return s.states[chainSelector], nil
}

func (s *stubFullAdapter) ApplySignatureConfigs(_ context.Context, _ deployment.Environment, _ uint64, _ string, _ adapters.SignatureConfigChange) error {
	return nil
}

func (s *stubFullAdapter) GetDeployedChains(_ datastore.DataStore, _ string) []uint64 {
	chains := make([]uint64, 0, len(s.states))
	for sel := range s.states {
		chains = append(chains, sel)
	}
	return chains
}

func (s *stubFullAdapter) ResolveVerifierAddress(_ datastore.DataStore, chainSelector uint64, _ string) (string, error) {
	if s.resolveErr != nil {
		return "", s.resolveErr
	}
	addr, ok := s.verifierAddrs[chainSelector]
	if !ok {
		return "", fmt.Errorf("no verifier address for chain %d", chainSelector)
	}
	return addr, nil
}

func (s *stubFullAdapter) ResolveVerifierContractAddresses(_ datastore.DataStore, chainSelector uint64, _, _ string) (*adapters.VerifierContractAddresses, error) {
	addr := s.verifierAddrs[chainSelector]
	return &adapters.VerifierContractAddresses{
		CommitteeVerifierAddress: addr,
		OnRampAddress:            "0x000000000000000000000000000000000000AAAA",
		ExecutorProxyAddress:     "0x000000000000000000000000000000000000BBBB",
		RMNRemoteAddress:         "0x000000000000000000000000000000000000CCCC",
	}, nil
}

func (s *stubFullAdapter) GetSignerAddressFamily() string {
	return chainsel.FamilyEVM
}

func newFullEVMRegistry(a *stubFullAdapter) *adapters.Registry {
	r := adapters.GetRegistry()
	r.Register(chainsel.FamilyEVM, adapters.ChainAdapters{
		CommitteeVerifierOnchain: a,
		Aggregator:               a,
		Verifier:                 a,
	})
	return r
}

func newTestBlockChains(selectors []uint64) cldf_chain.BlockChains {
	chains := make(map[uint64]cldf_chain.BlockChain, len(selectors))
	for _, sel := range selectors {
		chains[sel] = cldfevm.Chain{Selector: sel}
	}
	return cldf_chain.NewBlockChains(chains)
}

// newTestEnvForApply builds a deployment.Environment with all the infrastructure needed for
// changeset apply functions that invoke ManageJobProposals (Logger, OperationsBundle, Offchain,
// NodeIDs).
func newTestEnvForApply(t *testing.T, nopAlias string, chainSelectors []uint64) deployment.Environment {
	t.Helper()
	nodeID := "node-" + nopAlias
	lggr := logger.Test(t)
	bundle := operations.NewBundle(
		func() context.Context { return context.Background() },
		lggr,
		operations.NewMemoryReporter(),
	)
	return deployment.Environment{
		Logger:           lggr,
		BlockChains:      newTestBlockChains(chainSelectors),
		DataStore:        datastore.NewMemoryDataStore().Seal(),
		Offchain:         &stubOffchainClient{nodes: map[string]string{nodeID: nopAlias}},
		NodeIDs:          []string{nodeID},
		OperationsBundle: bundle,
	}
}

// testAggregatorRefs returns a minimal AggregatorRef slice for tests that exercise the
// job provisioning path but don't care about the specific aggregator values.
func testAggregatorRefs() []AggregatorRef {
	return []AggregatorRef{{
		Name:    "test-aggregator",
		Address: "0xAGGAGGAGGAGGAGGAGGAGGAGGAGGAGGAGGAGGAGG",
	}}
}
