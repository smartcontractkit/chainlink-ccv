package changesets

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	cldfevm "github.com/smartcontractkit/chainlink-deployments-framework/chain/evm"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	csav1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/csa"
	jobv1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/job"
	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

// ---- pure helper: buildAddSignerChange ----

func TestBuildAddSignerChange_AppendsSigner(t *testing.T) {
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: []string{"0xAAA", "0xBBB"}, Threshold: 2},
		},
	}
	change, err := buildAddSignerChange(state, "0xCCC", 0)
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
	change, err := buildAddSignerChange(state, "0xBBB", 2)
	require.NoError(t, err)
	assert.Equal(t, uint8(2), change.NewConfigs[0].Threshold)
}

func TestBuildAddSignerChange_KeepsThresholdWhenZero(t *testing.T) {
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: []string{"0xAAA"}, Threshold: 2},
		},
	}
	change, err := buildAddSignerChange(state, "0xBBB", 0)
	require.NoError(t, err)
	assert.Equal(t, uint8(2), change.NewConfigs[0].Threshold)
}

func TestBuildAddSignerChange_ErrorsWhenThresholdExceedsNewSignerCount(t *testing.T) {
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: []string{"0xAAA"}, Threshold: 1},
		},
	}
	_, err := buildAddSignerChange(state, "0xBBB", 3)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid threshold 3 for 2 signers")
}

func TestBuildAddSignerChange_ErrorsIfAlreadyMember(t *testing.T) {
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: []string{"0xAAA", "0xBBB"}, Threshold: 1},
		},
	}
	_, err := buildAddSignerChange(state, "0xAAA", 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already a committee member")
}

func TestBuildAddSignerChange_CaseInsensitiveAlreadyMemberCheck(t *testing.T) {
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: []string{"0xabc"}, Threshold: 1},
		},
	}
	_, err := buildAddSignerChange(state, "0xABC", 0)
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
	change, err := buildAddSignerChange(state, "0xBBB", 0)
	require.NoError(t, err)
	require.Len(t, change.NewConfigs, 2)
	for _, cfg := range change.NewConfigs {
		assert.Contains(t, cfg.Signers, "0xBBB")
		assert.Len(t, cfg.Signers, 2)
	}
}

func TestBuildAddSignerChange_DoesNotMutateOriginalSigners(t *testing.T) {
	original := []string{"0xAAA"}
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: original, Threshold: 1},
		},
	}
	_, err := buildAddSignerChange(state, "0xBBB", 0)
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
		ChainSelectors: []uint64{chainsel.TEST_90000001.Selector},
		NOPAlias:       "nop1",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "committee qualifier is required")
}

func TestAddNOPToCommittee_Validation_MissingChainSelectors(t *testing.T) {
	cs := AddNOPToCommittee(newEVMRegistry(&stubOnchainAdapter{}))
	err := cs.VerifyPreconditions(newTestEnvironmentWithOffchain(), AddNOPToCommitteeInput{
		CommitteeQualifier: "default",
		NOPAlias:           "nop1",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one chain selector is required")
}

func TestAddNOPToCommittee_Validation_MissingNOPAlias(t *testing.T) {
	cs := AddNOPToCommittee(newEVMRegistry(&stubOnchainAdapter{}))
	err := cs.VerifyPreconditions(newTestEnvironmentWithOffchain(), AddNOPToCommitteeInput{
		CommitteeQualifier: "default",
		ChainSelectors:     []uint64{chainsel.TEST_90000001.Selector},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "NOP alias is required")
}

func TestAddNOPToCommittee_Validation_RequiresOffchainClient(t *testing.T) {
	cs := AddNOPToCommittee(newEVMRegistry(&stubOnchainAdapter{}))
	err := cs.VerifyPreconditions(deployment.Environment{}, AddNOPToCommitteeInput{
		CommitteeQualifier: "default",
		ChainSelectors:     []uint64{chainsel.TEST_90000001.Selector},
		NOPAlias:           "nop1",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "offchain client is required")
}

// ---- AddNOPOffchain validation ----

func TestAddNOPOffchain_Validation_MissingQualifier(t *testing.T) {
	cs := AddNOPOffchain(newFullEVMRegistry(&stubFullAdapter{}))
	err := cs.VerifyPreconditions(deployment.Environment{}, AddNOPOffchainInput{
		ChainSelectors:     []uint64{chainsel.TEST_90000001.Selector},
		ServiceIdentifiers: []string{"svc1"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "committee qualifier is required")
}

func TestAddNOPOffchain_Validation_MissingChainSelectors(t *testing.T) {
	cs := AddNOPOffchain(newFullEVMRegistry(&stubFullAdapter{}))
	err := cs.VerifyPreconditions(deployment.Environment{}, AddNOPOffchainInput{
		CommitteeQualifier: "default",
		ServiceIdentifiers: []string{"svc1"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one chain selector is required")
}

func TestAddNOPOffchain_Validation_MissingServiceIdentifiers(t *testing.T) {
	cs := AddNOPOffchain(newFullEVMRegistry(&stubFullAdapter{}))
	err := cs.VerifyPreconditions(deployment.Environment{}, AddNOPOffchainInput{
		CommitteeQualifier: "default",
		ChainSelectors:     []uint64{chainsel.TEST_90000001.Selector},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one service identifier is required")
}

// ---- AddNOPOffchain apply ----

func TestAddNOPOffchain_Apply_WritesAggregatorConfigToDataStore(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	qualifier := "default"
	verifierAddr := "0x1111111111111111111111111111111111111111"

	// sel1 is both source and destination — the simplest self-contained case.
	// buildQuorumConfigs only includes source chains present in chainSelectors.
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

	env := deployment.Environment{
		BlockChains: newTestBlockChains([]uint64{sel1}),
		DataStore:   datastore.NewMemoryDataStore().Seal(),
	}

	out, err := cs.Apply(env, AddNOPOffchainInput{
		CommitteeQualifier: qualifier,
		ChainSelectors:     []uint64{sel1},
		ServiceIdentifiers: []string{"my-aggregator"},
	})
	require.NoError(t, err)
	require.NotNil(t, out.DataStore)

	cfg, err := ccvdeployment.GetAggregatorConfig(out.DataStore.Seal(), "my-aggregator")
	require.NoError(t, err)
	require.Len(t, cfg.QuorumConfigs, 1, "one source chain quorum config expected")
	signers := cfg.QuorumConfigs[fmt.Sprintf("%d", sel1)].Signers
	require.Len(t, signers, 3)
}

func TestAddNOPOffchain_Apply_ScanError(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector

	adapter := &stubFullAdapter{
		scanErr: fmt.Errorf("rpc timeout"),
	}

	cs := AddNOPOffchain(newFullEVMRegistry(adapter))
	env := deployment.Environment{
		BlockChains: newTestBlockChains([]uint64{sel1}),
	}

	_, err := cs.Apply(env, AddNOPOffchainInput{
		CommitteeQualifier: "default",
		ChainSelectors:     []uint64{sel1},
		ServiceIdentifiers: []string{"svc1"},
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
		CommitteeQualifier: "default",
		ChainSelectors:     []uint64{sel1},
		ServiceIdentifiers: []string{"svc1"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `committee "default" not found`)
}

func TestAddNOPOffchain_Apply_PreservesExistingDataStoreEntries(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	qualifier := "default"
	verifierAddr := "0x1111111111111111111111111111111111111111"

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

	ds := datastore.NewMemoryDataStore()
	env := deployment.Environment{
		BlockChains: newTestBlockChains([]uint64{sel1}),
		DataStore:   ds.Seal(),
	}

	out, err := cs.Apply(env, AddNOPOffchainInput{
		CommitteeQualifier: qualifier,
		ChainSelectors:     []uint64{sel1},
		ServiceIdentifiers: []string{"svc-a", "svc-b"},
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

type stubOffchainClient struct {
	jobv1.JobServiceClient
	nodev1.NodeServiceClient
	csav1.CSAServiceClient
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
	verifierAddrs map[uint64]string
	resolveErr    error
}

var _ adapters.AggregatorConfigAdapter = (*stubAggregatorAdapter)(nil)

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

// stubFullAdapter combines both adapter interfaces for offchain-step tests.
type stubFullAdapter struct {
	states        map[uint64][]*adapters.CommitteeState
	scanErr       error
	verifierAddrs map[uint64]string
	resolveErr    error
}

var _ adapters.CommitteeVerifierOnchainAdapter = (*stubFullAdapter)(nil)
var _ adapters.AggregatorConfigAdapter = (*stubFullAdapter)(nil)

func (s *stubFullAdapter) ScanCommitteeStates(_ context.Context, _ deployment.Environment, chainSelector uint64) ([]*adapters.CommitteeState, error) {
	if s.scanErr != nil {
		return nil, s.scanErr
	}
	return s.states[chainSelector], nil
}

func (s *stubFullAdapter) ApplySignatureConfigs(_ context.Context, _ deployment.Environment, _ uint64, _ string, _ adapters.SignatureConfigChange) error {
	return nil
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

func newFullEVMRegistry(a *stubFullAdapter) *adapters.Registry {
	r := adapters.GetRegistry()
	r.Register(chainsel.FamilyEVM, adapters.ChainAdapters{
		CommitteeVerifierOnchain: a,
		Aggregator:               a,
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
