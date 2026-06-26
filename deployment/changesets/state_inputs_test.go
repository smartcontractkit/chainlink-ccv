package changesets

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	csav1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/csa"
	jobv1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/job"
	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

// registerEVMChainTypeForIdentities mirrors integration/evm/adapters/init.go so the
// state-resolution tests are self-contained (the EVM integration package, which
// normally registers these, is not imported here).
func registerEVMChainTypeForIdentities() {
	shared.RegisterChainTypeFamily(nodev1.ChainType_CHAIN_TYPE_EVM, chainsel.FamilyEVM)
	shared.RegisterAddressNormalizer(chainsel.FamilyEVM, func(addr string) string {
		lower := strings.ToLower(addr)
		if !strings.HasPrefix(lower, "0x") {
			return "0x" + lower
		}
		return lower
	})
}

// stubJDIdentities is a JD client that serves node names (aliases) and per-node
// EVM OCR signing addresses — enough for LoadNOPIdentities.
type stubJDIdentities struct {
	jobv1.JobServiceClient
	nodev1.NodeServiceClient
	csav1.CSAServiceClient

	names   map[string]string // nodeID -> name (alias)
	signers map[string]string // nodeID -> EVM onchain signing address
}

func (s *stubJDIdentities) ListNodes(_ context.Context, in *nodev1.ListNodesRequest, _ ...grpc.CallOption) (*nodev1.ListNodesResponse, error) {
	out := make([]*nodev1.Node, 0, len(s.names))
	for id, name := range s.names {
		if in.Filter != nil && len(in.Filter.Ids) > 0 && !slices.Contains(in.Filter.Ids, id) {
			continue
		}
		out = append(out, &nodev1.Node{Id: id, Name: name})
	}
	return &nodev1.ListNodesResponse{Nodes: out}, nil
}

func (s *stubJDIdentities) ListNodeChainConfigs(_ context.Context, in *nodev1.ListNodeChainConfigsRequest, _ ...grpc.CallOption) (*nodev1.ListNodeChainConfigsResponse, error) {
	var cfgs []*nodev1.ChainConfig
	for id, signer := range s.signers {
		if in.Filter != nil && len(in.Filter.NodeIds) > 0 && !slices.Contains(in.Filter.NodeIds, id) {
			continue
		}
		cfgs = append(cfgs, &nodev1.ChainConfig{
			NodeId: id,
			Chain:  &nodev1.Chain{Type: nodev1.ChainType_CHAIN_TYPE_EVM},
			Ocr2Config: &nodev1.OCR2Config{
				OcrKeyBundle: &nodev1.OCR2Config_OCRKeyBundle{OnchainSigningAddress: signer},
			},
		})
	}
	return &nodev1.ListNodeChainConfigsResponse{ChainConfigs: cfgs}, nil
}

func newIdentitiesEnv(t *testing.T, names, signers map[string]string, selectors []uint64) deployment.Environment {
	t.Helper()
	lggr := logger.Test(t)
	bundle := operations.NewBundle(
		func() context.Context { return context.Background() },
		lggr,
		operations.NewMemoryReporter(),
	)
	nodeIDs := make([]string, 0, len(names))
	for id := range names {
		nodeIDs = append(nodeIDs, id)
	}
	return deployment.Environment{
		Logger:           lggr,
		BlockChains:      newTestBlockChains(selectors),
		DataStore:        datastore.NewMemoryDataStore().Seal(),
		Offchain:         &stubJDIdentities{names: names, signers: signers},
		NodeIDs:          nodeIDs,
		OperationsBundle: bundle,
		GetContext:       func() context.Context { return context.Background() },
	}
}

func TestLoadNOPIdentities_BuildsBothDirections(t *testing.T) {
	registerEVMChainTypeForIdentities()
	env := newIdentitiesEnv(t,
		map[string]string{"node-nop1": "nop1", "node-nop2": "nop2"},
		map[string]string{"node-nop1": "0xAAA1", "node-nop2": "0xBBB2"},
		nil,
	)

	ids, err := LoadNOPIdentities(context.Background(), env)
	require.NoError(t, err)

	// forward: NOPInputs carries the normalized signer per family
	inputs := ids.NOPInputs()
	require.Len(t, inputs, 2)
	assert.Equal(t, shared.NOPAlias("nop1"), inputs[0].Alias)
	assert.Equal(t, "0xaaa1", inputs[0].SignerAddressByFamily[chainsel.FamilyEVM])

	// inverse: signer address (any case) resolves back to its alias
	alias, ok := ids.AliasForSigner(chainsel.FamilyEVM, "0xAAA1")
	require.True(t, ok)
	assert.Equal(t, shared.NOPAlias("nop1"), alias)

	_, ok = ids.AliasForSigner(chainsel.FamilyEVM, "0xUNKNOWN")
	assert.False(t, ok)
}

func TestCommitteeInputFromState_ReconstructsMembership(t *testing.T) {
	registerEVMChainTypeForIdentities()
	sel := chainsel.TEST_90000001.Selector

	adapter := &stubFullAdapter{
		states: map[uint64][]*adapters.CommitteeState{
			sel: {{
				Qualifier:     testQualifier,
				ChainSelector: sel,
				SignatureConfigs: []adapters.SignatureConfig{
					{SourceChainSelector: sel, Signers: []string{"0xAAA1", "0xBBB2"}, Threshold: 2},
				},
			}},
		},
		verifierAddrs: map[uint64]string{sel: testVerifierAddr},
	}
	registerFullEVMAdapters(adapter)

	env := newIdentitiesEnv(t,
		map[string]string{"node-nop1": "nop1", "node-nop2": "nop2"},
		map[string]string{"node-nop1": "0xAAA1", "node-nop2": "0xBBB2"},
		[]uint64{sel},
	)

	ids, err := LoadNOPIdentities(context.Background(), env)
	require.NoError(t, err)

	committee, err := CommitteeInputFromState(context.Background(), env, ids, testQualifier, "")
	require.NoError(t, err)
	assert.Equal(t, testQualifier, committee.Qualifier)
	require.Contains(t, committee.ChainConfigs, sel)
	assert.Equal(t,
		[]shared.NOPAlias{"nop1", "nop2"},
		committee.ChainConfigs[sel].NOPAliases,
	)
}

func TestCommitteeInputFromState_ErrorsOnUnknownSigner(t *testing.T) {
	registerEVMChainTypeForIdentities()
	sel := chainsel.TEST_90000001.Selector

	adapter := &stubFullAdapter{
		states: map[uint64][]*adapters.CommitteeState{
			sel: {{
				Qualifier:     testQualifier,
				ChainSelector: sel,
				SignatureConfigs: []adapters.SignatureConfig{
					{SourceChainSelector: sel, Signers: []string{"0xAAA1", "0xORPHAN"}, Threshold: 1},
				},
			}},
		},
		verifierAddrs: map[uint64]string{sel: testVerifierAddr},
	}
	registerFullEVMAdapters(adapter)

	env := newIdentitiesEnv(t,
		map[string]string{"node-nop1": "nop1"},
		map[string]string{"node-nop1": "0xAAA1"},
		[]uint64{sel},
	)
	ids, err := LoadNOPIdentities(context.Background(), env)
	require.NoError(t, err)

	_, err = CommitteeInputFromState(context.Background(), env, ids, testQualifier, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no JD-known NOP")
}

func TestCommitteeInputFromState_UnionsOnCrossSourceDrift(t *testing.T) {
	registerEVMChainTypeForIdentities()
	sel := chainsel.TEST_90000001.Selector
	src2 := chainsel.TEST_90000002.Selector

	adapter := &stubFullAdapter{
		states: map[uint64][]*adapters.CommitteeState{
			sel: {{
				Qualifier:     testQualifier,
				ChainSelector: sel,
				SignatureConfigs: []adapters.SignatureConfig{
					{SourceChainSelector: sel, Signers: []string{"0xAAA1", "0xBBB2"}, Threshold: 2},
					// nop2 missing on the second source — divergence is unioned (and warned).
					{SourceChainSelector: src2, Signers: []string{"0xAAA1"}, Threshold: 1},
				},
			}},
		},
		verifierAddrs: map[uint64]string{sel: testVerifierAddr},
	}
	registerFullEVMAdapters(adapter)

	env := newIdentitiesEnv(t,
		map[string]string{"node-nop1": "nop1", "node-nop2": "nop2"},
		map[string]string{"node-nop1": "0xAAA1", "node-nop2": "0xBBB2"},
		[]uint64{sel},
	)
	ids, err := LoadNOPIdentities(context.Background(), env)
	require.NoError(t, err)

	committee, err := CommitteeInputFromState(context.Background(), env, ids, testQualifier, "")
	require.NoError(t, err)
	// Union of both source memberships.
	assert.Equal(t, []shared.NOPAlias{"nop1", "nop2"}, committee.ChainConfigs[sel].NOPAliases)
}

func TestCommitteeChainSelectorsFromState(t *testing.T) {
	registerEVMChainTypeForIdentities()
	sel := chainsel.TEST_90000001.Selector

	adapter := &stubFullAdapter{
		states: map[uint64][]*adapters.CommitteeState{
			sel: {{Qualifier: testQualifier, ChainSelector: sel}},
		},
		verifierAddrs: map[uint64]string{sel: testVerifierAddr},
	}
	registerFullEVMAdapters(adapter)

	got, err := CommitteeChainSelectorsFromState(
		datastore.NewMemoryDataStore().Seal(), testQualifier, chainsel.FamilyEVM)
	require.NoError(t, err)
	assert.Equal(t, []uint64{sel}, got)

	// A family with no deployed verifiers yields an empty (non-nil) slice.
	got, err = CommitteeChainSelectorsFromState(
		datastore.NewMemoryDataStore().Seal(), testQualifier, chainsel.FamilySolana)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestApplyVerifierConfigInputFromState_BuildsReadyInput(t *testing.T) {
	registerEVMChainTypeForIdentities()
	sel := chainsel.TEST_90000001.Selector

	adapter := &stubFullAdapter{
		states: map[uint64][]*adapters.CommitteeState{
			sel: {{
				Qualifier:     testQualifier,
				ChainSelector: sel,
				SignatureConfigs: []adapters.SignatureConfig{
					{SourceChainSelector: sel, Signers: []string{"0xAAA1", "0xBBB2"}, Threshold: 2},
				},
			}},
		},
		verifierAddrs: map[uint64]string{sel: testVerifierAddr},
	}
	registerFullEVMAdapters(adapter)

	env := newIdentitiesEnv(t,
		map[string]string{"node-nop1": "nop1", "node-nop2": "nop2"},
		map[string]string{"node-nop1": "0xAAA1", "node-nop2": "0xBBB2"},
		[]uint64{sel},
	)

	in, err := ApplyVerifierConfigInputFromState(context.Background(), env, testQualifier, "", VerifierConfigFromStateOptions{
		Aggregators:              testAggregatorRefs(),
		DefaultExecutorQualifier: "default-executor",
		ModeByNOP:                map[shared.NOPAlias]shared.NOPMode{"nop2": shared.NOPModeStandalone},
	})
	require.NoError(t, err)

	assert.Equal(t, testQualifier, in.CommitteeQualifier)
	assert.Equal(t, "default-executor", in.DefaultExecutorQualifier)
	assert.Equal(t, testAggregatorRefs(), in.Committee.Aggregators)
	require.Contains(t, in.Committee.ChainConfigs, sel)
	assert.Equal(t, []shared.NOPAlias{"nop1", "nop2"}, in.Committee.ChainConfigs[sel].NOPAliases)

	// NOPs restricted to committee membership, mode override applied.
	require.Len(t, in.NOPs, 2)
	modeByAlias := map[shared.NOPAlias]shared.NOPMode{}
	for _, n := range in.NOPs {
		modeByAlias[n.Alias] = n.Mode
	}
	assert.Equal(t, shared.NOPModeCL, modeByAlias["nop1"])
	assert.Equal(t, shared.NOPModeStandalone, modeByAlias["nop2"])
}
