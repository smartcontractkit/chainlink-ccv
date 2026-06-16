package changesets

import (
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

// stubLaneConfigAdapter implements adapters.LaneConfigAdapter for validation
// tests. The sequence body is never executed in the validation path.
type stubLaneConfigAdapter struct{}

var _ adapters.LaneConfigAdapter = (*stubLaneConfigAdapter)(nil)

var stubLaneConfigSequence = operations.NewSequence(
	"stub-configure-lane",
	semver.MustParse("1.0.0"),
	"stub sequence used only by validation tests",
	func(_ operations.Bundle, _ cldf_chain.BlockChains, _ adapters.LaneConfigInput) (adapters.LaneConfigOutput, error) {
		return adapters.LaneConfigOutput{}, nil
	},
)

func (s *stubLaneConfigAdapter) ConfigureLane() *operations.Sequence[adapters.LaneConfigInput, adapters.LaneConfigOutput, cldf_chain.BlockChains] {
	return stubLaneConfigSequence
}

func registerLaneConfigAdapter() {
	adapters.GetLaneConfigRegistry().Register(chainsel.FamilyEVM, &stubLaneConfigAdapter{})
}

func newLaneTestEnv(selectors []uint64) deployment.Environment {
	return deployment.Environment{
		BlockChains: newTestBlockChains(selectors),
		DataStore:   datastore.NewMemoryDataStore().Seal(),
	}
}

func TestLaneExpansion_Validation_MissingSrcChain(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerLaneConfigAdapter()
	cs := LaneExpansion()
	err := cs.VerifyPreconditions(newLaneTestEnv([]uint64{sel}), LaneExpansionInput{
		DestChainSelector: sel,
	})
	require.ErrorContains(t, err, "source chain selector is required")
}

func TestLaneExpansion_Validation_MissingDestChain(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerLaneConfigAdapter()
	cs := LaneExpansion()
	err := cs.VerifyPreconditions(newLaneTestEnv([]uint64{sel}), LaneExpansionInput{
		SrcChainSelector: sel,
	})
	require.ErrorContains(t, err, "destination chain selector is required")
}

func TestLaneExpansion_Validation_SameChain(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerLaneConfigAdapter()
	cs := LaneExpansion()
	err := cs.VerifyPreconditions(newLaneTestEnv([]uint64{sel}), LaneExpansionInput{
		SrcChainSelector:  sel,
		DestChainSelector: sel,
	})
	require.ErrorContains(t, err, "source and destination chain selectors must be different")
}

func TestLaneExpansion_Validation_SrcChainNotInEnv(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	sel2 := chainsel.TEST_90000002.Selector
	registerLaneConfigAdapter()
	cs := LaneExpansion()
	err := cs.VerifyPreconditions(newLaneTestEnv([]uint64{sel2}), LaneExpansionInput{
		SrcChainSelector:  sel1,
		DestChainSelector: sel2,
	})
	require.ErrorContains(t, err, "source chain selector")
	require.ErrorContains(t, err, "is not available in environment")
}

func TestLaneExpansion_Validation_DestChainNotInEnv(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	sel2 := chainsel.TEST_90000002.Selector
	registerLaneConfigAdapter()
	cs := LaneExpansion()
	err := cs.VerifyPreconditions(newLaneTestEnv([]uint64{sel1}), LaneExpansionInput{
		SrcChainSelector:  sel1,
		DestChainSelector: sel2,
	})
	require.ErrorContains(t, err, "destination chain selector")
	require.ErrorContains(t, err, "is not available in environment")
}

func TestLaneExpansion_Validation_HappyPath(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	sel2 := chainsel.TEST_90000002.Selector
	registerLaneConfigAdapter()
	cs := LaneExpansion()
	err := cs.VerifyPreconditions(newLaneTestEnv([]uint64{sel1, sel2}), LaneExpansionInput{
		SrcChainSelector:  sel1,
		DestChainSelector: sel2,
		UseTestRouter:     true,
	})
	require.NoError(t, err)
}

func TestPromoteLaneRouter_Validation_HappyPath(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	sel2 := chainsel.TEST_90000002.Selector
	registerLaneConfigAdapter()
	cs := PromoteLaneRouter()
	err := cs.VerifyPreconditions(newLaneTestEnv([]uint64{sel1, sel2}), PromoteLaneRouterInput{
		SrcChainSelector:  sel1,
		DestChainSelector: sel2,
	})
	require.NoError(t, err)
}

func TestPromoteLaneRouter_Validation_MissingSrcChain(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerLaneConfigAdapter()
	cs := PromoteLaneRouter()
	err := cs.VerifyPreconditions(newLaneTestEnv([]uint64{sel}), PromoteLaneRouterInput{
		DestChainSelector: sel,
	})
	require.ErrorContains(t, err, "source chain selector is required")
}

func TestBuildRemoteLaneConfig_WithOverrides(t *testing.T) {
	allow := true
	gasCost := uint32(100000)
	cfg := buildRemoteLaneConfig("exec-default", []string{"ccv-a"}, []string{"ccv-b"}, &LaneChainOverrides{
		AllowTrafficFrom:     &allow,
		BaseExecutionGasCost: &gasCost,
		FamilyExtras:         map[string]any{"key": "value"},
	})
	require.Equal(t, "exec-default", cfg.ExecutorQualifier)
	require.Equal(t, []string{"ccv-a"}, cfg.InboundCCVQualifiers)
	require.Equal(t, []string{"ccv-b"}, cfg.OutboundCCVQualifiers)
	require.Equal(t, &allow, cfg.AllowTrafficFrom)
	require.Equal(t, &gasCost, cfg.BaseExecutionGasCost)
	require.Equal(t, map[string]any{"key": "value"}, cfg.FamilyExtras)
}

func TestBuildRemoteLaneConfig_NoOverrides(t *testing.T) {
	cfg := buildRemoteLaneConfig("exec-default", nil, nil, nil)
	require.Equal(t, "exec-default", cfg.ExecutorQualifier)
	require.Nil(t, cfg.AllowTrafficFrom)
	require.Nil(t, cfg.BaseExecutionGasCost)
	require.Nil(t, cfg.FamilyExtras)
}
