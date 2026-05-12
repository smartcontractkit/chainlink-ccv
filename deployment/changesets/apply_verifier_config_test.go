package changesets

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

func TestApplyVerifierConfig_Validation_RequiresCommitteeQualifier(t *testing.T) {
	cs := ApplyVerifierConfig(newEVMRegistry(&stubOnchainAdapter{}))
	err := cs.VerifyPreconditions(deployment.Environment{}, ApplyVerifierConfigInput{
		DefaultExecutorQualifier: "default-executor",
		NOPs:                     []NOPInput{{Alias: "nop1"}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "committee qualifier is required")
}

func TestApplyVerifierConfig_Validation_RequiresExecutorQualifier(t *testing.T) {
	cs := ApplyVerifierConfig(newEVMRegistry(&stubOnchainAdapter{}))
	err := cs.VerifyPreconditions(deployment.Environment{}, ApplyVerifierConfigInput{
		CommitteeQualifier: "default",
		NOPs:               []NOPInput{{Alias: "nop1"}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "default executor qualifier is required")
}

func TestApplyVerifierConfig_Validation_RequiresNOPs(t *testing.T) {
	cs := ApplyVerifierConfig(newEVMRegistry(&stubOnchainAdapter{}))
	err := cs.VerifyPreconditions(deployment.Environment{}, ApplyVerifierConfigInput{
		CommitteeQualifier:       "default",
		DefaultExecutorQualifier: "default-executor",
		Committee:                CommitteeInput{Aggregators: []AggregatorRef{{Name: "agg", Address: "0xAGG"}}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one NOP is required")
}

func TestApplyVerifierConfig_Validation_RequiresAggregator(t *testing.T) {
	cs := ApplyVerifierConfig(newEVMRegistry(&stubOnchainAdapter{}))
	err := cs.VerifyPreconditions(deployment.Environment{}, ApplyVerifierConfigInput{
		CommitteeQualifier:       "default",
		DefaultExecutorQualifier: "default-executor",
		NOPs:                     []NOPInput{{Alias: "nop1"}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one aggregator is required")
}

func TestApplyVerifierConfig_Validation_DuplicateNOPAliasRejected(t *testing.T) {
	cs := ApplyVerifierConfig(newEVMRegistry(&stubOnchainAdapter{}))
	err := cs.VerifyPreconditions(deployment.Environment{}, ApplyVerifierConfigInput{
		CommitteeQualifier:       "default",
		DefaultExecutorQualifier: "default-executor",
		NOPs:                     []NOPInput{{Alias: "nop1"}, {Alias: "nop1"}},
		Committee:                CommitteeInput{Aggregators: []AggregatorRef{{Name: "agg", Address: "0xAGG"}}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `duplicate NOP alias "nop1"`)
}

func TestApplyVerifierConfig_Validation_QualifierMismatchRejected(t *testing.T) {
	cs := ApplyVerifierConfig(newEVMRegistry(&stubOnchainAdapter{}))
	err := cs.VerifyPreconditions(deployment.Environment{}, ApplyVerifierConfigInput{
		CommitteeQualifier:       "primary",
		DefaultExecutorQualifier: "default-executor",
		NOPs:                     []NOPInput{{Alias: "nop1"}},
		Committee: CommitteeInput{
			Qualifier:   "secondary",
			Aggregators: []AggregatorRef{{Name: "agg", Address: "0xAGG"}},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "committee qualifier mismatch")
}

func TestApplyVerifierConfig_Validation_TargetNOPMustExist(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	cs := ApplyVerifierConfig(newEVMRegistry(&stubOnchainAdapter{}))
	err := cs.VerifyPreconditions(deployment.Environment{}, ApplyVerifierConfigInput{
		CommitteeQualifier:       "default",
		DefaultExecutorQualifier: "default-executor",
		NOPs:                     []NOPInput{{Alias: "nop1"}},
		Committee: CommitteeInput{
			Aggregators: []AggregatorRef{{Name: "agg", Address: "0xAGG"}},
			ChainConfigs: map[uint64]CommitteeChainMembership{
				sel1: {NOPAliases: []shared.NOPAlias{"nop1"}},
			},
		},
		TargetNOPs: []shared.NOPAlias{"nopX"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `NOP alias "nopX" not found`)
}

func TestApplyVerifierConfig_Validation_ChainReferencesUnknownNOPRejected(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	cs := ApplyVerifierConfig(newEVMRegistry(&stubOnchainAdapter{}))
	err := cs.VerifyPreconditions(deployment.Environment{}, ApplyVerifierConfigInput{
		CommitteeQualifier:       "default",
		DefaultExecutorQualifier: "default-executor",
		NOPs:                     []NOPInput{{Alias: "nop1"}},
		Committee: CommitteeInput{
			Aggregators: []AggregatorRef{{Name: "agg", Address: "0xAGG"}},
			ChainConfigs: map[uint64]CommitteeChainMembership{
				sel1: {NOPAliases: []shared.NOPAlias{"nopGhost"}},
			},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown NOP alias "nopGhost"`)
}

func TestApplyVerifierConfig_Validation_ProductionRejectsPyroscope(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	cs := ApplyVerifierConfig(newEVMRegistry(&stubOnchainAdapter{}))
	err := cs.VerifyPreconditions(deployment.Environment{Name: "mainnet"}, ApplyVerifierConfigInput{
		CommitteeQualifier:       "default",
		DefaultExecutorQualifier: "default-executor",
		NOPs:                     []NOPInput{{Alias: "nop1"}},
		Committee: CommitteeInput{
			Aggregators: []AggregatorRef{{Name: "agg", Address: "0xAGG"}},
			ChainConfigs: map[uint64]CommitteeChainMembership{
				sel1: {NOPAliases: []shared.NOPAlias{"nop1"}},
			},
		},
		PyroscopeURL: "http://pyroscope.example",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pyroscope URL is not supported for production")
}

func TestApplyVerifierConfig_Validation_AcceptsValidImperativeInput(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	cs := ApplyVerifierConfig(newEVMRegistry(&stubOnchainAdapter{}))
	err := cs.VerifyPreconditions(deployment.Environment{}, ApplyVerifierConfigInput{
		CommitteeQualifier:       "default",
		DefaultExecutorQualifier: "default-executor",
		NOPs: []NOPInput{
			{Alias: "nop1", Mode: shared.NOPModeCL, SignerAddressByFamily: map[string]string{chainsel.FamilyEVM: "0xAAA"}},
			{Alias: "nop2", Mode: shared.NOPModeCL, SignerAddressByFamily: map[string]string{chainsel.FamilyEVM: "0xBBB"}},
		},
		Committee: CommitteeInput{
			Qualifier:   "default",
			Aggregators: []AggregatorRef{{Name: "agg", Address: "0xAGG"}},
			ChainConfigs: map[uint64]CommitteeChainMembership{
				sel1: {NOPAliases: []shared.NOPAlias{"nop1", "nop2"}},
			},
		},
	})
	require.NoError(t, err)
}

// ---- pure helpers ----

func TestCommitteeNOPAliasesFromInput_FallsBackToFlatNOPsWhenChainConfigsEmpty(t *testing.T) {
	got := committeeNOPAliasesFromInput(
		CommitteeInput{},
		[]NOPInput{{Alias: "nop2"}, {Alias: "nop1"}},
	)
	assert.Equal(t, []shared.NOPAlias{"nop1", "nop2"}, got)
}

func TestCommitteeNOPAliasesFromInput_UsesUnionOfChainConfigs(t *testing.T) {
	got := committeeNOPAliasesFromInput(
		CommitteeInput{
			ChainConfigs: map[uint64]CommitteeChainMembership{
				1: {NOPAliases: []shared.NOPAlias{"nop1", "nop2"}},
				2: {NOPAliases: []shared.NOPAlias{"nop2", "nop3"}},
			},
		},
		[]NOPInput{{Alias: "nop1"}, {Alias: "nop2"}, {Alias: "nop3"}, {Alias: "nopUnused"}},
	)
	assert.Equal(t, []shared.NOPAlias{"nop1", "nop2", "nop3"}, got)
}

func TestCommitteeChainSelectorsFromInput_SortsSelectors(t *testing.T) {
	got, err := committeeChainSelectorsFromInput(CommitteeInput{
		ChainConfigs: map[uint64]CommitteeChainMembership{
			3: {}, 1: {}, 2: {},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []uint64{1, 2, 3}, got)
}

func TestGetRequiredChainsForVerifierNOP_ReturnsParticipatingChainsSorted(t *testing.T) {
	got := getRequiredChainsForVerifierNOP("nop1", CommitteeInput{
		ChainConfigs: map[uint64]CommitteeChainMembership{
			3: {NOPAliases: []shared.NOPAlias{"nop1"}},
			1: {NOPAliases: []shared.NOPAlias{"nop1", "nop2"}},
			2: {NOPAliases: []shared.NOPAlias{"nop2"}},
		},
	})
	assert.Equal(t, []uint64{1, 3}, got)
}
