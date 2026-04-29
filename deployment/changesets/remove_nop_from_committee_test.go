package changesets

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

// ---- pure helper: buildRemoveSignerChange ----

func TestBuildRemoveSignerChange_RemovesSigner(t *testing.T) {
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: []string{"0xAAA", "0xBBB", "0xCCC"}, Threshold: 2},
		},
	}
	change, err := buildRemoveSignerChange(state, "0xBBB", 0)
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
	change, err := buildRemoveSignerChange(state, "0xCCC", 2)
	require.NoError(t, err)
	assert.Equal(t, uint8(2), change.NewConfigs[0].Threshold)
}

func TestBuildRemoveSignerChange_KeepsThresholdWhenZero(t *testing.T) {
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: []string{"0xAAA", "0xBBB"}, Threshold: 1},
		},
	}
	change, err := buildRemoveSignerChange(state, "0xBBB", 0)
	require.NoError(t, err)
	assert.Equal(t, uint8(1), change.NewConfigs[0].Threshold)
}

func TestBuildRemoveSignerChange_ErrorsIfSignerNotFound(t *testing.T) {
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: []string{"0xAAA", "0xBBB"}, Threshold: 1},
		},
	}
	_, err := buildRemoveSignerChange(state, "0xCCC", 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found in committee")
}

func TestBuildRemoveSignerChange_CaseInsensitiveMatch(t *testing.T) {
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: []string{"0xabc", "0xDEF"}, Threshold: 1},
		},
	}
	change, err := buildRemoveSignerChange(state, "0xABC", 0)
	require.NoError(t, err)
	assert.Equal(t, []string{"0xDEF"}, change.NewConfigs[0].Signers)
}

func TestBuildRemoveSignerChange_ErrorsOnLastSigner(t *testing.T) {
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: []string{"0xAAA"}, Threshold: 1},
		},
	}
	_, err := buildRemoveSignerChange(state, "0xAAA", 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot remove the last signer")
}

func TestBuildRemoveSignerChange_ErrorsWhenThresholdExceedsRemaining(t *testing.T) {
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: []string{"0xAAA", "0xBBB", "0xCCC"}, Threshold: 2},
		},
	}
	// Removing one signer leaves 2. Requesting threshold of 3 is invalid.
	_, err := buildRemoveSignerChange(state, "0xCCC", 3)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "threshold 3 exceeds remaining signer count 2")
}

func TestBuildRemoveSignerChange_CurrentThresholdExceedsRemainingIsAlsoCaught(t *testing.T) {
	// Threshold of 2 was set before removal; only 1 signer remains after.
	// Keeping existing threshold (newThreshold=0) should also error.
	state := &adapters.CommitteeState{
		SignatureConfigs: []adapters.SignatureConfig{
			{SourceChainSelector: 1, Signers: []string{"0xAAA", "0xBBB"}, Threshold: 2},
		},
	}
	_, err := buildRemoveSignerChange(state, "0xBBB", 0)
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
	change, err := buildRemoveSignerChange(state, "0xAAA", 0)
	require.NoError(t, err)
	require.Len(t, change.NewConfigs, 2)
	for _, cfg := range change.NewConfigs {
		assert.Equal(t, []string{"0xBBB"}, cfg.Signers)
	}
}

// ---- RemoveNOPFromCommittee validation ----

func TestRemoveNOPFromCommittee_Validation_MissingQualifier(t *testing.T) {
	cs := RemoveNOPFromCommittee(newEVMRegistry(&stubOnchainAdapter{}))
	err := cs.VerifyPreconditions(newTestEnvironmentWithOffchain(), RemoveNOPFromCommitteeInput{
		ChainSelectors: []uint64{chainsel.TEST_90000001.Selector},
		NOPAlias:       "nop1",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "committee qualifier is required")
}

func TestRemoveNOPFromCommittee_Validation_MissingChainSelectors(t *testing.T) {
	cs := RemoveNOPFromCommittee(newEVMRegistry(&stubOnchainAdapter{}))
	err := cs.VerifyPreconditions(newTestEnvironmentWithOffchain(), RemoveNOPFromCommitteeInput{
		CommitteeQualifier: "default",
		NOPAlias:           "nop1",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one chain selector is required")
}

func TestRemoveNOPFromCommittee_Validation_MissingNOPAlias(t *testing.T) {
	cs := RemoveNOPFromCommittee(newEVMRegistry(&stubOnchainAdapter{}))
	err := cs.VerifyPreconditions(newTestEnvironmentWithOffchain(), RemoveNOPFromCommitteeInput{
		CommitteeQualifier: "default",
		ChainSelectors:     []uint64{chainsel.TEST_90000001.Selector},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "NOP alias is required")
}

func TestRemoveNOPFromCommittee_Validation_RequiresOffchainClient(t *testing.T) {
	cs := RemoveNOPFromCommittee(newEVMRegistry(&stubOnchainAdapter{}))
	err := cs.VerifyPreconditions(deployment.Environment{}, RemoveNOPFromCommitteeInput{
		CommitteeQualifier: "default",
		ChainSelectors:     []uint64{chainsel.TEST_90000001.Selector},
		NOPAlias:           "nop1",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "offchain client is required")
}

// ---- RemoveNOPOffchain validation ----

func TestRemoveNOPOffchain_Validation_MissingQualifier(t *testing.T) {
	cs := RemoveNOPOffchain(newFullEVMRegistry(&stubFullAdapter{}))
	err := cs.VerifyPreconditions(deployment.Environment{}, RemoveNOPOffchainInput{
		ChainSelectors:     []uint64{chainsel.TEST_90000001.Selector},
		ServiceIdentifiers: []string{"svc1"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "committee qualifier is required")
}

func TestRemoveNOPOffchain_Validation_MissingChainSelectors(t *testing.T) {
	cs := RemoveNOPOffchain(newFullEVMRegistry(&stubFullAdapter{}))
	err := cs.VerifyPreconditions(deployment.Environment{}, RemoveNOPOffchainInput{
		CommitteeQualifier: "default",
		ServiceIdentifiers: []string{"svc1"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one chain selector is required")
}

func TestRemoveNOPOffchain_Validation_MissingServiceIdentifiers(t *testing.T) {
	cs := RemoveNOPOffchain(newFullEVMRegistry(&stubFullAdapter{}))
	err := cs.VerifyPreconditions(deployment.Environment{}, RemoveNOPOffchainInput{
		CommitteeQualifier: "default",
		ChainSelectors:     []uint64{chainsel.TEST_90000001.Selector},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one service identifier is required")
}

// ---- RemoveNOPOffchain apply ----

func TestRemoveNOPOffchain_Apply_WritesUpdatedAggregatorConfig(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	qualifier := "default"
	verifierAddr := "0x1111111111111111111111111111111111111111"

	// After removal, committee has 2 signers (0xAAA was removed onchain by step-1).
	// sel1 is both source and destination so buildQuorumConfigs includes it.
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

	cs := RemoveNOPOffchain(newFullEVMRegistry(adapter))
	env := deployment.Environment{
		BlockChains: newTestBlockChains([]uint64{sel1}),
		DataStore:   datastore.NewMemoryDataStore().Seal(),
	}

	out, err := cs.Apply(env, RemoveNOPOffchainInput{
		CommitteeQualifier: qualifier,
		ChainSelectors:     []uint64{sel1},
		ServiceIdentifiers: []string{"my-aggregator"},
	})
	require.NoError(t, err)
	require.NotNil(t, out.DataStore)

	cfg, err := ccvdeployment.GetAggregatorConfig(out.DataStore.Seal(), "my-aggregator")
	require.NoError(t, err)
	signers := cfg.QuorumConfigs[fmt.Sprintf("%d", sel1)].Signers
	require.Len(t, signers, 2, "two signers remain after removal")
}

func TestRemoveNOPOffchain_Apply_ScanError(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector

	adapter := &stubFullAdapter{scanErr: fmt.Errorf("node unreachable")}
	cs := RemoveNOPOffchain(newFullEVMRegistry(adapter))
	env := deployment.Environment{
		BlockChains: newTestBlockChains([]uint64{sel1}),
	}

	_, err := cs.Apply(env, RemoveNOPOffchainInput{
		CommitteeQualifier: "default",
		ChainSelectors:     []uint64{sel1},
		ServiceIdentifiers: []string{"svc1"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "node unreachable")
}

func TestRemoveNOPOffchain_Apply_MultipleServiceIdentifiers(t *testing.T) {
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
					{SourceChainSelector: sel1, Signers: []string{"0xBBB"}, Threshold: 1},
				},
			}},
		},
		verifierAddrs: map[uint64]string{sel1: verifierAddr},
	}

	cs := RemoveNOPOffchain(newFullEVMRegistry(adapter))
	env := deployment.Environment{
		BlockChains: newTestBlockChains([]uint64{sel1}),
		DataStore:   datastore.NewMemoryDataStore().Seal(),
	}

	out, err := cs.Apply(env, RemoveNOPOffchainInput{
		CommitteeQualifier: qualifier,
		ChainSelectors:     []uint64{sel1},
		ServiceIdentifiers: []string{"svc-primary", "svc-secondary"},
	})
	require.NoError(t, err)
	require.NotNil(t, out.DataStore)
}
