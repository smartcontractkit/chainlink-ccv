package changesets

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
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
	cs := RemoveNOPFromCommittee(newEVMRegistry(&stubOnchainAdapter{}))
	err := cs.VerifyPreconditions(newTestEnvironmentWithOffchain(), RemoveNOPFromCommitteeInput{
		SourceChainSelectors: []uint64{chainsel.TEST_90000001.Selector},
		NOPAlias:             testNOPAlias,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "committee qualifier is required")
}

func TestRemoveNOPFromCommittee_Validation_MissingSourceChainSelectors(t *testing.T) {
	cs := RemoveNOPFromCommittee(newEVMRegistry(&stubOnchainAdapter{}))
	err := cs.VerifyPreconditions(newTestEnvironmentWithOffchain(), RemoveNOPFromCommitteeInput{
		CommitteeQualifier: testQualifier,
		NOPAlias:           testNOPAlias,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one source chain selector is required")
}

func TestRemoveNOPFromCommittee_Validation_MissingNOPAlias(t *testing.T) {
	cs := RemoveNOPFromCommittee(newEVMRegistry(&stubOnchainAdapter{}))
	err := cs.VerifyPreconditions(newTestEnvironmentWithOffchain(), RemoveNOPFromCommitteeInput{
		CommitteeQualifier:   testQualifier,
		SourceChainSelectors: []uint64{chainsel.TEST_90000001.Selector},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "NOP alias is required")
}

func TestRemoveNOPFromCommittee_Validation_RequiresOffchainClient(t *testing.T) {
	cs := RemoveNOPFromCommittee(newEVMRegistry(&stubOnchainAdapter{}))
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
	cs := RemoveNOPOffchain(newFullEVMRegistry(&stubFullAdapter{}))
	err := cs.VerifyPreconditions(deployment.Environment{}, RemoveNOPOffchainInput{
		SourceChainSelectors: []uint64{chainsel.TEST_90000001.Selector},
		ServiceIdentifiers:   []string{"svc1"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "committee qualifier is required")
}

func TestRemoveNOPOffchain_Validation_MissingSourceChainSelectors(t *testing.T) {
	cs := RemoveNOPOffchain(newFullEVMRegistry(&stubFullAdapter{}))
	err := cs.VerifyPreconditions(deployment.Environment{}, RemoveNOPOffchainInput{
		CommitteeQualifier: testQualifier,
		ServiceIdentifiers: []string{"svc1"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one source chain selector is required")
}

func TestRemoveNOPOffchain_Validation_MissingServiceIdentifiers(t *testing.T) {
	cs := RemoveNOPOffchain(newFullEVMRegistry(&stubFullAdapter{}))
	err := cs.VerifyPreconditions(deployment.Environment{}, RemoveNOPOffchainInput{
		CommitteeQualifier:   testQualifier,
		SourceChainSelectors: []uint64{chainsel.TEST_90000001.Selector},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one service identifier is required")
}

func TestRemoveNOPOffchain_Validation_MissingNOPAlias(t *testing.T) {
	cs := RemoveNOPOffchain(newFullEVMRegistry(&stubFullAdapter{}))
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

	cs := RemoveNOPOffchain(newFullEVMRegistry(adapter))
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

	cs := RemoveNOPOffchain(newFullEVMRegistry(adapter))
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

	cs := RemoveNOPOffchain(newFullEVMRegistry(adapter))
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

	cs := RemoveNOPOffchain(newFullEVMRegistry(adapter))
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
	cs := RemoveNOPOffchain(newFullEVMRegistry(adapter))
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

	cs := RemoveNOPOffchain(newFullEVMRegistry(adapter))
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
