package changesets

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/offchain"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	"github.com/smartcontractkit/chainlink-ccv/deployment/inventory"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

// nopOffchainClient is a non-nil offchain.Client value used only to make
// e.Offchain != nil true for validate-only tests. It embeds the interface
// itself (rather than implementing it) so every method promotes from a nil
// field -- calling any of them would panic, but validate() never calls any
// Offchain method, only checks it for nilness, so this is safe here. This is
// intentionally not a JD/Offchain mock: it carries no behavior at all.
type nopOffchainClient struct {
	offchain.Client
}

func validCombinedVerifierExecutorInput(sel uint64) ApplyVerifierExecutorConfigInput {
	return ApplyVerifierExecutorConfigInput{
		NOPs: []NOPInput{{Alias: "nop1", SignerAddressByFamily: map[string]string{chainsel.FamilyEVM: "0xAAA"}}},
		Verifier: VerifierBundleInput{
			Committee: VerifierBundleCommittee{
				Aggregators: []AggregatorRef{{Name: "agg", Address: "0xAGG"}},
				ChainConfigs: map[uint64]CommitteeChainMembership{
					sel: {NOPAliases: []shared.NOPAlias{"nop1"}},
				},
			},
		},
		Executor: ExecutorBundleInput{
			Pool: ExecutorPoolInput{
				ChainConfigs: map[uint64]ChainExecutorPoolMembership{
					sel: {NOPAliases: []shared.NOPAlias{"nop1"}, ExecutionInterval: 5 * time.Second},
				},
			},
			IndexerAddress: []string{"indexer:1234"},
		},
	}
}

func TestApplyVerifierExecutorConfig_Validation_AcceptsValidCombinedInput(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerEVMOnchain(&stubOnchainAdapter{})
	cs := ApplyVerifierExecutorConfig()

	err := cs.VerifyPreconditions(
		deployment.Environment{Offchain: nopOffchainClient{}},
		validCombinedVerifierExecutorInput(sel),
	)
	require.NoError(t, err)
}

func TestApplyVerifierExecutorConfig_Validation_VerifierInvalidNamesVerifierFailure(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerEVMOnchain(&stubOnchainAdapter{})
	cs := ApplyVerifierExecutorConfig()

	cfg := validCombinedVerifierExecutorInput(sel)
	cfg.Verifier.Committee.Aggregators = nil // invalidate verifier side only

	err := cs.VerifyPreconditions(deployment.Environment{Offchain: nopOffchainClient{}}, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verifier:")
	assert.Contains(t, err.Error(), "at least one aggregator is required")
}

func TestApplyVerifierExecutorConfig_Validation_ExecutorInvalidNamesExecutorFailure(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerEVMOnchain(&stubOnchainAdapter{})
	cs := ApplyVerifierExecutorConfig()

	cfg := validCombinedVerifierExecutorInput(sel)
	cfg.Executor.IndexerAddress = nil // invalidate executor side only

	err := cs.VerifyPreconditions(deployment.Environment{Offchain: nopOffchainClient{}}, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "executor:")
	assert.Contains(t, err.Error(), "indexer address is required")
}

func TestApplyVerifierExecutorConfig_Validation_BothInvalidAggregatesBothFailures(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerEVMOnchain(&stubOnchainAdapter{})
	cs := ApplyVerifierExecutorConfig()

	cfg := validCombinedVerifierExecutorInput(sel)
	cfg.Verifier.Committee.Aggregators = nil
	cfg.Executor.IndexerAddress = nil

	err := cs.VerifyPreconditions(deployment.Environment{Offchain: nopOffchainClient{}}, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one aggregator is required")
	assert.Contains(t, err.Error(), "indexer address is required")
}

func TestApplyVerifierExecutorConfig_Validation_OffchainAbsentFailsFastWithNonEmptyInput(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerEVMOnchain(&stubOnchainAdapter{})
	cs := ApplyVerifierExecutorConfig()

	err := cs.VerifyPreconditions(deployment.Environment{}, validCombinedVerifierExecutorInput(sel))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "NOPs require JD but e.Offchain is nil")
}

// TestApplyVerifierExecutorConfig_InjectsDefaultQualifier proves the bundle input
// exposes no qualifier field at all (see VerifierBundleCommittee) and that the
// derive helpers inject defaultQualifier on every qualifier the sub-changesets
// consume -- committee, default-executor, the derived CommitteeInput, and the
// executor pool -- so nothing is left to downstream defaulting.
func TestApplyVerifierExecutorConfig_InjectsDefaultQualifier(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerEVMOnchain(&stubOnchainAdapter{})
	cs := ApplyVerifierExecutorConfig()

	cfg := validCombinedVerifierExecutorInput(sel)

	err := cs.VerifyPreconditions(deployment.Environment{Offchain: nopOffchainClient{}}, cfg)
	require.NoError(t, err)
	derived := deriveVerifierInput(cfg)
	assert.Equal(t, defaultQualifier, derived.Committee.Qualifier)
	assert.Equal(t, defaultQualifier, derived.CommitteeQualifier)
	assert.Equal(t, defaultQualifier, derived.DefaultExecutorQualifier)
	assert.Equal(t, defaultQualifier, deriveExecutorInput(cfg).ExecutorQualifier)
}

func TestApplyVerifierExecutorConfig_Validation_ProductionRejectsPyroscope(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerEVMOnchain(&stubOnchainAdapter{})
	cs := ApplyVerifierExecutorConfig()

	cfg := validCombinedVerifierExecutorInput(sel)
	cfg.PyroscopeURL = "http://pyroscope.example"

	err := cs.VerifyPreconditions(deployment.Environment{Name: "mainnet", Offchain: nopOffchainClient{}}, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pyroscope URL is not supported for production")
}

// ---- derive-function parity ----

func TestDeriveVerifierInput_MatchesHandBuiltStandaloneInput(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	cfg := ApplyVerifierExecutorConfigInput{
		NOPs:               []NOPInput{{Alias: "nop1", Mode: shared.NOPModeCL}},
		PyroscopeURL:       "http://pyroscope.example",
		TargetNOPs:         []shared.NOPAlias{"nop1"},
		RevokeOrphanedJobs: true,
		Verifier: VerifierBundleInput{
			Committee: VerifierBundleCommittee{
				Aggregators: []AggregatorRef{{Name: "agg", Address: "0xAGG"}},
				ChainConfigs: map[uint64]CommitteeChainMembership{
					sel: {NOPAliases: []shared.NOPAlias{"nop1"}},
				},
			},
			DisableFinalityCheckers: []string{"1"},
			ConsolidateAggregators:  true,
		},
		Executor: ExecutorBundleInput{
			Pool:           ExecutorPoolInput{ChainConfigs: map[uint64]ChainExecutorPoolMembership{sel: {NOPAliases: []shared.NOPAlias{"nop1"}}}},
			IndexerAddress: []string{"indexer:1234"},
		},
	}

	want := ApplyVerifierConfigInput{
		// The combined input carries no qualifier fields; the bundle injects
		// defaultQualifier on every qualifier the sub-changeset consumes,
		// including the derived CommitteeInput.Qualifier.
		NOPs:                     cfg.NOPs,
		CommitteeQualifier:       defaultQualifier,
		DefaultExecutorQualifier: defaultQualifier,
		Committee: CommitteeInput{
			Qualifier:    defaultQualifier,
			Aggregators:  cfg.Verifier.Committee.Aggregators,
			ChainConfigs: cfg.Verifier.Committee.ChainConfigs,
		},
		PyroscopeURL:            cfg.PyroscopeURL,
		TargetNOPs:              cfg.TargetNOPs,
		DisableFinalityCheckers: cfg.Verifier.DisableFinalityCheckers,
		RevokeOrphanedJobs:      cfg.RevokeOrphanedJobs,
		ConsolidateAggregators:  cfg.Verifier.ConsolidateAggregators,
	}

	assert.Equal(t, want, deriveVerifierInput(cfg))
}

func TestApplyVerifierExecutorConfigPreservesBothJobOutputs(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerEVMChainTypeForIdentities()
	registerFullEVMAdapters(&stubFullAdapter{
		states:        map[uint64][]*adapters.CommitteeState{sel: nil},
		verifierAddrs: map[uint64]string{sel: "0xcommittee"},
	})
	env := newTestEnvForApply(t, "nop1", []uint64{sel})
	env.GetContext = t.Context
	addCCVTestEVMChainSupport(t, env, sel)

	out, err := ApplyVerifierExecutorConfig().Apply(env, validCombinedVerifierExecutorInput(sel))
	require.NoError(t, err)
	jobs, err := ccvdeployment.GetAllJobs(out.DataStore.Seal())
	require.NoError(t, err)
	require.Len(t, jobs["nop1"], 2, "the executor output must retain the verifier job metadata")
	signers, err := ccvdeployment.GetNOPSigners(out.DataStore.Seal())
	require.NoError(t, err)
	require.Equal(t, "0xAAA", signers["nop1"][chainsel.FamilyEVM])

	nodes, err := ccvdeployment.GetJDNodes(out.DataStore.Seal())
	require.NoError(t, err)
	require.Len(t, nodes, 1)
}

func TestApplyVerifierExecutorConfigUsesPersistedJDNodeInventory(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	registerEVMChainTypeForIdentities()
	registerFullEVMAdapters(&stubFullAdapter{
		states:        map[uint64][]*adapters.CommitteeState{sel: nil},
		verifierAddrs: map[uint64]string{sel: "0xcommittee"},
	})
	env := newTestEnvForApply(t, "nop1", []uint64{sel})
	env.GetContext = t.Context
	env.NodeIDs = nil
	ds := datastore.NewMemoryDataStore()
	require.NoError(t, ccvdeployment.SaveJDNodes(ds, map[string]ccvdeployment.JDNode{
		"node-nop1": {Name: "nop1"},
	}))
	env.DataStore = ds.Seal()
	addCCVTestEVMChainSupport(t, env, sel)

	out, err := ApplyVerifierExecutorConfig().Apply(env, validCombinedVerifierExecutorInput(sel))
	require.NoError(t, err)
	jobs, err := ccvdeployment.GetAllJobs(out.DataStore.Seal())
	require.NoError(t, err)
	require.Len(t, jobs["nop1"], 2)
}

func TestApplyVerifierExecutorConfigPublishesObservedCommittees(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	signer := "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
	registerEVMChainTypeForIdentities()
	registerFullEVMAdapters(&stubFullAdapter{
		states: map[uint64][]*adapters.CommitteeState{sel: {{
			Qualifier: "default", ChainSelector: sel, Address: "0xcommittee",
			SignatureConfigs: []adapters.SignatureConfig{{SourceChainSelector: sel, Threshold: 2, Signers: []string{signer}}},
		}}},
		verifierAddrs: map[uint64]string{sel: "0xcommittee"},
	})
	env := newTestEnvForApply(t, "nop1", []uint64{sel})
	env.GetContext = t.Context
	addCCVTestEVMChainSupport(t, env, sel)
	cfg := validCombinedVerifierExecutorInput(sel)
	cfg.NOPs[0].SignerAddressByFamily = map[string]string{chainsel.FamilyEVM: signer}

	out, err := ApplyVerifierExecutorConfig().Apply(env, cfg)
	require.NoError(t, err)

	inv, err := ccvdeployment.GetInventory(out.DataStore.Seal())
	require.NoError(t, err)
	var onchain []inventory.Committee
	for _, c := range inv.Committees {
		if c.Source == inventory.SourceOnchain {
			onchain = append(onchain, c)
		}
	}
	require.Len(t, onchain, 1, "a normal run publishes the observed committee on the first run")
	require.Len(t, onchain[0].VerifierDeployments, 1)
	assert.Equal(t, inventory.ChainSelector(sel), onchain[0].VerifierDeployments[0].Chain)
	assert.Equal(t, inventory.ChainSelector(sel), onchain[0].SourceChain)
	assert.Equal(t, uint8(2), onchain[0].Threshold)
	require.Len(t, onchain[0].Members, 1)
	assert.Equal(t, signer, onchain[0].Members[0].SignerAddress)
	assert.Equal(t, "nop1", onchain[0].Members[0].NOPAlias)

	require.Len(t, inv.Refreshes, 1)
	assert.Empty(t, inv.Refreshes[0].LastError)
	assert.False(t, inv.Refreshes[0].LastSuccessAt.IsZero())
}

func TestDeriveExecutorInput_MatchesHandBuiltStandaloneInput(t *testing.T) {
	sel := chainsel.TEST_90000001.Selector
	cfg := ApplyVerifierExecutorConfigInput{
		NOPs:               []NOPInput{{Alias: "nop1", Mode: shared.NOPModeCL}},
		PyroscopeURL:       "http://pyroscope.example",
		TargetNOPs:         []shared.NOPAlias{"nop1"},
		RevokeOrphanedJobs: true,
		Verifier: VerifierBundleInput{
			Committee: VerifierBundleCommittee{
				Aggregators: []AggregatorRef{{Name: "agg", Address: "0xAGG"}},
			},
		},
		Executor: ExecutorBundleInput{
			Pool: ExecutorPoolInput{
				ChainConfigs: map[uint64]ChainExecutorPoolMembership{
					sel: {NOPAliases: []shared.NOPAlias{"nop1"}, ExecutionInterval: 5 * time.Second},
				},
				WorkerCount: 3,
			},
			IndexerAddress: []string{"indexer:1234"},
		},
	}

	want := ApplyExecutorConfigInput{
		// The combined input carries no qualifier field; the bundle injects
		// defaultQualifier.
		NOPs:               cfg.NOPs,
		ExecutorQualifier:  defaultQualifier,
		Pool:               cfg.Executor.Pool,
		IndexerAddress:     cfg.Executor.IndexerAddress,
		PyroscopeURL:       cfg.PyroscopeURL,
		TargetNOPs:         cfg.TargetNOPs,
		RevokeOrphanedJobs: cfg.RevokeOrphanedJobs,
	}

	assert.Equal(t, want, deriveExecutorInput(cfg))
}
