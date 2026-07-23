package changesets

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/offchain"

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
