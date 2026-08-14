package changesets

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	ccipadapters "github.com/smartcontractkit/chainlink-ccip/deployment/v2_0_0/adapters"
	ccipmocks "github.com/smartcontractkit/chainlink-ccip/deployment/v2_0_0/mocks"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

// newOnrampUpgradeTestEnv builds an environment for ApplyOnrampRedeployVerifierConfig.Apply:
// it registers the verifier/executor adapters (via stubFullAdapter, defined in
// add_nop_to_committee_test.go) and leaves Offchain nil so JD-only steps (signing-key
// fetch, node chain-support validation, job proposal) take their AllowMissingJD /
// e.Offchain==nil skip paths — job specs are still generated and persisted to DataStore,
// which is all these tests need to inspect.
func newOnrampUpgradeTestEnv(t *testing.T, verifierAddrs map[uint64]string) deployment.Environment {
	t.Helper()
	adapter := &stubFullAdapter{verifierAddrs: verifierAddrs}
	registerFullEVMAdapters(adapter)

	lggr := logger.Test(t)
	bundle := operations.NewBundle(
		func() context.Context { return context.Background() },
		lggr,
		operations.NewMemoryReporter(),
	)
	return deployment.Environment{
		Logger:           lggr,
		DataStore:        datastore.NewMemoryDataStore().Seal(),
		OperationsBundle: bundle,
	}
}

func TestApplyVerifierConfigOnrampUpgrade_Validation_RequiresUpgradedChainSelectors(t *testing.T) {
	registerEVMOnchain(&stubOnchainAdapter{})
	cs := ApplyOnrampRedeployVerifierConfig(&ccipadapters.OnRampUpgraderRegistry{})
	err := cs.VerifyPreconditions(deployment.Environment{}, ApplyVerifierConfigOnrampUpgradeInput{
		ApplyVerifierConfigInput: ApplyVerifierConfigInput{
			CommitteeQualifier:       "default",
			DefaultExecutorQualifier: "default-executor",
			Committee:                CommitteeInput{Aggregators: []AggregatorRef{{Name: "agg", Address: "0xAGG"}}},
			NOPs:                     []NOPInput{{Alias: "nop1"}},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one upgraded chain selector is required")
}

func TestApplyVerifierConfigOnrampUpgrade_UseCorrectPrefix(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	verifierAddr := testVerifierAddr

	mockUpgrader := ccipmocks.NewMockOnRampUpgrader(t)
	mockUpgrader.EXPECT().
		LegacyOnRampRef(mock.Anything, sel1).
		Return(datastore.AddressRef{Address: "0xLEGACY1"}, nil)

	registry := ccipadapters.NewOnRampUpgraderRegistry()
	registry.Register(chainsel.FamilyEVM, mockUpgrader)

	env := newOnrampUpgradeTestEnv(t, map[uint64]string{sel1: verifierAddr})

	cs := ApplyOnrampRedeployVerifierConfig(registry)
	out, err := cs.Apply(env, ApplyVerifierConfigOnrampUpgradeInput{
		UpgradedChainSelectors: []uint64{sel1},
		ApplyVerifierConfigInput: ApplyVerifierConfigInput{
			CommitteeQualifier:       testQualifier,
			DefaultExecutorQualifier: "default-executor",
			Committee: CommitteeInput{
				Aggregators: []AggregatorRef{{Name: "agg", Address: "0xAGG"}},
				ChainConfigs: map[uint64]CommitteeChainMembership{
					sel1: {NOPAliases: []shared.NOPAlias{testNOPAlias}},
				},
			},
			NOPs: []NOPInput{{Alias: testNOPAlias, SignerAddressByFamily: map[string]string{chainsel.FamilyEVM: testSignerAddr}}},
		},
	})
	require.NoError(t, err)

	jobs, err := ccvdeployment.GetAllJobs(out.DataStore.Seal())
	require.NoError(t, err)
	require.NotEmpty(t, jobs[testNOPAlias])

	for jobID := range jobs[testNOPAlias] {
		assert.Contains(t, string(jobID), jobSuffix, "job ID %q must carry the onramp-upgrade suffix", jobID)
	}
}

func TestApplyVerifierConfigOnrampUpgrade_IncludesNonUpgradedChainsButOnlyOverridesUpgradedChains(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	sel2 := chainsel.TEST_90000002.Selector

	verifierAddr1 := testVerifierAddr
	verifierAddr2 := "0x2222222222222222222222222222222222222222"
	legacyOnramp := "0xLEGACY1"

	mockUpgrader := ccipmocks.NewMockOnRampUpgrader(t)
	mockUpgrader.EXPECT().
		LegacyOnRampRef(mock.Anything, sel1).
		Return(datastore.AddressRef{Address: legacyOnramp}, nil)

	// sel2 is not upgraded, so LegacyOnRampRef must never be called for it.

	registry := ccipadapters.NewOnRampUpgraderRegistry()
	registry.Register(chainsel.FamilyEVM, mockUpgrader)

	env := newOnrampUpgradeTestEnv(t, map[uint64]string{
		sel1: verifierAddr1,
		sel2: verifierAddr2,
	})

	cs := ApplyOnrampRedeployVerifierConfig(registry)
	out, err := cs.Apply(env, ApplyVerifierConfigOnrampUpgradeInput{
		UpgradedChainSelectors: []uint64{sel1},
		ApplyVerifierConfigInput: ApplyVerifierConfigInput{
			CommitteeQualifier:       testQualifier,
			DefaultExecutorQualifier: "default-executor",
			Committee: CommitteeInput{
				Aggregators: []AggregatorRef{
					{Name: "agg", Address: "0xAGG"},
				},
				ChainConfigs: map[uint64]CommitteeChainMembership{
					sel1: {NOPAliases: []shared.NOPAlias{testNOPAlias}},
					sel2: {NOPAliases: []shared.NOPAlias{testNOPAlias}},
				},
			},
			NOPs: []NOPInput{{
				Alias: testNOPAlias,
				SignerAddressByFamily: map[string]string{
					chainsel.FamilyEVM: testSignerAddr,
				},
			}},
		},
	})
	require.NoError(t, err)

	jobs, err := ccvdeployment.GetAllJobs(out.DataStore.Seal())
	require.NoError(t, err)
	require.NotEmpty(t, jobs[testNOPAlias])

	sel1Key := fmt.Sprintf("%d", sel1)
	sel2Key := fmt.Sprintf("%d", sel2)

	for _, job := range jobs[testNOPAlias] {
		assert.Contains(
			t,
			job.Spec,
			sel1Key,
			"job spec must contain the upgraded chain",
		)

		assert.Contains(
			t,
			job.Spec,
			sel2Key,
			"job spec must retain non-upgraded committee chains",
		)

		assert.Contains(
			t,
			job.Spec,
			legacyOnramp,
			"job spec must use the legacy OnRamp for the upgraded chain",
		)
	}
}

func TestApplyVerifierConfigOnrampUpgrade_UseCorrectOnRampAddress(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	verifierAddr := testVerifierAddr
	legacyOnramp := "0xLEGACYONRAMPADDRESS"

	mockUpgrader := ccipmocks.NewMockOnRampUpgrader(t)
	mockUpgrader.EXPECT().
		LegacyOnRampRef(mock.Anything, sel1).
		Return(datastore.AddressRef{Address: legacyOnramp}, nil)

	registry := ccipadapters.NewOnRampUpgraderRegistry()
	registry.Register(chainsel.FamilyEVM, mockUpgrader)

	env := newOnrampUpgradeTestEnv(t, map[uint64]string{sel1: verifierAddr})

	cs := ApplyOnrampRedeployVerifierConfig(registry)
	out, err := cs.Apply(env, ApplyVerifierConfigOnrampUpgradeInput{
		UpgradedChainSelectors: []uint64{sel1},
		ApplyVerifierConfigInput: ApplyVerifierConfigInput{
			CommitteeQualifier:       testQualifier,
			DefaultExecutorQualifier: "default-executor",
			Committee: CommitteeInput{
				Aggregators: []AggregatorRef{{Name: "agg", Address: "0xAGG"}},
				ChainConfigs: map[uint64]CommitteeChainMembership{
					sel1: {NOPAliases: []shared.NOPAlias{testNOPAlias}},
				},
			},
			NOPs: []NOPInput{{Alias: testNOPAlias, SignerAddressByFamily: map[string]string{chainsel.FamilyEVM: testSignerAddr}}},
		},
	})
	require.NoError(t, err)

	jobs, err := ccvdeployment.GetAllJobs(out.DataStore.Seal())
	require.NoError(t, err)
	require.NotEmpty(t, jobs[testNOPAlias])

	for _, job := range jobs[testNOPAlias] {
		assert.Contains(t, job.Spec, legacyOnramp, "job spec must use the legacy OnRamp address for the upgraded chain")
		// stubFullAdapter.ResolveVerifierContractAddresses always returns this new OnRamp
		// address; it must have been overridden by the legacy address above.
		assert.NotContains(t, job.Spec, "0x000000000000000000000000000000000000AAAA")
	}
}

func TestApplyVerifierConfigOnrampUpgrade_ErrorWhenNoLegacyOnramp(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	verifierAddr := testVerifierAddr

	// LegacyOnRampRef errors (no legacy OnRamp on record): the apply loop's `continue`
	// path skips the override and the normal (new) OnRamp address is used instead.
	mockUpgrader := ccipmocks.NewMockOnRampUpgrader(t)
	mockUpgrader.EXPECT().
		LegacyOnRampRef(mock.Anything, sel1).
		Return(datastore.AddressRef{}, fmt.Errorf("no legacy onramp for selector %d", sel1))

	registry := ccipadapters.NewOnRampUpgraderRegistry()
	registry.Register(chainsel.FamilyEVM, mockUpgrader)

	env := newOnrampUpgradeTestEnv(t, map[uint64]string{sel1: verifierAddr})

	cs := ApplyOnrampRedeployVerifierConfig(registry)
	_, err := cs.Apply(env, ApplyVerifierConfigOnrampUpgradeInput{
		UpgradedChainSelectors: []uint64{sel1},
		ApplyVerifierConfigInput: ApplyVerifierConfigInput{
			CommitteeQualifier:       testQualifier,
			DefaultExecutorQualifier: "default-executor",
			Committee: CommitteeInput{
				Aggregators: []AggregatorRef{{Name: "agg", Address: "0xAGG"}},
				ChainConfigs: map[uint64]CommitteeChainMembership{
					sel1: {NOPAliases: []shared.NOPAlias{testNOPAlias}},
				},
			},
			NOPs: []NOPInput{{Alias: testNOPAlias, SignerAddressByFamily: map[string]string{chainsel.FamilyEVM: testSignerAddr}}},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no legacy onramp for selector")
}
