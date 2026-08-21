package changesets

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
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
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"
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
	cs := ApplyOnrampUpgradeVerifierConfig(&ccipadapters.OnRampUpgraderRegistry{})
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

	cs := ApplyOnrampUpgradeVerifierConfig(registry)
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

	cs := ApplyOnrampUpgradeVerifierConfig(registry)
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

func TestApplyVerifierConfigOnrampUpgrade_ProperlyIsolateVerifierID(t *testing.T) {
	sel1 := chainsel.TEST_90000001.Selector
	verifierScope := shared.VerifierJobScope{
		CommitteeQualifier: testQualifier,
	}

	aggregators := []AggregatorRef{
		{Name: "agg-a", Address: "0xAGGA"},
		{Name: "agg-b", Address: "0xAGGB"},
	}

	tests := []struct {
		name                   string
		consolidateAggregators bool
		expectedJobs           int
	}{
		{
			name:                   "legacy one job per aggregator",
			consolidateAggregators: false,
			expectedJobs:           len(aggregators),
		},
		{
			name:                   "consolidated aggregator job",
			consolidateAggregators: true,
			expectedJobs:           1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUpgrader := ccipmocks.NewMockOnRampUpgrader(t)
			mockUpgrader.EXPECT().
				LegacyOnRampRef(mock.Anything, sel1).
				Return(datastore.AddressRef{Address: "0xLEGACY1"}, nil)

			registry := ccipadapters.NewOnRampUpgraderRegistry()
			registry.Register(chainsel.FamilyEVM, mockUpgrader)

			env := newOnrampUpgradeTestEnv(t, map[uint64]string{
				sel1: testVerifierAddr,
			})

			cs := ApplyOnrampUpgradeVerifierConfig(registry)
			out, err := cs.Apply(env, ApplyVerifierConfigOnrampUpgradeInput{
				UpgradedChainSelectors: []uint64{sel1},
				ApplyVerifierConfigInput: ApplyVerifierConfigInput{
					CommitteeQualifier:       testQualifier,
					DefaultExecutorQualifier: "default-executor",
					ConsolidateAggregators:   tt.consolidateAggregators,
					Committee: CommitteeInput{
						Aggregators: aggregators,
						ChainConfigs: map[uint64]CommitteeChainMembership{
							sel1: {
								NOPAliases: []shared.NOPAlias{testNOPAlias},
							},
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

			nopJobs := jobs[testNOPAlias]
			require.Len(t, nopJobs, tt.expectedJobs)

			for jobID, job := range nopJobs {
				assert.Contains(
					t,
					string(jobID),
					jobSuffix,
					"isolated job ID must contain the isolation suffix",
				)

				// The verifier config is embedded in the job spec between triple quotes,
				// regardless of whether the job uses committeeVerifierConfig or appConfig.
				parts := strings.Split(job.Spec, "'''")
				require.GreaterOrEqual(
					t,
					len(parts),
					3,
					"job spec must contain an embedded verifier config",
				)

				var verifierCfg commit.Config
				_, err := toml.Decode(parts[1], &verifierCfg)
				require.NoError(t, err)

				// Isolated legacy jobs also use the Aggregators representation so that
				// their runtime verifier_id can differ from the secret lookup key.
				require.Empty(
					t,
					verifierCfg.AggregatorAddress,
					"isolated jobs must not use the legacy aggregator_address field",
				)

				if tt.consolidateAggregators {
					canonicalVerifierID := shared.NewConsolidatedVerifierJobID(
						testNOPAlias,
						verifierScope,
					).GetVerifierID()

					require.Equal(
						t,
						fmt.Sprintf("%s-%s", canonicalVerifierID, jobSuffix),
						verifierCfg.VerifierID,
						"isolated consolidated job must have a unique verifier_id",
					)

					require.Len(t, verifierCfg.Aggregators, len(aggregators))

					aggregatorsByName := make(map[string]commit.AggregatorConnection)
					for _, agg := range verifierCfg.Aggregators {
						aggregatorsByName[agg.Name] = agg
					}

					for _, agg := range aggregators {
						actual, ok := aggregatorsByName[agg.Name]
						require.True(t, ok, "missing aggregator %q", agg.Name)

						expectedSecretName := shared.NewVerifierJobID(
							testNOPAlias,
							agg.Name,
							verifierScope,
						).GetVerifierID()

						assert.Equal(
							t,
							expectedSecretName,
							actual.SecretName,
							"isolating the consolidated job must not change aggregator secret lookup",
						)

						assert.Equal(t, agg.Address, actual.Address)
					}

					continue
				}

				require.Len(
					t,
					verifierCfg.Aggregators,
					1,
					"isolated legacy jobs must use a one-entry aggregators list",
				)

				agg := verifierCfg.Aggregators[0]

				canonicalVerifierID := shared.NewVerifierJobID(
					testNOPAlias,
					agg.Name,
					verifierScope,
				).GetVerifierID()

				require.Equal(
					t,
					fmt.Sprintf("%s-%s", canonicalVerifierID, jobSuffix),
					verifierCfg.VerifierID,
					"isolated legacy job must have a unique verifier_id",
				)

				require.Equal(
					t,
					canonicalVerifierID,
					agg.SecretName,
					"isolated legacy job must keep using the canonical verifier ID as its secret name",
				)

				assert.NotEqual(
					t,
					verifierCfg.VerifierID,
					agg.SecretName,
					"runtime verifier_id and secret lookup identity must be isolated",
				)
			}
		})
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

	cs := ApplyOnrampUpgradeVerifierConfig(registry)
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

	cs := ApplyOnrampUpgradeVerifierConfig(registry)
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
