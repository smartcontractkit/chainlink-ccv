package changesets_test

import (
	"fmt"
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/deployments"
	"github.com/smartcontractkit/chainlink-ccv/deployments/changesets"
	"github.com/smartcontractkit/chainlink-ccv/deployments/testutils"
)

const testCommitteeQualifier = "test-committee"

func TestGenerateIndexerConfig_ValidatesServiceIdentifier(t *testing.T) {
	changeset := changesets.GenerateIndexerConfig()

	env := createTestEnvironmentForValidation(t)

	err := changeset.VerifyPreconditions(env, changesets.GenerateIndexerConfigCfg{
		ServiceIdentifier:  "",
		VerifierQualifiers: []string{"default"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "service identifier is required")
}

func TestGenerateIndexerConfig_ValidatesVerifierQualifiers(t *testing.T) {
	changeset := changesets.GenerateIndexerConfig()

	env := createTestEnvironmentForValidation(t)

	err := changeset.VerifyPreconditions(env, changesets.GenerateIndexerConfigCfg{
		ServiceIdentifier:  "default-indexer",
		VerifierQualifiers: []string{},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one verifier qualifier is required")
}

func TestGenerateIndexerConfig_ValidatesSourceChainSelectors(t *testing.T) {
	changeset := changesets.GenerateIndexerConfig()

	env := createTestEnvironmentForValidation(t)

	err := changeset.VerifyPreconditions(env, changesets.GenerateIndexerConfigCfg{
		ServiceIdentifier:  "default-indexer",
		VerifierQualifiers: []string{"default"},
		ChainSelectors:     []uint64{1234},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "selector 1234 is not available in environment")
}

func TestGenerateIndexerConfig_GeneratesCorrectConfigWithMultipleVerifiers(t *testing.T) {
	chainSelectors := []uint64{1001, 1002}
	verifiers := []string{"verifier-a", "verifier-b"}

	ds := datastore.NewMemoryDataStore()
	for _, verifier := range verifiers {
		for _, sel := range chainSelectors {
			err := ds.Addresses().Add(datastore.AddressRef{
				ChainSelector: sel,
				Qualifier:     verifier,
				Type:          datastore.ContractType(committee_verifier.ResolverType),
				Address:       fmt.Sprintf("0x%s_%d", verifier, sel),
				Version:       semver.MustParse("1.0.0"),
			})
			require.NoError(t, err)
		}
	}

	env := deployment.Environment{
		OperationsBundle: testutils.NewTestBundle(),
		BlockChains:      testutils.NewStubBlockChains(chainSelectors),
		DataStore:        ds.Seal(),
	}

	cs := changesets.GenerateIndexerConfig()
	output, err := cs.Apply(env, changesets.GenerateIndexerConfigCfg{
		ServiceIdentifier:  "test-indexer",
		VerifierQualifiers: verifiers,
		ChainSelectors:     chainSelectors,
	})
	require.NoError(t, err)

	require.NotNil(t, output.DataStore)
	cfg, err := deployments.GetIndexerConfig(output.DataStore.Seal(), "test-indexer")
	require.NoError(t, err)

	assert.Len(t, cfg.Verifier, len(verifiers))

	for _, qualifier := range verifiers {
		verifierCfg, ok := cfg.Verifier[qualifier]
		require.True(t, ok, "expected verifier config for qualifier %s", qualifier)
		assert.Len(t, verifierCfg.IssuerAddresses, len(chainSelectors),
			"verifier %s should have %d issuer addresses", qualifier, len(chainSelectors))
	}
}

func TestGenerateIndexerConfig_PreservesExistingAggregatorConfig(t *testing.T) {
	chainSelectors := []uint64{1001, 1002}
	committee := testCommitteeQualifier

	ds := datastore.NewMemoryDataStore()
	for _, sel := range chainSelectors {
		err := ds.Addresses().Add(datastore.AddressRef{
			ChainSelector: sel,
			Qualifier:     committee,
			Type:          datastore.ContractType(committee_verifier.ResolverType),
			Address:       fmt.Sprintf("0xverifier_%d", sel),
			Version:       semver.MustParse("1.0.0"),
		})
		require.NoError(t, err)
	}

	existingAggregatorConfig := &model.Committee{
		DestinationVerifiers: map[model.DestinationSelector]string{
			"1001": "0xdest_1001",
			"1002": "0xdest_1002",
		},
		QuorumConfigs: map[model.SourceSelector]*model.QuorumConfig{
			"1001": {
				SourceVerifierAddress: "0xsource_1001",
				Signers:               []model.Signer{{Address: "0xsigner1"}},
				Threshold:             1,
			},
		},
	}
	err := deployments.SaveAggregatorConfig(ds, "existing-aggregator", existingAggregatorConfig)
	require.NoError(t, err)

	env := deployment.Environment{
		OperationsBundle: testutils.NewTestBundle(),
		BlockChains:      testutils.NewStubBlockChains(chainSelectors),
		DataStore:        ds.Seal(),
	}

	cs := changesets.GenerateIndexerConfig()
	output, err := cs.Apply(env, changesets.GenerateIndexerConfigCfg{
		ServiceIdentifier:  "new-indexer",
		VerifierQualifiers: []string{committee},
		ChainSelectors:     chainSelectors,
	})
	require.NoError(t, err)
	require.NotNil(t, output.DataStore)

	outputSealed := output.DataStore.Seal()

	_, err = deployments.GetIndexerConfig(outputSealed, "new-indexer")
	require.NoError(t, err, "new indexer config should be present")

	retrievedAggregatorConfig, err := deployments.GetAggregatorConfig(outputSealed, "existing-aggregator")
	require.NoError(t, err, "existing aggregator config should be preserved")
	assert.Equal(t, existingAggregatorConfig, retrievedAggregatorConfig, "aggregator config should be unchanged")
}
