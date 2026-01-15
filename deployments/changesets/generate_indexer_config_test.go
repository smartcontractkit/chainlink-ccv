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

	"github.com/smartcontractkit/chainlink-ccv/deployments"
	"github.com/smartcontractkit/chainlink-ccv/deployments/changesets"
	"github.com/smartcontractkit/chainlink-ccv/deployments/testutils"
)

func TestGenerateIndexerConfig_ValidatesServiceIdentifier(t *testing.T) {
	changeset := changesets.GenerateIndexerConfig()

	env := createTestEnvironmentForValidation(t)

	err := changeset.VerifyPreconditions(env, changesets.GenerateIndexerConfigCfg{
		ServiceIdentifier:   "",
		CommitteeQualifiers: []string{"default"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "service identifier is required")
}

func TestGenerateIndexerConfig_ValidatesCommitteeQualifiers(t *testing.T) {
	changeset := changesets.GenerateIndexerConfig()

	env := createTestEnvironmentForValidation(t)

	err := changeset.VerifyPreconditions(env, changesets.GenerateIndexerConfigCfg{
		ServiceIdentifier:   "default-indexer",
		CommitteeQualifiers: []string{},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one committee qualifier is required")
}

func TestGenerateIndexerConfig_ValidatesSourceChainSelectors(t *testing.T) {
	changeset := changesets.GenerateIndexerConfig()

	env := createTestEnvironmentForValidation(t)

	err := changeset.VerifyPreconditions(env, changesets.GenerateIndexerConfigCfg{
		ServiceIdentifier:   "default-indexer",
		CommitteeQualifiers: []string{"default"},
		ChainSelectors:      []uint64{1234},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "selector 1234 is not available in environment")
}

func TestGenerateIndexerConfig_GeneratesCorrectConfigWithMultipleCommittees(t *testing.T) {
	chainSelectors := []uint64{1001, 1002}
	committees := []string{"committee-a", "committee-b"}

	ds := datastore.NewMemoryDataStore()
	for _, committee := range committees {
		for _, sel := range chainSelectors {
			err := ds.Addresses().Add(datastore.AddressRef{
				ChainSelector: sel,
				Qualifier:     committee,
				Type:          datastore.ContractType(committee_verifier.ResolverType),
				Address:       fmt.Sprintf("0x%s_%d", committee, sel),
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
		ServiceIdentifier:   "test-indexer",
		CommitteeQualifiers: committees,
		ChainSelectors:      chainSelectors,
	})
	require.NoError(t, err)

	require.NotNil(t, output.DataStore)
	cfg, err := deployments.GetIndexerConfig(output.DataStore.Seal(), "test-indexer")
	require.NoError(t, err)

	assert.Len(t, cfg.Verifier, len(committees))

	for idx := range committees {
		idxStr := fmt.Sprintf("%d", idx)
		verifierCfg, ok := cfg.Verifier[idxStr]
		require.True(t, ok, "expected verifier config at index %s", idxStr)
		assert.Len(t, verifierCfg.IssuerAddresses, len(chainSelectors),
			"verifier %s should have %d issuer addresses", idxStr, len(chainSelectors))
	}
}
