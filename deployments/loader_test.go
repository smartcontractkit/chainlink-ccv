package deployments_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/deployments"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
)

func TestSaveAggregatorConfig_PreservesUnknownProperties(t *testing.T) {
	ds := datastore.NewMemoryDataStore()

	err := ds.EnvMetadata().Set(datastore.EnvMetadata{
		Metadata: map[string]any{
			"ccipConfig": map[string]any{"setting": "enabled"},
		},
	})
	require.NoError(t, err)

	cfg := &model.Committee{
		QuorumConfigs: map[model.SourceSelector]*model.QuorumConfig{},
	}
	err = deployments.SaveAggregatorConfig(ds, "test-aggregator", cfg)
	require.NoError(t, err)

	result := getMetadataAsMap(t, ds)
	assert.Contains(t, result, "ccipConfig")
	assert.Contains(t, result, "offchainConfigs")

	ccipConfig, ok := result["ccipConfig"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "enabled", ccipConfig["setting"])
}

func TestSaveIndexerConfig_PreservesUnknownProperties(t *testing.T) {
	ds := datastore.NewMemoryDataStore()

	err := ds.EnvMetadata().Set(datastore.EnvMetadata{
		Metadata: map[string]any{
			"externalConfig": map[string]any{"version": "1.0"},
		},
	})
	require.NoError(t, err)

	cfg := &config.GeneratedConfig{}
	err = deployments.SaveIndexerConfig(ds, "test-indexer", cfg)
	require.NoError(t, err)

	result := getMetadataAsMap(t, ds)
	assert.Contains(t, result, "externalConfig")
	assert.Contains(t, result, "offchainConfigs")

	externalConfig, ok := result["externalConfig"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "1.0", externalConfig["version"])
}

func TestMultipleSaves_PreservesAllUnknownProperties(t *testing.T) {
	ds := datastore.NewMemoryDataStore()

	err := ds.EnvMetadata().Set(datastore.EnvMetadata{
		Metadata: map[string]any{
			"domainA": map[string]any{"a": 1},
			"domainB": map[string]any{"b": 2},
		},
	})
	require.NoError(t, err)

	aggCfg := &model.Committee{
		QuorumConfigs: map[model.SourceSelector]*model.QuorumConfig{},
	}
	err = deployments.SaveAggregatorConfig(ds, "agg", aggCfg)
	require.NoError(t, err)

	idxCfg := &config.GeneratedConfig{}
	err = deployments.SaveIndexerConfig(ds, "idx", idxCfg)
	require.NoError(t, err)

	result := getMetadataAsMap(t, ds)
	assert.Contains(t, result, "domainA")
	assert.Contains(t, result, "domainB")
	assert.Contains(t, result, "offchainConfigs")
}

func getMetadataAsMap(t *testing.T, ds datastore.MutableDataStore) map[string]any {
	t.Helper()
	envMeta, err := ds.EnvMetadata().Get()
	require.NoError(t, err)

	data, err := json.Marshal(envMeta.Metadata)
	require.NoError(t, err)

	var result map[string]any
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	return result
}
