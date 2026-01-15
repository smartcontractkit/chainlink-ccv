package deployments

import (
	"encoding/json"
	"fmt"

	jsonpatch "github.com/evanphx/json-patch/v5"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
)

// OffchainConfigs contains generated configurations for offchain services.
// Uses the types from the aggregator and indexer packages directly.
type OffchainConfigs struct {
	// Aggregators maps service identifier (e.g., "default-aggregator") to generated committee config.
	Aggregators map[string]*model.Committee `json:"aggregators,omitempty"`
	// Indexers maps service identifier (e.g., "indexer") to generated verifier config.
	Indexers map[string]*config.GeneratedConfig `json:"indexers,omitempty"`
}

// CCVEnvMetadata represents the expected structure of env_metadata.json for CCV.
// OffchainConfigs stores generated configs after scanning on-chain state.
type CCVEnvMetadata struct {
	OffchainConfigs *OffchainConfigs `json:"offchainConfigs,omitempty"`
}

func loadCCVEnvMetadata(ds datastore.DataStore) (*CCVEnvMetadata, error) {
	envMeta, err := ds.EnvMetadata().Get()
	if err != nil {
		return nil, fmt.Errorf("failed to get env metadata: %w", err)
	}
	return parseCCVEnvMetadata(envMeta.Metadata)
}

func parseCCVEnvMetadata(metadata any) (*CCVEnvMetadata, error) {
	if metadata == nil {
		return &CCVEnvMetadata{}, nil
	}

	data, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal env metadata: %w", err)
	}

	var ccvMeta CCVEnvMetadata
	if err := json.Unmarshal(data, &ccvMeta); err != nil {
		return nil, fmt.Errorf("failed to unmarshal CCV env metadata: %w", err)
	}

	return &ccvMeta, nil
}

// SaveAggregatorConfig saves an aggregator committee config to the datastore under the given service identifier.
func SaveAggregatorConfig(ds datastore.MutableDataStore, serviceIdentifier string, cfg *model.Committee) error {
	ccvMeta, err := loadOrCreateCCVEnvMetadata(ds)
	if err != nil {
		return err
	}

	if ccvMeta.OffchainConfigs == nil {
		ccvMeta.OffchainConfigs = &OffchainConfigs{}
	}
	if ccvMeta.OffchainConfigs.Aggregators == nil {
		ccvMeta.OffchainConfigs.Aggregators = make(map[string]*model.Committee)
	}

	ccvMeta.OffchainConfigs.Aggregators[serviceIdentifier] = cfg

	return saveCCVEnvMetadata(ds, ccvMeta)
}

// SaveIndexerConfig saves an indexer generated config to the datastore under the given service identifier.
func SaveIndexerConfig(ds datastore.MutableDataStore, serviceIdentifier string, cfg *config.GeneratedConfig) error {
	ccvMeta, err := loadOrCreateCCVEnvMetadata(ds)
	if err != nil {
		return err
	}

	if ccvMeta.OffchainConfigs == nil {
		ccvMeta.OffchainConfigs = &OffchainConfigs{}
	}
	if ccvMeta.OffchainConfigs.Indexers == nil {
		ccvMeta.OffchainConfigs.Indexers = make(map[string]*config.GeneratedConfig)
	}

	ccvMeta.OffchainConfigs.Indexers[serviceIdentifier] = cfg

	return saveCCVEnvMetadata(ds, ccvMeta)
}

// GetAggregatorConfig retrieves an aggregator committee config from the datastore by service identifier.
func GetAggregatorConfig(ds datastore.DataStore, serviceIdentifier string) (*model.Committee, error) {
	ccvMeta, err := loadCCVEnvMetadata(ds)
	if err != nil {
		return nil, err
	}

	if ccvMeta.OffchainConfigs == nil || ccvMeta.OffchainConfigs.Aggregators == nil {
		return nil, fmt.Errorf("no aggregator configs found")
	}

	cfg, ok := ccvMeta.OffchainConfigs.Aggregators[serviceIdentifier]
	if !ok {
		return nil, fmt.Errorf("aggregator config %q not found", serviceIdentifier)
	}

	return cfg, nil
}

// GetIndexerConfig retrieves an indexer generated config from the datastore by service identifier.
func GetIndexerConfig(ds datastore.DataStore, serviceIdentifier string) (*config.GeneratedConfig, error) {
	ccvMeta, err := loadCCVEnvMetadata(ds)
	if err != nil {
		return nil, err
	}

	if ccvMeta.OffchainConfigs == nil || ccvMeta.OffchainConfigs.Indexers == nil {
		return nil, fmt.Errorf("no indexer configs found")
	}

	cfg, ok := ccvMeta.OffchainConfigs.Indexers[serviceIdentifier]
	if !ok {
		return nil, fmt.Errorf("indexer config %q not found", serviceIdentifier)
	}

	return cfg, nil
}

func loadOrCreateCCVEnvMetadata(ds datastore.MutableDataStore) (*CCVEnvMetadata, error) {
	envMeta, err := ds.EnvMetadata().Get()
	if err != nil {
		return &CCVEnvMetadata{}, nil
	}
	return parseCCVEnvMetadata(envMeta.Metadata)
}

func saveCCVEnvMetadata(ds datastore.MutableDataStore, ccvMeta *CCVEnvMetadata) error {
	var base json.RawMessage = []byte(`{}`)

	if envMeta, err := ds.EnvMetadata().Get(); err == nil && envMeta.Metadata != nil {
		b, err := json.Marshal(envMeta.Metadata)
		if err != nil {
			return err
		}
		base = b
	}

	patch, err := json.Marshal(ccvMeta)
	if err != nil {
		return err
	}

	merged, err := jsonpatch.MergePatch(base, patch)
	if err != nil {
		return err
	}

	var result map[string]any
	if err := json.Unmarshal(merged, &result); err != nil {
		return err
	}

	return ds.EnvMetadata().Set(datastore.EnvMetadata{Metadata: result})
}
