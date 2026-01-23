package deployments

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"

	jsonpatch "github.com/evanphx/json-patch/v5"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/deployments/operations/shared"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

// OffchainConfigs contains generated configurations for offchain services.
// Uses the types from the aggregator and indexer packages directly.
type OffchainConfigs struct {
	// Aggregators maps service identifier (e.g., "default-aggregator") to generated committee config.
	Aggregators map[string]*model.Committee `json:"aggregators,omitempty"`
	// Indexers maps service identifier (e.g., "indexer") to generated verifier config.
	Indexers map[string]*config.GeneratedConfig `json:"indexers,omitempty"`
	// NOPJobSpecs maps NOP alias to a map of job spec ID to job spec TOML.
	// This groups all job specs (verifier, executor) for a given NOP together.
	NOPJobSpecs shared.NOPJobSpecs `json:"nopJobSpecs,omitempty"`
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

// SaveNOPJobSpec saves a job spec to the datastore under the given NOP alias and job spec ID.
// This allows grouping all job specs (verifier, executor) for a given NOP together.
func SaveNOPJobSpec(ds datastore.MutableDataStore, nopAlias shared.NOPAlias, jobSpecID shared.JobID, jobSpec string) error {
	ccvMeta, err := loadOrCreateCCVEnvMetadata(ds)
	if err != nil {
		return err
	}

	if ccvMeta.OffchainConfigs == nil {
		ccvMeta.OffchainConfigs = &OffchainConfigs{}
	}
	if ccvMeta.OffchainConfigs.NOPJobSpecs == nil {
		ccvMeta.OffchainConfigs.NOPJobSpecs = make(shared.NOPJobSpecs)
	}
	if ccvMeta.OffchainConfigs.NOPJobSpecs[nopAlias] == nil {
		ccvMeta.OffchainConfigs.NOPJobSpecs[nopAlias] = make(map[shared.JobID]string)
	}

	ccvMeta.OffchainConfigs.NOPJobSpecs[nopAlias][jobSpecID] = jobSpec

	return saveCCVEnvMetadata(ds, ccvMeta)
}

// GetNOPJobSpec retrieves a specific job spec from the datastore by NOP alias and job spec ID.
func GetNOPJobSpec(ds datastore.DataStore, nopAlias shared.NOPAlias, jobSpecID shared.JobID) (string, error) {
	ccvMeta, err := loadCCVEnvMetadata(ds)
	if err != nil {
		return "", err
	}

	if ccvMeta.OffchainConfigs == nil || ccvMeta.OffchainConfigs.NOPJobSpecs == nil {
		return "", fmt.Errorf("no NOP job specs found")
	}

	nopSpecs, ok := ccvMeta.OffchainConfigs.NOPJobSpecs[nopAlias]
	if !ok {
		return "", fmt.Errorf("no job specs found for NOP %q", nopAlias)
	}

	jobSpec, ok := nopSpecs[jobSpecID]
	if !ok {
		return "", fmt.Errorf("job spec %q not found for NOP %q", jobSpecID, nopAlias)
	}

	return jobSpec, nil
}

// GetNOPJobSpecs retrieves all job specs for a given NOP alias.
func GetNOPJobSpecs(ds datastore.DataStore, nopAlias shared.NOPAlias) (map[shared.JobID]string, error) {
	ccvMeta, err := loadCCVEnvMetadata(ds)
	if err != nil {
		return nil, err
	}

	if ccvMeta.OffchainConfigs == nil || ccvMeta.OffchainConfigs.NOPJobSpecs == nil {
		return nil, fmt.Errorf("no NOP job specs found")
	}

	nopSpecs, ok := ccvMeta.OffchainConfigs.NOPJobSpecs[nopAlias]
	if !ok {
		return nil, fmt.Errorf("no job specs found for NOP %q", nopAlias)
	}

	return nopSpecs, nil
}

// GetAllNOPJobSpecs retrieves all NOP job specs from the datastore.
// Returns a map of NOP alias to map of job spec ID to job spec content.
// Returns an empty map (not error) if no job specs exist.
func GetAllNOPJobSpecs(ds datastore.DataStore) (shared.NOPJobSpecs, error) {
	ccvMeta, err := loadCCVEnvMetadata(ds)
	if err != nil {
		return nil, err
	}

	if ccvMeta.OffchainConfigs == nil || ccvMeta.OffchainConfigs.NOPJobSpecs == nil {
		return make(shared.NOPJobSpecs), nil
	}

	return ccvMeta.OffchainConfigs.NOPJobSpecs, nil
}

// DeleteNOPJobSpec removes a specific job spec from the datastore by NOP alias and job spec ID.
// Returns nil if the job spec doesn't exist (idempotent delete).
func DeleteNOPJobSpec(ds datastore.MutableDataStore, nopAlias shared.NOPAlias, jobSpecID shared.JobID) error {
	ccvMeta, err := loadOrCreateCCVEnvMetadata(ds)
	if err != nil {
		return err
	}

	if ccvMeta.OffchainConfigs == nil || ccvMeta.OffchainConfigs.NOPJobSpecs == nil {
		return nil // Nothing to delete
	}

	nopSpecs, ok := ccvMeta.OffchainConfigs.NOPJobSpecs[nopAlias]
	if !ok {
		return nil // NOP not found, nothing to delete
	}

	if _, ok := nopSpecs[jobSpecID]; !ok {
		return nil // Job spec not found, nothing to delete
	}

	delete(ccvMeta.OffchainConfigs.NOPJobSpecs[nopAlias], jobSpecID)

	// Clean up empty NOP entry
	if len(ccvMeta.OffchainConfigs.NOPJobSpecs[nopAlias]) == 0 {
		delete(ccvMeta.OffchainConfigs.NOPJobSpecs, nopAlias)
	}

	// Use full replacement instead of merge patch to properly handle deletions
	return replaceCCVEnvMetadata(ds, ccvMeta)
}

// SaveNOPJobSpecs saves multiple job specs to the datastore in a single operation.
// The input is a map of NOP alias to a map of job spec ID to job spec content.
func SaveNOPJobSpecs(ds datastore.MutableDataStore, jobSpecs shared.NOPJobSpecs) error {
	if len(jobSpecs) == 0 {
		return nil
	}

	ccvMeta, err := loadOrCreateCCVEnvMetadata(ds)
	if err != nil {
		return err
	}

	if ccvMeta.OffchainConfigs == nil {
		ccvMeta.OffchainConfigs = &OffchainConfigs{}
	}
	if ccvMeta.OffchainConfigs.NOPJobSpecs == nil {
		ccvMeta.OffchainConfigs.NOPJobSpecs = make(shared.NOPJobSpecs)
	}

	for nopAlias, specs := range jobSpecs {
		if ccvMeta.OffchainConfigs.NOPJobSpecs[nopAlias] == nil {
			ccvMeta.OffchainConfigs.NOPJobSpecs[nopAlias] = make(map[shared.JobID]string)
		}
		maps.Copy(ccvMeta.OffchainConfigs.NOPJobSpecs[nopAlias], specs)
	}

	return saveCCVEnvMetadata(ds, ccvMeta)
}

// CleanupOrphanedJobSpecs removes job specs that match the given suffix but are not in the expected set.
// Parameters:
//   - ds: the datastore to modify
//   - suffix: the suffix pattern to match (e.g., "-default-executor")
//   - expectedJobSpecIDs: set of job spec IDs that should be kept
//   - scopedNOPs: if non-nil, only cleanup NOPs in this set; if nil, cleanup all NOPs
func CleanupOrphanedJobSpecs(
	ds datastore.MutableDataStore,
	scope shared.JobScope,
	expectedJobIDs []shared.JobID,
	scopedNOPs map[shared.NOPAlias]bool,
	environmentNOPs map[shared.NOPAlias]bool,
) error {
	allNOPJobSpecs, err := GetAllNOPJobSpecs(ds.Seal())
	if err != nil {
		return fmt.Errorf("failed to get all NOP job specs for cleanup: %w", err)
	}

	for nopAlias, jobSpecs := range allNOPJobSpecs {
		if scopedNOPs != nil && !scopedNOPs[nopAlias] {
			continue
		}

		for jobSpecID := range jobSpecs {
			if !scope.IsJobInScope(jobSpecID) {
				continue
			}

			shouldDelete := !slices.Contains(expectedJobIDs, jobSpecID)
			if environmentNOPs != nil && !environmentNOPs[nopAlias] {
				shouldDelete = true
			}

			if shouldDelete {
				if err := DeleteNOPJobSpec(ds, nopAlias, jobSpecID); err != nil {
					return fmt.Errorf("failed to delete orphaned job spec %q for NOP %q: %w", jobSpecID, nopAlias, err)
				}
			}
		}
	}

	return nil
}

// replaceCCVEnvMetadata replaces the CCV metadata completely (not merge).
// This is needed for delete operations since JSON Merge Patch doesn't remove missing keys.
func replaceCCVEnvMetadata(ds datastore.MutableDataStore, ccvMeta *CCVEnvMetadata) error {
	// Get existing metadata to preserve non-CCV fields
	var existingMeta map[string]any
	if envMeta, err := ds.EnvMetadata().Get(); err == nil && envMeta.Metadata != nil {
		data, err := json.Marshal(envMeta.Metadata)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &existingMeta); err != nil {
			return err
		}
	} else {
		existingMeta = make(map[string]any)
	}

	// Marshal the CCV metadata
	ccvData, err := json.Marshal(ccvMeta)
	if err != nil {
		return err
	}

	var ccvMap map[string]any
	if err := json.Unmarshal(ccvData, &ccvMap); err != nil {
		return err
	}

	// Replace CCV-specific fields (offchainConfigs) completely
	maps.Copy(existingMeta, ccvMap)

	return ds.EnvMetadata().Set(datastore.EnvMetadata{Metadata: existingMeta})
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
