package deployment

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
	indexerconfig "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token"
)

type OffchainConfigs struct {
	Aggregators    map[string]*model.Committee               `json:"aggregators,omitempty"`
	Indexers       map[string]*indexerconfig.GeneratedConfig `json:"indexers,omitempty"`
	TokenVerifiers map[string]*token.Config                  `json:"tokenVerifiers,omitempty"`
	NOPJobs        shared.NOPJobs                            `json:"nopJobs,omitempty"`
}

type CCVEnvMetadata struct {
	OffchainConfigs *OffchainConfigs `json:"offchainConfigs,omitempty"`
}

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

	return persistCCVEnvMetadata(ds, ccvMeta)
}

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

func SaveIndexerConfig(ds datastore.MutableDataStore, serviceIdentifier string, cfg *indexerconfig.GeneratedConfig) error {
	ccvMeta, err := loadOrCreateCCVEnvMetadata(ds)
	if err != nil {
		return err
	}

	if ccvMeta.OffchainConfigs == nil {
		ccvMeta.OffchainConfigs = &OffchainConfigs{}
	}
	if ccvMeta.OffchainConfigs.Indexers == nil {
		ccvMeta.OffchainConfigs.Indexers = make(map[string]*indexerconfig.GeneratedConfig)
	}

	ccvMeta.OffchainConfigs.Indexers[serviceIdentifier] = cfg

	return persistCCVEnvMetadata(ds, ccvMeta)
}

func GetIndexerConfig(ds datastore.DataStore, serviceIdentifier string) (*indexerconfig.GeneratedConfig, error) {
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

func SaveTokenVerifierConfig(ds datastore.MutableDataStore, serviceIdentifier string, cfg *token.Config) error {
	ccvMeta, err := loadOrCreateCCVEnvMetadata(ds)
	if err != nil {
		return err
	}

	if ccvMeta.OffchainConfigs == nil {
		ccvMeta.OffchainConfigs = &OffchainConfigs{}
	}
	if ccvMeta.OffchainConfigs.TokenVerifiers == nil {
		ccvMeta.OffchainConfigs.TokenVerifiers = make(map[string]*token.Config)
	}

	ccvMeta.OffchainConfigs.TokenVerifiers[serviceIdentifier] = cfg

	return persistCCVEnvMetadata(ds, ccvMeta)
}

func GetTokenVerifierConfig(ds datastore.DataStore, serviceIdentifier string) (*token.Config, error) {
	ccvMeta, err := loadCCVEnvMetadata(ds)
	if err != nil {
		return nil, err
	}

	if ccvMeta.OffchainConfigs == nil || ccvMeta.OffchainConfigs.TokenVerifiers == nil {
		return nil, fmt.Errorf("no token verifier configs found")
	}

	cfg, ok := ccvMeta.OffchainConfigs.TokenVerifiers[serviceIdentifier]
	if !ok {
		return nil, fmt.Errorf("token verifier config %q not found", serviceIdentifier)
	}

	return cfg, nil
}

func loadCCVEnvMetadata(ds datastore.DataStore) (*CCVEnvMetadata, error) {
	envMeta, err := ds.EnvMetadata().Get()
	if err != nil {
		return nil, fmt.Errorf("failed to get env metadata: %w", err)
	}
	return parseCCVEnvMetadata(envMeta.Metadata)
}

func loadOrCreateCCVEnvMetadata(ds datastore.MutableDataStore) (*CCVEnvMetadata, error) {
	envMeta, err := ds.EnvMetadata().Get()
	if err != nil {
		if errors.Is(err, datastore.ErrEnvMetadataNotSet) {
			return &CCVEnvMetadata{}, nil
		}
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

// persistCCVEnvMetadata persists CCV metadata using shallow merge at the
// offchainConfigs level. Known offchainConfigs keys (aggregators, indexers,
// tokenVerifiers, nopJobs) are replaced fully — removing stale nested entries
// when chains or jobs are removed. Unknown sibling keys under offchainConfigs
// and non-CCV top-level keys are preserved.
func persistCCVEnvMetadata(ds datastore.MutableDataStore, ccvMeta *CCVEnvMetadata) error {
	existingMeta, err := loadExistingEnvMetadata(ds)
	if err != nil {
		return err
	}

	if ccvMeta.OffchainConfigs != nil {
		existingOC, err := mergeOffchainConfigs(existingMeta, ccvMeta.OffchainConfigs)
		if err != nil {
			return err
		}
		existingMeta["offchainConfigs"] = existingOC
	}

	return ds.EnvMetadata().Set(datastore.EnvMetadata{Metadata: existingMeta})
}

// loadExistingEnvMetadata reads the current env metadata as a generic map so it can
// be shallow-merged with new CCV values. A missing or nil metadata is returned as an
// empty map.
func loadExistingEnvMetadata(ds datastore.MutableDataStore) (map[string]any, error) {
	envMeta, err := ds.EnvMetadata().Get()
	if err != nil {
		if errors.Is(err, datastore.ErrEnvMetadataNotSet) {
			return make(map[string]any), nil
		}
		return nil, fmt.Errorf("failed to get env metadata: %w", err)
	}
	if envMeta.Metadata == nil {
		return make(map[string]any), nil
	}

	data, err := json.Marshal(envMeta.Metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal existing env metadata: %w", err)
	}
	var existingMeta map[string]any
	if err := json.Unmarshal(data, &existingMeta); err != nil {
		return nil, fmt.Errorf("failed to unmarshal existing env metadata: %w", err)
	}
	return existingMeta, nil
}

// mergeOffchainConfigs merges the non-nil fields of oc into the offchainConfigs sub-map of
// existingMeta. Unknown sibling keys already present under offchainConfigs are preserved.
func mergeOffchainConfigs(existingMeta map[string]any, oc *OffchainConfigs) (map[string]any, error) {
	existingOC, ok := existingMeta["offchainConfigs"].(map[string]any)
	if !ok {
		existingOC = make(map[string]any)
	}

	type entry struct {
		key   string
		value any
		label string
	}
	entries := []entry{
		{"aggregators", oc.Aggregators, "aggregators"},
		{"indexers", oc.Indexers, "indexers"},
		{"tokenVerifiers", oc.TokenVerifiers, "token verifiers"},
		{"nopJobs", oc.NOPJobs, "NOP jobs"},
	}

	for _, e := range entries {
		if isNilValue(e.value) {
			continue
		}
		v, err := marshalToAny(e.value)
		if err != nil {
			return nil, fmt.Errorf("failed to convert %s: %w", e.label, err)
		}
		existingOC[e.key] = v
	}

	return existingOC, nil
}

// isNilValue reports whether v is an untyped nil or a typed nil reference value
// (map, slice, pointer, interface, channel, or func). It uses reflection so callers
// don't need to be updated when OffchainConfigs gains new map fields.
func isNilValue(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Map, reflect.Slice, reflect.Pointer, reflect.Interface, reflect.Chan, reflect.Func:
		return rv.IsNil()
	default:
		return false
	}
}

func marshalToAny(v any) (any, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal value: %w", err)
	}
	var result any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal value: %w", err)
	}
	return result, nil
}

func SaveJob(ds datastore.MutableDataStore, job shared.JobInfo) error {
	ccvMeta, err := loadOrCreateCCVEnvMetadata(ds)
	if err != nil {
		return err
	}

	if ccvMeta.OffchainConfigs == nil {
		ccvMeta.OffchainConfigs = &OffchainConfigs{}
	}
	if ccvMeta.OffchainConfigs.NOPJobs == nil {
		ccvMeta.OffchainConfigs.NOPJobs = make(shared.NOPJobs)
	}
	if ccvMeta.OffchainConfigs.NOPJobs[job.NOPAlias] == nil {
		ccvMeta.OffchainConfigs.NOPJobs[job.NOPAlias] = make(map[shared.JobID]shared.JobInfo)
	}

	ccvMeta.OffchainConfigs.NOPJobs[job.NOPAlias][job.JobID] = job

	return persistCCVEnvMetadata(ds, ccvMeta)
}

func SaveJobs(ds datastore.MutableDataStore, jobs []shared.JobInfo) error {
	if len(jobs) == 0 {
		return nil
	}

	ccvMeta, err := loadOrCreateCCVEnvMetadata(ds)
	if err != nil {
		return err
	}

	if ccvMeta.OffchainConfigs == nil {
		ccvMeta.OffchainConfigs = &OffchainConfigs{}
	}
	if ccvMeta.OffchainConfigs.NOPJobs == nil {
		ccvMeta.OffchainConfigs.NOPJobs = make(shared.NOPJobs)
	}

	for _, job := range jobs {
		if ccvMeta.OffchainConfigs.NOPJobs[job.NOPAlias] == nil {
			ccvMeta.OffchainConfigs.NOPJobs[job.NOPAlias] = make(map[shared.JobID]shared.JobInfo)
		}
		ccvMeta.OffchainConfigs.NOPJobs[job.NOPAlias][job.JobID] = job
	}

	return persistCCVEnvMetadata(ds, ccvMeta)
}

func GetAllJobs(ds datastore.DataStore) (shared.NOPJobs, error) {
	ccvMeta, err := loadCCVEnvMetadata(ds)
	if err != nil {
		return nil, err
	}

	if ccvMeta.OffchainConfigs == nil || ccvMeta.OffchainConfigs.NOPJobs == nil {
		return make(shared.NOPJobs), nil
	}

	return ccvMeta.OffchainConfigs.NOPJobs, nil
}

func GetJob(ds datastore.DataStore, nopAlias shared.NOPAlias, jobID shared.JobID) (*shared.JobInfo, error) {
	ccvMeta, err := loadCCVEnvMetadata(ds)
	if err != nil {
		return nil, err
	}

	if ccvMeta.OffchainConfigs == nil || ccvMeta.OffchainConfigs.NOPJobs == nil {
		return nil, fmt.Errorf("no jobs found")
	}

	nopJobs, ok := ccvMeta.OffchainConfigs.NOPJobs[nopAlias]
	if !ok {
		return nil, fmt.Errorf("no jobs found for NOP %q", nopAlias)
	}

	job, ok := nopJobs[jobID]
	if !ok {
		return nil, fmt.Errorf("job %q not found for NOP %q", jobID, nopAlias)
	}

	return &job, nil
}

func DeleteJob(ds datastore.MutableDataStore, nopAlias shared.NOPAlias, jobID shared.JobID) error {
	ccvMeta, err := loadOrCreateCCVEnvMetadata(ds)
	if err != nil {
		return err
	}

	if ccvMeta.OffchainConfigs == nil || ccvMeta.OffchainConfigs.NOPJobs == nil {
		return nil
	}

	nopJobs, ok := ccvMeta.OffchainConfigs.NOPJobs[nopAlias]
	if !ok {
		return nil
	}

	if _, ok := nopJobs[jobID]; !ok {
		return nil
	}

	delete(ccvMeta.OffchainConfigs.NOPJobs[nopAlias], jobID)

	if len(ccvMeta.OffchainConfigs.NOPJobs[nopAlias]) == 0 {
		delete(ccvMeta.OffchainConfigs.NOPJobs, nopAlias)
	}

	return persistCCVEnvMetadata(ds, ccvMeta)
}

func CollectOrphanedJobs(
	ds datastore.DataStore,
	scope shared.JobScope,
	expectedJobsByNOP map[shared.NOPAlias]map[shared.JobID]bool,
	scopedNOPs map[shared.NOPAlias]bool,
	environmentNOPs map[shared.NOPAlias]bool,
) ([]shared.JobInfo, error) {
	allJobs, err := GetAllJobs(ds)
	if err != nil {
		return nil, fmt.Errorf("failed to get all jobs for cleanup: %w", err)
	}

	orphaned := make([]shared.JobInfo, 0)
	for nopAlias, nopJobs := range allJobs {
		if scopedNOPs != nil && !scopedNOPs[nopAlias] {
			continue
		}

		for jobID, job := range nopJobs {
			if !scope.IsJobInScope(jobID) {
				continue
			}

			nopExpectedJobs := expectedJobsByNOP[nopAlias]
			shouldRevoke := nopExpectedJobs == nil || !nopExpectedJobs[jobID]
			if environmentNOPs != nil && !environmentNOPs[nopAlias] {
				shouldRevoke = true
			}

			if shouldRevoke {
				orphaned = append(orphaned, job)
			}
		}
	}

	return orphaned, nil
}

func CleanupOrphanedJobs(
	ds datastore.MutableDataStore,
	jobs []shared.JobInfo,
) error {
	for _, job := range jobs {
		if err := DeleteJob(ds, job.NOPAlias, job.JobID); err != nil {
			return fmt.Errorf("failed to delete job %q for NOP %q: %w", job.JobID, job.NOPAlias, err)
		}
	}
	return nil
}
