package deployment

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
	indexerconfig "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token"
)

type OffchainConfigs struct {
	Aggregators    map[string]*model.Committee               `json:"aggregators,omitempty"`
	Indexers       map[string]*indexerconfig.GeneratedConfig `json:"indexers,omitempty"`
	TokenVerifiers map[string]*token.Config                  `json:"tokenVerifiers,omitempty"`
	NOPJobs        shared.NOPJobs                            `json:"nopJobs,omitempty"`
	// NOPSigners maps NOP alias -> chain family -> signer address. It is the
	// persisted signer↔alias index that lets committee membership be reconstructed
	// from state for NOPs the Job Distributor does not manage (notably standalone
	// verifiers, which register only a CSA bootstrap key with JD).
	NOPSigners map[string]map[string]string `json:"nopSigners,omitempty"`
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

// MergeAggregatorConfig upserts cfg into the aggregator config already stored for
// serviceIdentifier: every source-chain quorum config and every destination
// verifier in cfg is added or overwritten, while entries for chains not present in
// cfg are preserved. When no config exists yet, cfg is stored as-is.
//
// This is the persistence primitive behind modular, per-chain generation: running
// GenerateAggregatorConfig once per chain (or per batch) accumulates into a single
// committee rather than replacing it, so onboarding a new chain does not require
// re-scanning every existing chain. Use SaveAggregatorConfig (full replace) when
// stale chains must be removed.
func MergeAggregatorConfig(ds datastore.MutableDataStore, serviceIdentifier string, cfg *model.Committee) error {
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

	ccvMeta.OffchainConfigs.Aggregators[serviceIdentifier] = mergeCommittees(
		ccvMeta.OffchainConfigs.Aggregators[serviceIdentifier], cfg,
	)

	return persistCCVEnvMetadata(ds, ccvMeta)
}

// mergeCommittees upserts incoming's quorum configs and destination verifiers over
// existing's, returning the combined committee. Keys present only in existing are
// preserved; keys present in both take incoming's value. The inputs are not
// mutated. If either argument is nil, the other is returned as-is.
func mergeCommittees(existing, incoming *model.Committee) *model.Committee {
	if existing == nil {
		return incoming
	}
	if incoming == nil {
		return existing
	}

	merged := &model.Committee{
		QuorumConfigs:        make(map[string]*model.QuorumConfig, len(existing.QuorumConfigs)+len(incoming.QuorumConfigs)),
		DestinationVerifiers: make(map[string]string, len(existing.DestinationVerifiers)+len(incoming.DestinationVerifiers)),
	}

	maps.Copy(merged.QuorumConfigs, existing.QuorumConfigs)
	maps.Copy(merged.DestinationVerifiers, existing.DestinationVerifiers)
	maps.Copy(merged.QuorumConfigs, incoming.QuorumConfigs)
	maps.Copy(merged.DestinationVerifiers, incoming.DestinationVerifiers)

	return merged
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

// MergeIndexerConfig upserts cfg into the indexer config already stored for
// serviceIdentifier: verifiers are merged by Name (entries in cfg add or replace
// those with the same Name), while verifiers not present in cfg are preserved.
// When no config exists yet, cfg is stored as-is.
//
// This lets indexer config be generated modularly — once per verifier set — and
// accumulate into a single config. Use SaveIndexerConfig (full replace) when
// stale verifiers must be removed.
func MergeIndexerConfig(ds datastore.MutableDataStore, serviceIdentifier string, cfg *indexerconfig.GeneratedConfig) error {
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

	ccvMeta.OffchainConfigs.Indexers[serviceIdentifier] = mergeIndexerConfigs(
		ccvMeta.OffchainConfigs.Indexers[serviceIdentifier], cfg,
	)

	return persistCCVEnvMetadata(ds, ccvMeta)
}

// mergeIndexerConfigs upserts incoming's verifiers over existing's, keyed by Name,
// returning the combined config. Existing order is preserved; new names are
// appended. The inputs are not mutated. If either argument is nil, the other is
// returned as-is.
func mergeIndexerConfigs(existing, incoming *indexerconfig.GeneratedConfig) *indexerconfig.GeneratedConfig {
	if existing == nil {
		return incoming
	}
	if incoming == nil {
		return existing
	}

	order := make([]string, 0, len(existing.Verifier)+len(incoming.Verifier))
	byName := make(map[string]indexerconfig.GeneratedVerifierConfig, len(existing.Verifier)+len(incoming.Verifier))
	for _, v := range existing.Verifier {
		if _, ok := byName[v.Name]; !ok {
			order = append(order, v.Name)
		}
		byName[v.Name] = v
	}
	for _, v := range incoming.Verifier {
		if _, ok := byName[v.Name]; !ok {
			order = append(order, v.Name)
		}
		byName[v.Name] = v
	}

	merged := make([]indexerconfig.GeneratedVerifierConfig, 0, len(order))
	for _, name := range order {
		merged = append(merged, byName[name])
	}

	return &indexerconfig.GeneratedConfig{Verifier: merged}
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

// MergeTokenVerifierConfig upserts cfg into the token-verifier config already
// stored for serviceIdentifier. The per-chain data accumulates: the
// CommitteeConfig on-ramp / RMN-remote maps are merged by chain selector, and each
// token verifier (matched by VerifierID) has its per-chain verifier and
// verifier-resolver address maps merged by chain selector. Config-wide fields
// (PyroscopeURL, Monitoring) and per-verifier scalars take the latest run's value.
// Verifiers and chains not present in cfg are preserved. When no config exists yet,
// cfg is stored as-is.
//
// This lets token-verifier config be generated modularly — once per chain (or per
// batch) — and accumulate into one config. Use SaveTokenVerifierConfig (full
// replace) when stale chains or verifiers must be removed.
func MergeTokenVerifierConfig(ds datastore.MutableDataStore, serviceIdentifier string, cfg *token.Config) error {
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

	ccvMeta.OffchainConfigs.TokenVerifiers[serviceIdentifier] = mergeTokenConfigs(
		ccvMeta.OffchainConfigs.TokenVerifiers[serviceIdentifier], cfg,
	)

	return persistCCVEnvMetadata(ds, ccvMeta)
}

// mergeTokenConfigs upserts incoming's per-chain data over existing's, returning
// the combined config. The inputs are not mutated. If either argument is nil, the
// other is returned as-is.
func mergeTokenConfigs(existing, incoming *token.Config) *token.Config {
	if existing == nil {
		return incoming
	}
	if incoming == nil {
		return existing
	}

	return &token.Config{
		// Config-wide fields take the latest run's value.
		PyroscopeURL: incoming.PyroscopeURL,
		Monitoring:   incoming.Monitoring,
		CommitteeConfig: chainaccess.CommitteeConfig{
			OnRampAddresses:    mergeStringMaps(existing.OnRampAddresses, incoming.OnRampAddresses),
			RMNRemoteAddresses: mergeStringMaps(existing.RMNRemoteAddresses, incoming.RMNRemoteAddresses),
		},
		TokenVerifiers: mergeTokenVerifiers(existing.TokenVerifiers, incoming.TokenVerifiers),
	}
}

// mergeTokenVerifiers upserts incoming verifiers over existing ones, keyed by
// VerifierID. Matching verifiers have their per-chain address maps merged; new
// VerifierIDs are appended. Existing order is preserved.
func mergeTokenVerifiers(existing, incoming []token.VerifierConfig) []token.VerifierConfig {
	order := make([]string, 0, len(existing)+len(incoming))
	byID := make(map[string]token.VerifierConfig, len(existing)+len(incoming))
	for _, vc := range existing {
		if _, ok := byID[vc.VerifierID]; !ok {
			order = append(order, vc.VerifierID)
		}
		byID[vc.VerifierID] = vc
	}
	for _, vc := range incoming {
		if prev, ok := byID[vc.VerifierID]; ok {
			byID[vc.VerifierID] = mergeVerifierConfig(prev, vc)
		} else {
			order = append(order, vc.VerifierID)
			byID[vc.VerifierID] = vc
		}
	}

	merged := make([]token.VerifierConfig, 0, len(order))
	for _, id := range order {
		merged = append(merged, byID[id])
	}

	return merged
}

// mergeVerifierConfig takes incoming's scalar fields and merges the per-chain
// address maps of its CCTP / Lombard sub-configs with existing's.
func mergeVerifierConfig(existing, incoming token.VerifierConfig) token.VerifierConfig {
	merged := incoming
	if existing.CCTPConfig != nil && incoming.CCTPConfig != nil {
		ec, ic := existing.CCTPConfig, incoming.CCTPConfig
		cctpCfg := *ic
		cctpCfg.Verifiers = mergeAnyMaps(ec.Verifiers, ic.Verifiers)
		cctpCfg.VerifierResolvers = mergeAnyMaps(ec.VerifierResolvers, ic.VerifierResolvers)
		merged.CCTPConfig = &cctpCfg
	}
	if existing.LombardConfig != nil && incoming.LombardConfig != nil {
		el, il := existing.LombardConfig, incoming.LombardConfig
		lombardCfg := *il
		lombardCfg.VerifierResolvers = mergeAnyMaps(el.VerifierResolvers, il.VerifierResolvers)
		merged.LombardConfig = &lombardCfg
	}

	return merged
}

func mergeStringMaps(existing, incoming map[string]string) map[string]string {
	if existing == nil && incoming == nil {
		return nil
	}
	merged := make(map[string]string, len(existing)+len(incoming))
	maps.Copy(merged, existing)
	maps.Copy(merged, incoming)

	return merged
}

func mergeAnyMaps(existing, incoming map[string]any) map[string]any {
	if existing == nil && incoming == nil {
		return nil
	}
	merged := make(map[string]any, len(existing)+len(incoming))
	maps.Copy(merged, existing)
	maps.Copy(merged, incoming)

	return merged
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
		{"nopSigners", oc.NOPSigners, "NOP signers"},
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

// SaveNOPSigners merges the given NOP alias -> chain family -> signer address
// index into the datastore. Existing entries are preserved; incoming non-empty
// addresses overwrite per (alias, family). Persisting the signer↔alias mapping is
// what allows committee membership to be reconstructed from state for NOPs the Job
// Distributor does not manage (e.g. standalone verifiers).
func SaveNOPSigners(ds datastore.MutableDataStore, signers map[string]map[string]string) error {
	if len(signers) == 0 {
		return nil
	}

	ccvMeta, err := loadOrCreateCCVEnvMetadata(ds)
	if err != nil {
		return err
	}

	if ccvMeta.OffchainConfigs == nil {
		ccvMeta.OffchainConfigs = &OffchainConfigs{}
	}
	if ccvMeta.OffchainConfigs.NOPSigners == nil {
		ccvMeta.OffchainConfigs.NOPSigners = make(map[string]map[string]string)
	}

	for alias, byFamily := range signers {
		if ccvMeta.OffchainConfigs.NOPSigners[alias] == nil {
			ccvMeta.OffchainConfigs.NOPSigners[alias] = make(map[string]string)
		}
		for family, addr := range byFamily {
			if addr == "" {
				continue
			}
			ccvMeta.OffchainConfigs.NOPSigners[alias][family] = addr
		}
	}

	return persistCCVEnvMetadata(ds, ccvMeta)
}

// GetNOPSigners returns the persisted NOP alias -> chain family -> signer address
// index. Returns an empty map (not an error) when no metadata or index exists yet.
func GetNOPSigners(ds datastore.DataStore) (map[string]map[string]string, error) {
	ccvMeta, err := loadCCVEnvMetadata(ds)
	if err != nil {
		if errors.Is(err, datastore.ErrEnvMetadataNotSet) {
			return make(map[string]map[string]string), nil
		}
		return nil, err
	}
	if ccvMeta.OffchainConfigs == nil || ccvMeta.OffchainConfigs.NOPSigners == nil {
		return make(map[string]map[string]string), nil
	}
	return ccvMeta.OffchainConfigs.NOPSigners, nil
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
