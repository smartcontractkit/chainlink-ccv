package changesets

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/BurntSushi/toml"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	"github.com/smartcontractkit/chainlink-ccv/executor"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

// ExecutorConnExtras carries the executor connection settings recovered alongside
// the pool from persisted job specs: these are not part of ExecutorPoolInput but
// are needed to rebuild a full ApplyExecutorConfigInput.
type ExecutorConnExtras struct {
	IndexerAddress []string
	PyroscopeURL   string
	Monitoring     ccvdeployment.MonitoringConfig
}

// ExecutorPoolInputFromState reconstructs the executor pool input from the
// executor job specs previously published for the qualifier and persisted in the
// datastore — the state analog of ExecutorPoolInputFromTopology.
//
// Unlike committee membership (which is read on-chain), an executor pool has no
// meaningful on-chain footprint: its membership, per-chain execution interval,
// and all pool-wide tuning live in the published job config. Those specs are the
// source of truth, so everything is recovered from them and nothing needs to be
// re-supplied. The connection settings (indexer addresses, pyroscope URL,
// monitoring) are returned separately via ExecutorConnExtras.
//
// Pool-wide tuning and connection settings are taken from the first job in scope
// (they are identical across a pool's NOPs); per-chain membership and interval are
// merged across all in-scope jobs. When no executor jobs exist yet (bootstrap) the
// result is an empty pool and zero-value extras.
func ExecutorPoolInputFromState(ds datastore.DataStore, qualifier string) (ExecutorPoolInput, ExecutorConnExtras, error) {
	pool := ExecutorPoolInput{ChainConfigs: make(map[uint64]ChainExecutorPoolMembership)}
	var extras ExecutorConnExtras

	allJobs, err := ccvdeployment.GetAllJobs(ds)
	if err != nil {
		// A store with no env metadata yet (bootstrap / nothing published) has no
		// jobs — return an empty pool rather than failing.
		if errors.Is(err, datastore.ErrEnvMetadataNotSet) {
			return pool, extras, nil
		}
		return pool, extras, fmt.Errorf("executor pool %q: failed to load jobs from datastore: %w", qualifier, err)
	}

	scope := shared.ExecutorJobScope{ExecutorQualifier: qualifier}
	poolWideSet := false

	for _, byJobID := range allJobs {
		for jobID, info := range byJobID {
			if !scope.IsJobInScope(jobID) {
				continue
			}

			cfg, err := parseExecutorConfigFromSpec(info.Spec)
			if err != nil {
				return pool, extras, fmt.Errorf("executor pool %q: job %q: %w", qualifier, jobID, err)
			}

			if !poolWideSet {
				pool.IndexerQueryLimit = cfg.IndexerQueryLimit
				pool.BackoffDuration = cfg.BackoffDuration
				pool.LookbackWindow = cfg.LookbackWindow
				pool.ReaderCacheExpiry = cfg.ReaderCacheExpiry
				pool.MaxRetryDuration = cfg.MaxRetryDuration
				pool.WorkerCount = cfg.WorkerCount
				pool.NtpServer = cfg.NtpServer
				extras.IndexerAddress = cfg.IndexerAddress
				extras.PyroscopeURL = cfg.PyroscopeURL
				extras.Monitoring = cfg.Monitoring
				poolWideSet = true
			}

			for selStr, cc := range cfg.ChainConfiguration {
				sel, perr := strconv.ParseUint(selStr, 10, 64)
				if perr != nil {
					return pool, extras, fmt.Errorf("executor pool %q: job %q: invalid chain selector key %q: %w", qualifier, jobID, selStr, perr)
				}
				pool.ChainConfigs[sel] = ChainExecutorPoolMembership{
					NOPAliases:        shared.ConvertStringToNopAliases(cc.ExecutorPool),
					ExecutionInterval: cc.ExecutionInterval,
				}
			}
		}
	}

	return pool, extras, nil
}

// parseExecutorConfigFromSpec extracts the embedded executor.Configuration from a
// ccvexecutor job spec. The spec is a TOML wrapper whose executorConfig field
// holds the inner config as a multi-line string; both are parsed with the same
// library buildExecutorJobSpecs used to emit them, so the round-trip is lossless.
func parseExecutorConfigFromSpec(spec string) (executor.Configuration, error) {
	var wrapper struct {
		Type           string `toml:"type"`
		ExecutorConfig string `toml:"executorConfig"`
	}
	if _, err := toml.Decode(spec, &wrapper); err != nil {
		return executor.Configuration{}, fmt.Errorf("failed to parse job spec wrapper: %w", err)
	}
	if wrapper.ExecutorConfig == "" {
		return executor.Configuration{}, fmt.Errorf("job spec has no executorConfig block")
	}

	var cfg executor.Configuration
	if _, err := toml.Decode(wrapper.ExecutorConfig, &cfg); err != nil {
		return executor.Configuration{}, fmt.Errorf("failed to parse executor config: %w", err)
	}
	return cfg, nil
}

// ExecutorConfigFromStateOptions carries the few executor inputs that are not
// recovered from state: publish-time flags and optional overrides.
type ExecutorConfigFromStateOptions struct {
	// ModeByNOP overrides the per-NOP mode (defaults to CL when absent).
	ModeByNOP map[shared.NOPAlias]shared.NOPMode
	// TargetNOPs filters the publish set. Empty means "all NOPs in the pool".
	TargetNOPs []shared.NOPAlias
	// RevokeOrphanedJobs when true revokes and cleans up orphaned jobs.
	RevokeOrphanedJobs bool
	// IndexerAddress overrides the indexer endpoints recovered from state when non-empty.
	IndexerAddress []string
}

// ApplyExecutorConfigInputFromState assembles a ready-to-apply
// ApplyExecutorConfigInput entirely from datastore state, then merges the
// operator-supplied options. This is the end-to-end entry point: feed the result
// straight into ApplyExecutorConfig().Apply.
//
// The NOP set is built directly from the reconstructed pool membership (executor
// job specs store NOP aliases verbatim, so no JD identity lookup is needed). When
// no pool exists yet (bootstrap) the result has no chains or NOPs.
func ApplyExecutorConfigInputFromState(
	ds datastore.DataStore,
	qualifier string,
	opts ExecutorConfigFromStateOptions,
) (ApplyExecutorConfigInput, error) {
	pool, extras, err := ExecutorPoolInputFromState(ds, qualifier)
	if err != nil {
		return ApplyExecutorConfigInput{}, err
	}

	members := executorPoolNOPAliases(pool)
	nops := make([]NOPInput, 0, len(members))
	for _, alias := range members {
		mode := shared.NOPModeCL
		if m, ok := opts.ModeByNOP[alias]; ok {
			mode = m
		}
		nops = append(nops, NOPInput{Alias: alias, Mode: mode})
	}

	indexer := extras.IndexerAddress
	if len(opts.IndexerAddress) > 0 {
		indexer = opts.IndexerAddress
	}

	return ApplyExecutorConfigInput{
		ExecutorQualifier:  qualifier,
		NOPs:               nops,
		Pool:               pool,
		IndexerAddress:     indexer,
		PyroscopeURL:       extras.PyroscopeURL,
		Monitoring:         extras.Monitoring,
		TargetNOPs:         opts.TargetNOPs,
		RevokeOrphanedJobs: opts.RevokeOrphanedJobs,
	}, nil
}
