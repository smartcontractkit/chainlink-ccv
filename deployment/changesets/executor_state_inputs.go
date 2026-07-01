package changesets

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	"github.com/smartcontractkit/chainlink-ccv/executor"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

// executorJobType is the job spec type emitted for executor jobs (see
// buildExecutorJobSpecs); parsed specs are validated against it.
const executorJobType = "ccvexecutor"

// ExecutorConnExtras carries the executor connection settings recovered alongside
// the pool from persisted job specs: these are not part of ExecutorPoolInput but
// are needed to rebuild a full ApplyExecutorConfigInput.
type ExecutorConnExtras struct {
	IndexerAddress []string
	PyroscopeURL   string
}

// ExecutorPoolInputFromState reconstructs the executor pool input from the
// executor job specs previously published for the qualifier and persisted in the
// datastore — the state analog of ExecutorPoolInputFromTopology.
//
// Unlike committee membership (which is read on-chain), an executor pool has no
// meaningful on-chain footprint: its membership, per-chain execution interval,
// and all pool-wide tuning live in the published job config. Those specs are the
// source of truth, so everything is recovered from them and nothing needs to be
// re-supplied. The connection settings (indexer addresses, pyroscope URL) are
// returned separately via ExecutorConnExtras.
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

	// All of a pool's jobs carry identical pool-wide tuning and the full per-chain
	// config, so the reconstructed pool is taken from a single job. To keep that
	// deterministic regardless of datastore iteration order, every other in-scope
	// job must agree — divergence is drift and is reported as an error rather than
	// silently resolved to whichever job happened to be visited first.
	var first *executor.Configuration
	var firstJobID shared.JobID

	for _, byJobID := range allJobs {
		for jobID, info := range byJobID {
			if !scope.IsJobInScope(jobID) {
				continue
			}
			cfg, err := parseExecutorConfigFromSpec(info.Spec)
			if err != nil {
				return pool, extras, fmt.Errorf("executor pool %q: job %q: %w", qualifier, jobID, err)
			}
			if first == nil {
				c := cfg
				first = &c
				firstJobID = jobID
				continue
			}
			if d := executorConfigDrift(*first, cfg); d != "" {
				return pool, extras, fmt.Errorf(
					"executor pool %q: job %q diverges from job %q: %s", qualifier, jobID, firstJobID, d)
			}
		}
	}

	if first == nil {
		return pool, extras, nil // bootstrap: no jobs in scope
	}

	pool.IndexerQueryLimit = first.IndexerQueryLimit
	pool.BackoffDuration = first.BackoffDuration
	pool.LookbackWindow = first.LookbackWindow
	pool.ReaderCacheExpiry = first.ReaderCacheExpiry
	pool.MaxRetryDuration = first.MaxRetryDuration
	pool.WorkerCount = first.WorkerCount
	pool.NtpServer = first.NtpServer
	extras.IndexerAddress = first.IndexerAddress
	extras.PyroscopeURL = first.PyroscopeURL

	for selStr, cc := range first.ChainConfiguration {
		sel, perr := strconv.ParseUint(selStr, 10, 64)
		if perr != nil {
			return pool, extras, fmt.Errorf("executor pool %q: invalid chain selector key %q: %w", qualifier, selStr, perr)
		}
		pool.ChainConfigs[sel] = ChainExecutorPoolMembership{
			NOPAliases:        shared.ConvertStringToNopAliases(cc.ExecutorPool),
			ExecutionInterval: cc.ExecutionInterval,
		}
	}

	return pool, extras, nil
}

// executorConfigDrift returns a non-empty description when two in-scope executor
// job configs disagree on any field the pool is reconstructed from (pool-wide
// tuning, connection settings, or per-chain membership/interval). Empty means the
// two are consistent.
func executorConfigDrift(a, b executor.Configuration) string {
	switch {
	case a.IndexerQueryLimit != b.IndexerQueryLimit:
		return fmt.Sprintf("indexerQueryLimit %d != %d", a.IndexerQueryLimit, b.IndexerQueryLimit)
	case a.BackoffDuration != b.BackoffDuration:
		return fmt.Sprintf("backoffDuration %s != %s", a.BackoffDuration, b.BackoffDuration)
	case a.LookbackWindow != b.LookbackWindow:
		return fmt.Sprintf("lookbackWindow %s != %s", a.LookbackWindow, b.LookbackWindow)
	case a.ReaderCacheExpiry != b.ReaderCacheExpiry:
		return fmt.Sprintf("readerCacheExpiry %s != %s", a.ReaderCacheExpiry, b.ReaderCacheExpiry)
	case a.MaxRetryDuration != b.MaxRetryDuration:
		return fmt.Sprintf("maxRetryDuration %s != %s", a.MaxRetryDuration, b.MaxRetryDuration)
	case a.WorkerCount != b.WorkerCount:
		return fmt.Sprintf("workerCount %d != %d", a.WorkerCount, b.WorkerCount)
	case a.NtpServer != b.NtpServer:
		return fmt.Sprintf("ntpServer %q != %q", a.NtpServer, b.NtpServer)
	case a.PyroscopeURL != b.PyroscopeURL:
		return fmt.Sprintf("pyroscopeURL %q != %q", a.PyroscopeURL, b.PyroscopeURL)
	case strings.Join(a.IndexerAddress, ",") != strings.Join(b.IndexerAddress, ","):
		return fmt.Sprintf("indexerAddress [%s] != [%s]", strings.Join(a.IndexerAddress, ","), strings.Join(b.IndexerAddress, ","))
	}
	return chainConfigurationDrift(a.ChainConfiguration, b.ChainConfiguration)
}

func chainConfigurationDrift(a, b map[string]executor.ChainConfiguration) string {
	if len(a) != len(b) {
		return fmt.Sprintf("chain config count %d != %d", len(a), len(b))
	}
	for sel, ca := range a {
		cb, ok := b[sel]
		if !ok {
			return fmt.Sprintf("chain %s present in one job but not the other", sel)
		}
		if pa, pb := sortedStrings(ca.ExecutorPool), sortedStrings(cb.ExecutorPool); strings.Join(pa, ",") != strings.Join(pb, ",") {
			return fmt.Sprintf("chain %s pool [%s] != [%s]", sel, strings.Join(pa, ","), strings.Join(pb, ","))
		}
		if ca.ExecutionInterval != cb.ExecutionInterval {
			return fmt.Sprintf("chain %s executionInterval %s != %s", sel, ca.ExecutionInterval, cb.ExecutionInterval)
		}
	}
	return ""
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// parseExecutorConfigFromSpec extracts the embedded executor.Configuration from a
// ccvexecutor job spec. Standalone specs use appConfig; CL specs use executorConfig.
func parseExecutorConfigFromSpec(spec string) (executor.Configuration, error) {
	inner, err := executorInnerConfigFromSpec(spec)
	if err != nil {
		return executor.Configuration{}, err
	}

	var cfg executor.Configuration
	if _, err := toml.Decode(inner, &cfg); err != nil {
		return executor.Configuration{}, fmt.Errorf("failed to parse executor config: %w", err)
	}
	return cfg, nil
}

func executorInnerConfigFromSpec(spec string) (string, error) {
	var wrapper struct {
		Type           string `toml:"type"`
		AppConfig      string `toml:"appConfig"`
		ExecutorConfig string `toml:"executorConfig"`
	}
	if _, err := toml.Decode(spec, &wrapper); err != nil {
		return "", fmt.Errorf("failed to parse job spec wrapper: %w", err)
	}
	if wrapper.Type != executorJobType {
		return "", fmt.Errorf("unexpected job spec type %q (want %q)", wrapper.Type, executorJobType)
	}
	if wrapper.AppConfig != "" {
		return wrapper.AppConfig, nil
	}
	if wrapper.ExecutorConfig != "" {
		return wrapper.ExecutorConfig, nil
	}
	return "", fmt.Errorf("job spec missing appConfig and executorConfig")
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
		TargetNOPs:         opts.TargetNOPs,
		RevokeOrphanedJobs: opts.RevokeOrphanedJobs,
	}, nil
}
