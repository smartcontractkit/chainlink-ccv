package changesets

import (
	"fmt"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccv/deployments"
	"github.com/smartcontractkit/chainlink-ccv/deployments/sequences"
	"github.com/smartcontractkit/chainlink-ccv/executor"
)

// GenerateExecutorConfigCfg is the configuration for the generate executor config changeset.
type GenerateExecutorConfigCfg struct {
	EnvConfigPath     string
	ExecutorQualifier string
	ChainSelectors    []uint64
	NOPAliases        []string
}

// GenerateExecutorConfig creates a changeset that generates executor configurations
// for NOPs that are part of an executor pool. It iterates over specified NOPs (or all if empty)
// and generates a job spec for each NOP.
func GenerateExecutorConfig() deployment.ChangeSetV2[GenerateExecutorConfigCfg] {
	validate := func(e deployment.Environment, cfg GenerateExecutorConfigCfg) error {
		if cfg.EnvConfigPath == "" {
			return fmt.Errorf("env config path is required")
		}

		envCfg, err := deployments.LoadEnvConfig(cfg.EnvConfigPath)
		if err != nil {
			return fmt.Errorf("failed to load env config: %w", err)
		}

		for _, alias := range cfg.NOPAliases {
			if _, ok := envCfg.NOPTopology.NOPs[alias]; !ok {
				return fmt.Errorf("NOP alias %q not found in env config", alias)
			}
		}

		envSelectors := e.BlockChains.ListChainSelectors()
		for _, s := range cfg.ChainSelectors {
			if !slices.Contains(envSelectors, s) {
				return fmt.Errorf("selector %d is not available in environment", s)
			}
		}
		return nil
	}

	apply := func(e deployment.Environment, cfg GenerateExecutorConfigCfg) (deployment.ChangesetOutput, error) {
		envCfg, err := deployments.LoadEnvConfig(cfg.EnvConfigPath)
		if err != nil {
			return deployment.ChangesetOutput{}, fmt.Errorf("failed to load env config: %w", err)
		}

		selectors := cfg.ChainSelectors
		if len(selectors) == 0 {
			selectors = e.BlockChains.ListChainSelectors()
		}

		deps := sequences.GenerateExecutorConfigDeps{
			Env: e,
		}

		input := sequences.GenerateExecutorConfigInput{
			ExecutorQualifier: cfg.ExecutorQualifier,
			ChainSelectors:    selectors,
		}

		report, err := operations.ExecuteSequence(e.OperationsBundle, sequences.GenerateExecutorConfig, deps, input)
		if err != nil {
			return deployment.ChangesetOutput{
				Reports: report.ExecutionReports,
			}, fmt.Errorf("failed to generate executor config: %w", err)
		}

		nopAliases := cfg.NOPAliases
		if len(nopAliases) == 0 {
			for alias := range envCfg.NOPTopology.NOPs {
				nopAliases = append(nopAliases, alias)
			}
		}

		outputDS := datastore.NewMemoryDataStore()
		if e.DataStore != nil {
			if err := outputDS.Merge(e.DataStore); err != nil {
				return deployment.ChangesetOutput{
					Reports: report.ExecutionReports,
				}, fmt.Errorf("failed to merge existing datastore: %w", err)
			}
		}

		// Track expected job spec IDs for cleanup
		expectedJobSpecIDs := make(map[string]bool)
		executorSuffix := fmt.Sprintf("-%s-executor", cfg.ExecutorQualifier)

		for _, nopAlias := range nopAliases {
			// Check if NOP is in the requested executor pool
			pools := envCfg.GetPoolsForNOP(nopAlias)
			if !slices.Contains(pools, cfg.ExecutorQualifier) {
				continue
			}

			pool, ok := envCfg.ExecutorPools[cfg.ExecutorQualifier]
			if !ok {
				continue
			}

			chainConfigs := make(map[string]executor.ChainConfiguration)
			for chainSelectorStr, genCfg := range report.Output.Config.ChainConfigs {
				chainConfigs[chainSelectorStr] = executor.ChainConfiguration{
					OffRampAddress:         genCfg.OffRampAddress,
					RmnAddress:             genCfg.RmnAddress,
					DefaultExecutorAddress: genCfg.DefaultExecutorAddress,
					ExecutorPool:           pool.NOPAliases,
					ExecutionInterval:      pool.ExecutionInterval,
				}
			}

			// Job spec ID includes the qualifier for cleanup tracking,
			// but executor ID is just the NOP alias to match the pool entries
			jobSpecID := fmt.Sprintf("%s-%s-executor", nopAlias, cfg.ExecutorQualifier)
			expectedJobSpecIDs[jobSpecID] = true

			executorCfg := executor.Configuration{
				IndexerAddress:     envCfg.IndexerAddress,
				ExecutorID:         nopAlias,
				PyroscopeURL:       envCfg.PyroscopeURL,
				NtpServer:          pool.NtpServer,
				IndexerQueryLimit:  pool.IndexerQueryLimit,
				BackoffDuration:    pool.BackoffDuration,
				LookbackWindow:     pool.LookbackWindow,
				ReaderCacheExpiry:  pool.ReaderCacheExpiry,
				MaxRetryDuration:   pool.MaxRetryDuration,
				WorkerCount:        pool.WorkerCount,
				Monitoring:         convertMonitoringConfig(envCfg.Monitoring),
				ChainConfiguration: chainConfigs,
			}

			configBytes, err := toml.Marshal(executorCfg)
			if err != nil {
				return deployment.ChangesetOutput{
					Reports: report.ExecutionReports,
				}, fmt.Errorf("failed to marshal executor config to TOML for NOP %q: %w", nopAlias, err)
			}

			jobSpec := fmt.Sprintf(`schemaVersion = 1
type = "ccvexecutor"
executorConfig = """
%s"""
`, string(configBytes))

			if err := deployments.SaveNOPJobSpec(outputDS, nopAlias, jobSpecID, jobSpec); err != nil {
				return deployment.ChangesetOutput{
					Reports: report.ExecutionReports,
				}, fmt.Errorf("failed to save executor job spec for NOP %q: %w", nopAlias, err)
			}
		}

		// Clean up orphaned executor job specs for this qualifier
		// When NOPAliases is explicitly set, only clean up those specific NOPs (scoped mode)
		// When NOPAliases is empty, clean up all NOPs in the datastore (full sync mode)
		scopedCleanup := len(cfg.NOPAliases) > 0
		scopedNOPs := make(map[string]bool)
		if scopedCleanup {
			for _, nopAlias := range cfg.NOPAliases {
				scopedNOPs[nopAlias] = true
			}
		}

		allNOPJobSpecs, err := deployments.GetAllNOPJobSpecs(outputDS.Seal())
		if err != nil {
			return deployment.ChangesetOutput{
				Reports: report.ExecutionReports,
			}, fmt.Errorf("failed to get all NOP job specs for cleanup: %w", err)
		}

		for nopAlias, jobSpecs := range allNOPJobSpecs {
			// In scoped mode, only cleanup NOPs that were explicitly specified
			if scopedCleanup && !scopedNOPs[nopAlias] {
				continue
			}
			for jobSpecID := range jobSpecs {
				// Check if this job spec matches the pattern for this executor qualifier
				if strings.HasSuffix(jobSpecID, executorSuffix) && !expectedJobSpecIDs[jobSpecID] {
					if err := deployments.DeleteNOPJobSpec(outputDS, nopAlias, jobSpecID); err != nil {
						return deployment.ChangesetOutput{
							Reports: report.ExecutionReports,
						}, fmt.Errorf("failed to delete orphaned executor job spec %q for NOP %q: %w", jobSpecID, nopAlias, err)
					}
				}
			}
		}

		return deployment.ChangesetOutput{
			Reports:   report.ExecutionReports,
			DataStore: outputDS,
		}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
}

func convertMonitoringConfig(cfg deployments.MonitoringConfig) executor.MonitoringConfig {
	return executor.MonitoringConfig{
		Enabled: cfg.Enabled,
		Type:    cfg.Type,
		Beholder: executor.BeholderConfig{
			InsecureConnection:       cfg.Beholder.InsecureConnection,
			CACertFile:               cfg.Beholder.CACertFile,
			OtelExporterGRPCEndpoint: cfg.Beholder.OtelExporterGRPCEndpoint,
			OtelExporterHTTPEndpoint: cfg.Beholder.OtelExporterHTTPEndpoint,
			LogStreamingEnabled:      cfg.Beholder.LogStreamingEnabled,
			MetricReaderInterval:     cfg.Beholder.MetricReaderInterval,
			TraceSampleRatio:         cfg.Beholder.TraceSampleRatio,
			TraceBatchTimeout:        cfg.Beholder.TraceBatchTimeout,
		},
	}
}
