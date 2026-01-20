package executor_config

import (
	"fmt"
	"slices"

	"github.com/BurntSushi/toml"
	"github.com/Masterminds/semver/v3"

	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccv/deployments"
	"github.com/smartcontractkit/chainlink-ccv/executor"
)

// NOPJobSpecs maps NOP alias to a map of job spec ID to job spec content.
type NOPJobSpecs map[string]map[string]string

// BuildJobSpecsDeps contains the dependencies for building executor job specs.
type BuildJobSpecsDeps struct {
	Topology *deployments.EnvironmentTopology
}

// BuildJobSpecsInput contains the input parameters for building executor job specs.
type BuildJobSpecsInput struct {
	GeneratedConfig   *ExecutorGeneratedConfig
	ExecutorQualifier string
	NOPAliases        []string
}

// BuildJobSpecsOutput contains the generated job specs and metadata for cleanup.
type BuildJobSpecsOutput struct {
	JobSpecs           NOPJobSpecs
	ExpectedJobSpecIDs map[string]bool
	ExecutorSuffix     string
}

// BuildJobSpecs is an operation that generates executor job specs for the specified NOPs.
var BuildJobSpecs = operations.NewOperation(
	"build-executor-job-specs",
	semver.MustParse("1.0.0"),
	"Builds executor job specs from generated config and environment topology",
	func(b operations.Bundle, deps BuildJobSpecsDeps, input BuildJobSpecsInput) (BuildJobSpecsOutput, error) {
		jobSpecs := make(NOPJobSpecs)
		expectedJobSpecIDs := make(map[string]bool)
		executorSuffix := fmt.Sprintf("-%s-executor", input.ExecutorQualifier)

		nopAliases := input.NOPAliases
		if len(nopAliases) == 0 {
			for _, nop := range deps.Topology.NOPTopology.NOPs {
				nopAliases = append(nopAliases, nop.Alias)
			}
		}

		for _, nopAlias := range nopAliases {
			pools := deps.Topology.GetPoolsForNOP(nopAlias)
			if !slices.Contains(pools, input.ExecutorQualifier) {
				continue
			}

			pool, ok := deps.Topology.ExecutorPools[input.ExecutorQualifier]
			if !ok {
				continue
			}

			chainConfigs := make(map[string]executor.ChainConfiguration)
			for chainSelectorStr, genCfg := range input.GeneratedConfig.ChainConfigs {
				chainConfigs[chainSelectorStr] = executor.ChainConfiguration{
					OffRampAddress:         genCfg.OffRampAddress,
					RmnAddress:             genCfg.RmnAddress,
					DefaultExecutorAddress: genCfg.DefaultExecutorAddress,
					ExecutorPool:           pool.NOPAliases,
					ExecutionInterval:      pool.ExecutionInterval,
				}
			}

			jobSpecID := fmt.Sprintf("%s-%s-executor", nopAlias, input.ExecutorQualifier)
			expectedJobSpecIDs[jobSpecID] = true

			executorCfg := executor.Configuration{
				IndexerAddress:     deps.Topology.IndexerAddress,
				ExecutorID:         nopAlias,
				PyroscopeURL:       deps.Topology.PyroscopeURL,
				NtpServer:          pool.NtpServer,
				IndexerQueryLimit:  pool.IndexerQueryLimit,
				BackoffDuration:    pool.BackoffDuration,
				LookbackWindow:     pool.LookbackWindow,
				ReaderCacheExpiry:  pool.ReaderCacheExpiry,
				MaxRetryDuration:   pool.MaxRetryDuration,
				WorkerCount:        pool.WorkerCount,
				Monitoring:         convertMonitoringConfig(deps.Topology.Monitoring),
				ChainConfiguration: chainConfigs,
			}

			configBytes, err := toml.Marshal(executorCfg)
			if err != nil {
				return BuildJobSpecsOutput{}, fmt.Errorf("failed to marshal executor config to TOML for NOP %q: %w", nopAlias, err)
			}

			jobSpec := fmt.Sprintf(`schemaVersion = 1
type = "ccvexecutor"
executorConfig = """
%s"""
`, string(configBytes))

			if jobSpecs[nopAlias] == nil {
				jobSpecs[nopAlias] = make(map[string]string)
			}
			jobSpecs[nopAlias][jobSpecID] = jobSpec
		}

		return BuildJobSpecsOutput{
			JobSpecs:           jobSpecs,
			ExpectedJobSpecIDs: expectedJobSpecIDs,
			ExecutorSuffix:     executorSuffix,
		}, nil
	},
)

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
