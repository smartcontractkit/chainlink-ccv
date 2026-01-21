package executor_config

import (
	"fmt"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/Masterminds/semver/v3"

	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccv/deployments/operations/shared"
	"github.com/smartcontractkit/chainlink-ccv/executor"
)

type NOPInput struct {
	Alias string
}

type ExecutorPoolInput struct {
	NOPAliases        []string
	ExecutionInterval time.Duration
	NtpServer         string
	IndexerQueryLimit uint64
	BackoffDuration   time.Duration
	LookbackWindow    time.Duration
	ReaderCacheExpiry time.Duration
	MaxRetryDuration  time.Duration
	WorkerCount       int
}

type BuildJobSpecsInput struct {
	GeneratedConfig   *ExecutorGeneratedConfig
	ExecutorQualifier string
	NOPAliases        []string
	ExecutorPool      ExecutorPoolInput
	IndexerAddress    string
	PyroscopeURL      string
	Monitoring        shared.MonitoringInput
}

type BuildJobSpecsOutput struct {
	JobSpecs           shared.NOPJobSpecs
	ExpectedJobSpecIDs map[string]bool
	ExecutorSuffix     string
}

var BuildJobSpecs = operations.NewOperation(
	"build-executor-job-specs",
	semver.MustParse("1.0.0"),
	"Builds executor job specs from generated config and explicit input",
	func(b operations.Bundle, deps struct{}, input BuildJobSpecsInput) (BuildJobSpecsOutput, error) {
		jobSpecs := make(shared.NOPJobSpecs)
		expectedJobSpecIDs := make(map[string]bool)
		executorSuffix := fmt.Sprintf("-%s-executor", input.ExecutorQualifier)

		nopAliases := input.NOPAliases
		if len(nopAliases) == 0 {
			nopAliases = input.ExecutorPool.NOPAliases
		}

		for _, nopAlias := range nopAliases {
			chainConfigs := make(map[string]executor.ChainConfiguration)
			for chainSelectorStr, genCfg := range input.GeneratedConfig.ChainConfigs {
				chainConfigs[chainSelectorStr] = executor.ChainConfiguration{
					OffRampAddress:         genCfg.OffRampAddress,
					RmnAddress:             genCfg.RmnAddress,
					DefaultExecutorAddress: genCfg.DefaultExecutorAddress,
					ExecutorPool:           input.ExecutorPool.NOPAliases,
					ExecutionInterval:      input.ExecutorPool.ExecutionInterval,
				}
			}

			jobSpecID := fmt.Sprintf("%s-%s-executor", nopAlias, input.ExecutorQualifier)
			expectedJobSpecIDs[jobSpecID] = true

			executorCfg := executor.Configuration{
				IndexerAddress:     input.IndexerAddress,
				ExecutorID:         nopAlias,
				PyroscopeURL:       input.PyroscopeURL,
				NtpServer:          input.ExecutorPool.NtpServer,
				IndexerQueryLimit:  input.ExecutorPool.IndexerQueryLimit,
				BackoffDuration:    input.ExecutorPool.BackoffDuration,
				LookbackWindow:     input.ExecutorPool.LookbackWindow,
				ReaderCacheExpiry:  input.ExecutorPool.ReaderCacheExpiry,
				MaxRetryDuration:   input.ExecutorPool.MaxRetryDuration,
				WorkerCount:        input.ExecutorPool.WorkerCount,
				Monitoring:         convertMonitoringInput(input.Monitoring),
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

func convertMonitoringInput(cfg shared.MonitoringInput) executor.MonitoringConfig {
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
