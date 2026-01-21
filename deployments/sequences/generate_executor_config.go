package sequences

import (
	"fmt"

	"github.com/Masterminds/semver/v3"

	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	executorconfig "github.com/smartcontractkit/chainlink-ccv/deployments/operations/executor_config"
	"github.com/smartcontractkit/chainlink-ccv/deployments/operations/shared"
)

type GenerateExecutorConfigInput struct {
	ExecutorQualifier string
	ChainSelectors    []uint64
	NOPAliases        []string
	ExecutorPool      executorconfig.ExecutorPoolInput
	IndexerAddress    string
	PyroscopeURL      string
	Monitoring        shared.MonitoringInput
}

type GenerateExecutorConfigOutput struct {
	JobSpecs           shared.NOPJobSpecs
	ExpectedJobSpecIDs map[string]bool
	ExecutorSuffix     string
}

type GenerateExecutorConfigDeps struct {
	Env deployment.Environment
}

var GenerateExecutorConfig = operations.NewSequence(
	"generate-executor-config",
	semver.MustParse("1.0.0"),
	"Generates executor job specs from datastore contract addresses and explicit input",
	func(b operations.Bundle, deps GenerateExecutorConfigDeps, input GenerateExecutorConfigInput) (GenerateExecutorConfigOutput, error) {
		buildResult, err := operations.ExecuteOperation(b, executorconfig.BuildConfig, executorconfig.BuildConfigDeps{
			Env: deps.Env,
		}, executorconfig.BuildConfigInput{
			ExecutorQualifier: input.ExecutorQualifier,
			ChainSelectors:    input.ChainSelectors,
		})
		if err != nil {
			return GenerateExecutorConfigOutput{}, fmt.Errorf("failed to build executor config: %w", err)
		}

		jobSpecsResult, err := operations.ExecuteOperation(b, executorconfig.BuildJobSpecs, struct{}{}, executorconfig.BuildJobSpecsInput{
			GeneratedConfig:   buildResult.Output.Config,
			ExecutorQualifier: input.ExecutorQualifier,
			NOPAliases:        input.NOPAliases,
			ExecutorPool:      input.ExecutorPool,
			IndexerAddress:    input.IndexerAddress,
			PyroscopeURL:      input.PyroscopeURL,
			Monitoring:        input.Monitoring,
		})
		if err != nil {
			return GenerateExecutorConfigOutput{}, fmt.Errorf("failed to build executor job specs: %w", err)
		}

		return GenerateExecutorConfigOutput{
			JobSpecs:           jobSpecsResult.Output.JobSpecs,
			ExpectedJobSpecIDs: jobSpecsResult.Output.ExpectedJobSpecIDs,
			ExecutorSuffix:     jobSpecsResult.Output.ExecutorSuffix,
		}, nil
	},
)
