package sequences

import (
	"fmt"

	"github.com/Masterminds/semver/v3"

	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccv/deployments"
	executorconfig "github.com/smartcontractkit/chainlink-ccv/deployments/operations/executor_config"
)

// GenerateExecutorConfigInput contains the input for the executor config generation sequence.
type GenerateExecutorConfigInput struct {
	ExecutorQualifier string
	ChainSelectors    []uint64
	NOPAliases        []string
}

// GenerateExecutorConfigOutput contains the output of the executor config generation sequence.
type GenerateExecutorConfigOutput struct {
	JobSpecs           executorconfig.NOPJobSpecs
	ExpectedJobSpecIDs map[string]bool
	ExecutorSuffix     string
}

// GenerateExecutorConfigDeps contains the dependencies for the sequence.
type GenerateExecutorConfigDeps struct {
	Env      deployment.Environment
	Topology *deployments.EnvironmentTopology
}

// GenerateExecutorConfig is a sequence that generates executor job specs
// by querying the datastore for contract addresses and building job specs for NOPs.
var GenerateExecutorConfig = operations.NewSequence(
	"generate-executor-config",
	semver.MustParse("1.0.0"),
	"Generates executor job specs from datastore contract addresses and environment topology",
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

		jobSpecsResult, err := operations.ExecuteOperation(b, executorconfig.BuildJobSpecs, executorconfig.BuildJobSpecsDeps{
			Topology: deps.Topology,
		}, executorconfig.BuildJobSpecsInput{
			GeneratedConfig:   buildResult.Output.Config,
			ExecutorQualifier: input.ExecutorQualifier,
			NOPAliases:        input.NOPAliases,
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
