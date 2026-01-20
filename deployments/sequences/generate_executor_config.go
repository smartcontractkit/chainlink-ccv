package sequences

import (
	"fmt"

	"github.com/Masterminds/semver/v3"

	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	executorconfig "github.com/smartcontractkit/chainlink-ccv/deployments/operations/executor_config"
)

// GenerateExecutorConfigInput contains the input for the executor config generation sequence.
type GenerateExecutorConfigInput struct {
	ExecutorQualifier string
	ChainSelectors    []uint64
}

// GenerateExecutorConfigOutput contains the output of the executor config generation sequence.
type GenerateExecutorConfigOutput struct {
	Config *executorconfig.ExecutorGeneratedConfig
}

// GenerateExecutorConfigDeps contains the dependencies for the sequence.
type GenerateExecutorConfigDeps struct {
	Env deployment.Environment
}

// GenerateExecutorConfig is a sequence that generates the executor configuration
// by querying the datastore for contract addresses.
var GenerateExecutorConfig = operations.NewSequence(
	"generate-executor-config",
	semver.MustParse("1.0.0"),
	"Generates the executor configuration from datastore contract addresses",
	func(b operations.Bundle, deps GenerateExecutorConfigDeps, input GenerateExecutorConfigInput) (GenerateExecutorConfigOutput, error) {
		result, err := operations.ExecuteOperation(b, executorconfig.BuildConfig, executorconfig.BuildConfigDeps{
			Env: deps.Env,
		}, executorconfig.BuildConfigInput{
			ExecutorQualifier: input.ExecutorQualifier,
			ChainSelectors:    input.ChainSelectors,
		})
		if err != nil {
			return GenerateExecutorConfigOutput{}, fmt.Errorf("failed to build executor config: %w", err)
		}

		return GenerateExecutorConfigOutput{
			Config: result.Output.Config,
		}, nil
	},
)
