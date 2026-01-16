package sequences

import (
	"fmt"

	"github.com/Masterminds/semver/v3"

	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	verifierconfig "github.com/smartcontractkit/chainlink-ccv/deployments/operations/verifier_config"
)

// GenerateVerifierConfigInput contains the input for the verifier config generation sequence.
type GenerateVerifierConfigInput struct {
	CommitteeQualifier string
	ExecutorQualifier  string
	ChainSelectors     []uint64
}

// GenerateVerifierConfigOutput contains the output of the verifier config generation sequence.
type GenerateVerifierConfigOutput struct {
	Config *verifierconfig.VerifierGeneratedConfig
}

// GenerateVerifierConfigDeps contains the dependencies for the sequence.
type GenerateVerifierConfigDeps struct {
	Env deployment.Environment
}

// GenerateVerifierConfig is a sequence that generates the verifier configuration
// by querying the datastore for contract addresses.
var GenerateVerifierConfig = operations.NewSequence(
	"generate-verifier-config",
	semver.MustParse("1.0.0"),
	"Generates the verifier configuration from datastore contract addresses",
	func(b operations.Bundle, deps GenerateVerifierConfigDeps, input GenerateVerifierConfigInput) (GenerateVerifierConfigOutput, error) {
		result, err := operations.ExecuteOperation(b, verifierconfig.BuildConfig, verifierconfig.BuildConfigDeps{
			Env: deps.Env,
		}, verifierconfig.BuildConfigInput{
			CommitteeQualifier: input.CommitteeQualifier,
			ExecutorQualifier:  input.ExecutorQualifier,
			ChainSelectors:     input.ChainSelectors,
		})
		if err != nil {
			return GenerateVerifierConfigOutput{}, fmt.Errorf("failed to build verifier config: %w", err)
		}

		return GenerateVerifierConfigOutput{
			Config: result.Output.Config,
		}, nil
	},
)
