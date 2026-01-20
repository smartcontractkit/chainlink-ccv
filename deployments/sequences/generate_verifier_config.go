package sequences

import (
	"fmt"

	"github.com/Masterminds/semver/v3"

	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccv/deployments"
	verifierconfig "github.com/smartcontractkit/chainlink-ccv/deployments/operations/verifier_config"
)

// GenerateVerifierConfigInput contains the input for the verifier config generation sequence.
type GenerateVerifierConfigInput struct {
	CommitteeQualifier string
	ExecutorQualifier  string
	ChainSelectors     []uint64
	NOPAliases         []string
}

// GenerateVerifierConfigOutput contains the output of the verifier config generation sequence.
type GenerateVerifierConfigOutput struct {
	JobSpecs           verifierconfig.NOPJobSpecs
	ExpectedJobSpecIDs map[string]bool
	ExpectedNOPs       map[string]bool
	VerifierSuffix     string
}

// GenerateVerifierConfigDeps contains the dependencies for the sequence.
type GenerateVerifierConfigDeps struct {
	Env      deployment.Environment
	Topology *deployments.EnvironmentTopology
}

// GenerateVerifierConfig is a sequence that generates verifier job specs
// by querying the datastore for contract addresses and building job specs for NOPs.
var GenerateVerifierConfig = operations.NewSequence(
	"generate-verifier-config",
	semver.MustParse("1.0.0"),
	"Generates verifier job specs from datastore contract addresses and environment topology",
	func(b operations.Bundle, deps GenerateVerifierConfigDeps, input GenerateVerifierConfigInput) (GenerateVerifierConfigOutput, error) {
		buildResult, err := operations.ExecuteOperation(b, verifierconfig.BuildConfig, verifierconfig.BuildConfigDeps{
			Env: deps.Env,
		}, verifierconfig.BuildConfigInput{
			CommitteeQualifier: input.CommitteeQualifier,
			ExecutorQualifier:  input.ExecutorQualifier,
			ChainSelectors:     input.ChainSelectors,
		})
		if err != nil {
			return GenerateVerifierConfigOutput{}, fmt.Errorf("failed to build verifier config: %w", err)
		}

		jobSpecsResult, err := operations.ExecuteOperation(b, verifierconfig.BuildJobSpecs, verifierconfig.BuildJobSpecsDeps{
			Topology: deps.Topology,
		}, verifierconfig.BuildJobSpecsInput{
			GeneratedConfig:    buildResult.Output.Config,
			CommitteeQualifier: input.CommitteeQualifier,
			NOPAliases:         input.NOPAliases,
		})
		if err != nil {
			return GenerateVerifierConfigOutput{}, fmt.Errorf("failed to build verifier job specs: %w", err)
		}

		return GenerateVerifierConfigOutput{
			JobSpecs:           jobSpecsResult.Output.JobSpecs,
			ExpectedJobSpecIDs: jobSpecsResult.Output.ExpectedJobSpecIDs,
			ExpectedNOPs:       jobSpecsResult.Output.ExpectedNOPs,
			VerifierSuffix:     jobSpecsResult.Output.VerifierSuffix,
		}, nil
	},
)
