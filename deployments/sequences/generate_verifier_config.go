package sequences

import (
	"fmt"

	"github.com/Masterminds/semver/v3"

	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccv/deployments/operations/shared"
	verifierconfig "github.com/smartcontractkit/chainlink-ccv/deployments/operations/verifier_config"
)

type GenerateVerifierConfigInput struct {
	DefaultExecutorQualifier string
	ChainSelectors           []uint64
	NOPAliases               []string
	NOPs                     []verifierconfig.NOPInput
	Committee                verifierconfig.CommitteeInput
	PyroscopeURL             string
	Monitoring               shared.MonitoringInput
}

type GenerateVerifierConfigOutput struct {
	JobSpecs           shared.NOPJobSpecs
	ExpectedJobSpecIDs map[string]bool
	ExpectedNOPs       map[string]bool
	VerifierSuffix     string
}

type GenerateVerifierConfigDeps struct {
	Env deployment.Environment
}

var GenerateVerifierConfig = operations.NewSequence(
	"generate-verifier-config",
	semver.MustParse("1.0.0"),
	"Generates verifier job specs from datastore contract addresses and explicit input",
	func(b operations.Bundle, deps GenerateVerifierConfigDeps, input GenerateVerifierConfigInput) (GenerateVerifierConfigOutput, error) {
		buildResult, err := operations.ExecuteOperation(b, verifierconfig.BuildConfig, verifierconfig.BuildConfigDeps{
			Env: deps.Env,
		}, verifierconfig.BuildConfigInput{
			CommitteeQualifier: input.Committee.Qualifier,
			ExecutorQualifier:  input.DefaultExecutorQualifier,
			ChainSelectors:     input.ChainSelectors,
		})
		if err != nil {
			return GenerateVerifierConfigOutput{}, fmt.Errorf("failed to build verifier config: %w", err)
		}

		jobSpecsResult, err := operations.ExecuteOperation(b, verifierconfig.BuildJobSpecs, struct{}{}, verifierconfig.BuildJobSpecsInput{
			GeneratedConfig:    buildResult.Output.Config,
			CommitteeQualifier: input.Committee.Qualifier,
			NOPAliases:         input.NOPAliases,
			NOPs:               input.NOPs,
			Committee:          input.Committee,
			PyroscopeURL:       input.PyroscopeURL,
			Monitoring:         input.Monitoring,
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
