package verifier_config

import (
	"fmt"

	"github.com/BurntSushi/toml"
	"github.com/Masterminds/semver/v3"

	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/deployments/operations/shared"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
)

// NOPInput defines the configuration for a single NOP (Node Operator).
type NOPInput struct {
	// Alias is the unique identifier for this NOP.
	Alias shared.NOPAlias
	// SignerAddress is the address used by this NOP for signing attestations.
	SignerAddressByFamily map[string]string
}

// AggregatorInput defines the configuration for an aggregator instance.
type AggregatorInput struct {
	// Name is the unique identifier for this aggregator instance.
	Name string
	// Address is the network endpoint of the aggregator service.
	Address string
	// InsecureAggregatorConnection disables TLS verification when connecting to the aggregator.
	InsecureAggregatorConnection bool
}

// CommitteeInput defines the configuration for a verifier committee.
type CommitteeInput struct {
	// Qualifier is the unique identifier for this committee.
	Qualifier string
	// Aggregators is the list of aggregator instances that serve this committee.
	Aggregators []AggregatorInput
	// NOPAliases is the list of NOP aliases that are members of this committee.
	NOPAliases []shared.NOPAlias
}

type BuildJobSpecsInput struct {
	GeneratedConfig *VerifierGeneratedConfig
	// TargetNOPs limits which NOPs will have their job specs updated. Defaults to all NOPs in the committee when empty.
	TargetNOPs      []shared.NOPAlias
	EnvironmentNOPs []NOPInput
	Committee       CommitteeInput
	PyroscopeURL    string
	Monitoring      shared.MonitoringInput
}

type BuildJobSpecsOutput struct {
	JobSpecs      shared.NOPJobSpecs
	AffectedScope shared.VerifierJobScope
}

var BuildJobSpecs = operations.NewOperation(
	"build-verifier-job-specs",
	semver.MustParse("1.0.0"),
	"Builds verifier job specs from generated config and explicit input",
	func(b operations.Bundle, deps struct{}, input BuildJobSpecsInput) (BuildJobSpecsOutput, error) {
		nopByAlias := make(map[shared.NOPAlias]NOPInput, len(input.EnvironmentNOPs))
		for _, nop := range input.EnvironmentNOPs {
			nopByAlias[nop.Alias] = nop
		}

		jobSpecs := make(shared.NOPJobSpecs)
		scope := shared.VerifierJobScope{
			CommitteeQualifier: input.Committee.Qualifier,
		}

		targetNOPs := input.TargetNOPs
		if len(targetNOPs) == 0 {
			targetNOPs = input.Committee.NOPAliases
		}

		for _, nopAlias := range targetNOPs {
			nop, ok := nopByAlias[nopAlias]
			if !ok {
				return BuildJobSpecsOutput{}, fmt.Errorf("NOP %q not found in input", nopAlias)
			}

			for _, agg := range input.Committee.Aggregators {
				verifierJobID := shared.NewVerifierJobID(agg.Name, scope)

				verifierCfg := commit.Config{
					VerifierID:                   verifierJobID.GetVerifierID(),
					AggregatorAddress:            agg.Address,
					InsecureAggregatorConnection: agg.InsecureAggregatorConnection,
					// TODO: Change this when verifier supports multiple families
					SignerAddress:                  nop.SignerAddressByFamily[chainsel.FamilyEVM],
					PyroscopeURL:                   input.PyroscopeURL,
					CommitteeVerifierAddresses:     input.GeneratedConfig.CommitteeVerifierAddresses,
					OnRampAddresses:                input.GeneratedConfig.OnRampAddresses,
					DefaultExecutorOnRampAddresses: input.GeneratedConfig.DefaultExecutorOnRampAddresses,
					RMNRemoteAddresses:             input.GeneratedConfig.RMNRemoteAddresses,
					Monitoring:                     convertMonitoringInput(input.Monitoring),
				}

				configBytes, err := toml.Marshal(verifierCfg)
				if err != nil {
					return BuildJobSpecsOutput{}, fmt.Errorf("failed to marshal verifier config to TOML for NOP %q aggregator %q: %w", nopAlias, agg.Name, err)
				}

				jobSpec := fmt.Sprintf(`schemaVersion = 1
type = "ccvcommitteeverifier"
committeeVerifierConfig = """
%s"""
`, string(configBytes))

				if jobSpecs[nopAlias] == nil {
					jobSpecs[nopAlias] = make(map[shared.JobID]string)
				}
				jobSpecs[nopAlias][verifierJobID.ToJobID()] = jobSpec
			}
		}

		return BuildJobSpecsOutput{
			JobSpecs:      jobSpecs,
			AffectedScope: scope,
		}, nil
	},
)

func convertMonitoringInput(cfg shared.MonitoringInput) verifier.MonitoringConfig {
	return verifier.MonitoringConfig{
		Enabled: cfg.Enabled,
		Type:    cfg.Type,
		Beholder: verifier.BeholderConfig{
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
