package verifier_config

import (
	"fmt"

	"github.com/BurntSushi/toml"
	"github.com/Masterminds/semver/v3"

	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccv/deployments/operations/shared"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
)

type NOPInput struct {
	Alias         string
	SignerAddress string
}

type AggregatorInput struct {
	Name                         string
	Address                      string
	InsecureAggregatorConnection bool
}

type CommitteeInput struct {
	Qualifier   string
	Aggregators []AggregatorInput
	NOPAliases  []string
}

type BuildJobSpecsInput struct {
	GeneratedConfig    *VerifierGeneratedConfig
	CommitteeQualifier string
	NOPAliases         []string
	NOPs               []NOPInput
	Committee          CommitteeInput
	PyroscopeURL       string
	Monitoring         shared.MonitoringInput
}

type BuildJobSpecsOutput struct {
	JobSpecs           shared.NOPJobSpecs
	ExpectedJobSpecIDs map[string]bool
	ExpectedNOPs       map[string]bool
	VerifierSuffix     string
}

var BuildJobSpecs = operations.NewOperation(
	"build-verifier-job-specs",
	semver.MustParse("1.0.0"),
	"Builds verifier job specs from generated config and explicit input",
	func(b operations.Bundle, deps struct{}, input BuildJobSpecsInput) (BuildJobSpecsOutput, error) {
		nopByAlias := make(map[string]NOPInput, len(input.NOPs))
		for _, nop := range input.NOPs {
			nopByAlias[nop.Alias] = nop
		}

		jobSpecs := make(shared.NOPJobSpecs)
		expectedJobSpecIDs := make(map[string]bool)
		expectedNOPs := make(map[string]bool)
		verifierSuffix := fmt.Sprintf("-%s-verifier", input.Committee.Qualifier)

		nopAliases := input.NOPAliases
		if len(nopAliases) == 0 {
			nopAliases = input.Committee.NOPAliases
		}

		for _, nopAlias := range nopAliases {
			nop, ok := nopByAlias[nopAlias]
			if !ok {
				return BuildJobSpecsOutput{}, fmt.Errorf("NOP %q not found in input", nopAlias)
			}
			expectedNOPs[nopAlias] = true

			for _, agg := range input.Committee.Aggregators {
				verifierID := fmt.Sprintf("%s-%s-verifier", agg.Name, input.Committee.Qualifier)
				expectedJobSpecIDs[verifierID] = true

				verifierCfg := commit.Config{
					VerifierID:                     verifierID,
					AggregatorAddress:              agg.Address,
					InsecureAggregatorConnection:   agg.InsecureAggregatorConnection,
					SignerAddress:                  nop.SignerAddress,
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
					jobSpecs[nopAlias] = make(map[string]string)
				}
				jobSpecs[nopAlias][verifierID] = jobSpec
			}
		}

		return BuildJobSpecsOutput{
			JobSpecs:           jobSpecs,
			ExpectedJobSpecIDs: expectedJobSpecIDs,
			ExpectedNOPs:       expectedNOPs,
			VerifierSuffix:     verifierSuffix,
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
