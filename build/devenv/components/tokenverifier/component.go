package tokenverifier

import (
	"context"
	"fmt"

	"github.com/pelletier/go-toml/v2"

	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	ccvadapters "github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	ccvchangesets "github.com/smartcontractkit/chainlink-ccv/deployment/changesets"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

const configKey = "token_verifier"

func init() {
	if err := devenvruntime.Register(configKey, factory); err != nil {
		panic(fmt.Sprintf("tokenverifier component: %v", err))
	}
}

func factory(_ map[string]any) (devenvruntime.Component, error) {
	return &component{}, nil
}

type component struct{}

func (c *component) ValidateConfig(_ any) error { return nil }

// RunPhase4 decodes [[token_verifier]] config, generates token verifier
// configuration from on-chain state via changeset, and launches standalone
// containers. It publishes the populated inputs under "token_verifier" so
// NewPhasedEnvironment can replace cfg.TokenVerifier before Store().
func (c *component) RunPhase4(
	_ context.Context,
	_ map[string]any,
	componentConfig any,
	priorOutputs map[string]any,
) (map[string]any, []devenvruntime.Effect, error) {
	inputs, err := decode(componentConfig)
	if err != nil {
		return nil, nil, err
	}
	if len(inputs) == 0 {
		return map[string]any{}, nil, nil
	}

	e, ok := priorOutputs["_env"].(*deployment.Environment)
	if !ok || e == nil {
		return nil, nil, fmt.Errorf("tokenverifier: _env not found in phase outputs")
	}
	selectors, ok := priorOutputs["_selectors"].([]uint64)
	if !ok {
		return nil, nil, fmt.Errorf("tokenverifier: _selectors not found in phase outputs")
	}
	blockchainOutputs, ok := priorOutputs["blockchainOutputs"].([]*blockchain.Output)
	if !ok {
		return nil, nil, fmt.Errorf("tokenverifier: blockchainOutputs not found in phase outputs")
	}

	var fakeOut *services.FakeOutput
	if fake, ok := priorOutputs["fake"].(*services.FakeInput); ok && fake != nil {
		fakeOut = fake.Out
	}
	if fakeOut == nil {
		return nil, nil, fmt.Errorf("tokenverifier: fake data provider is required to provide attestation API endpoints")
	}

	localEnv := *e
	for i, tvIn := range inputs {
		if tvIn == nil {
			continue
		}

		template, tmplErr := tvIn.GenerateTemplateConfig()
		if tmplErr != nil {
			return nil, nil, fmt.Errorf("tokenverifier: generating template config: %w", tmplErr)
		}

		cs := ccvchangesets.GenerateTokenVerifierConfig(ccvadapters.GetRegistry())
		output, csErr := cs.Apply(localEnv, ccvchangesets.GenerateTokenVerifierConfigInput{
			ServiceIdentifier: "TokenVerifier",
			ChainSelectors:    selectors,
			PyroscopeURL:      template.PyroscopeURL,
			Monitoring: ccvdeployment.MonitoringConfig{
				Enabled: template.Monitoring.Enabled,
				Type:    template.Monitoring.Type,
				Beholder: ccvdeployment.BeholderConfig{
					InsecureConnection:       template.Monitoring.Beholder.InsecureConnection,
					CACertFile:               template.Monitoring.Beholder.CACertFile,
					OtelExporterGRPCEndpoint: template.Monitoring.Beholder.OtelExporterGRPCEndpoint,
					OtelExporterHTTPEndpoint: template.Monitoring.Beholder.OtelExporterHTTPEndpoint,
					LogStreamingEnabled:      template.Monitoring.Beholder.LogStreamingEnabled,
					MetricReaderInterval:     template.Monitoring.Beholder.MetricReaderInterval,
					TraceSampleRatio:         template.Monitoring.Beholder.TraceSampleRatio,
					TraceBatchTimeout:        template.Monitoring.Beholder.TraceBatchTimeout,
				},
			},
			Lombard: ccvchangesets.LombardConfigInput{
				VerifierID:     "LombardVerifier",
				Qualifier:      devenvcommon.LombardContractsQualifier,
				AttestationAPI: fakeOut.InternalHTTPURL + "/lombard",
			},
			CCTP: ccvchangesets.CCTPConfigInput{
				VerifierID:     "CCTPVerifier",
				AttestationAPI: fakeOut.InternalHTTPURL + "/cctp",
			},
		})
		if csErr != nil {
			return nil, nil, fmt.Errorf("tokenverifier: generating token verifier config: %w", csErr)
		}

		tokenVerifierCfg, cfgErr := ccvdeployment.GetTokenVerifierConfig(output.DataStore.Seal(), "TokenVerifier")
		if cfgErr != nil {
			return nil, nil, fmt.Errorf("tokenverifier: getting token verifier config: %w", cfgErr)
		}
		inputs[i].GeneratedConfig = tokenVerifierCfg
		localEnv.DataStore = output.DataStore.Seal()
	}

	for _, tvIn := range inputs {
		if tvIn == nil || tvIn.Mode != services.Standalone {
			continue
		}
		out, launchErr := services.NewTokenVerifier(tvIn, blockchainOutputs)
		if launchErr != nil {
			return nil, nil, fmt.Errorf("tokenverifier: launching %q: %w", tvIn.ContainerName, launchErr)
		}
		tvIn.Out = out
	}

	return map[string]any{configKey: inputs}, nil, nil
}

// decode round-trips the raw TOML []any into []*services.TokenVerifierInput.
func decode(raw any) ([]*services.TokenVerifierInput, error) {
	b, err := toml.Marshal(struct {
		V any `toml:"token_verifier"`
	}{V: raw})
	if err != nil {
		return nil, fmt.Errorf("re-encoding token_verifier config: %w", err)
	}
	var wrapper struct {
		V []*services.TokenVerifierInput `toml:"token_verifier"`
	}
	if err := toml.Unmarshal(b, &wrapper); err != nil {
		return nil, fmt.Errorf("decoding token_verifier config: %w", err)
	}
	return wrapper.V, nil
}
