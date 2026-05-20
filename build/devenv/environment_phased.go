package ccv

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/timing"
	committeeverifier "github.com/smartcontractkit/chainlink-ccv/build/devenv/services/committeeverifier"
	executorsvc "github.com/smartcontractkit/chainlink-ccv/build/devenv/services/executor"
	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	ccvadapters "github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	ccvchangesets "github.com/smartcontractkit/chainlink-ccv/deployment/changesets"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

// NewPhasedEnvironment creates a new CCIP CCV environment using the phased
// component runtime. It loads the raw TOML config, hands control to the
// runtime, and extracts the resulting *Cfg produced by the legacy fallback
// component (see legacy_component.go).
func NewPhasedEnvironment() (in *Cfg, err error) {
	ctx := L.WithContext(context.Background())

	configs := strings.Split(os.Getenv(EnvVarTestConfigs), ",")
	if len(configs) > 1 {
		L.Warn().Msg("Multiple configuration files detected, this feature may be unsupported in the future.")
	}
	rawConfig, err := loadRaw(configs)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	out, err := devenvruntime.NewEnvironmentWithRegistry(ctx, rawConfig, devenvruntime.GlobalRegistry(), newDevenvEffectExecutor(), L)
	if err != nil {
		return nil, err
	}

	cfg, ok := out[legacyCfgKey].(*Cfg)
	if !ok {
		return nil, fmt.Errorf("runtime did not return a *Cfg")
	}
	return cfg, nil
}

// runPhasedEnvironmentFinish runs from executor job-spec generation through job
// proposal acceptance. It expects each IndexerInput's Out field to be populated
// by the indexer Phase 4 component (via services.NewIndexer), so URL collection
// can proceed without re-launching containers.
func runPhasedEnvironmentFinish(
	ctx context.Context,
	in *Cfg,
	e *deployment.Environment,
	topology *ccvdeployment.EnvironmentTopology,
	sharedTLSCerts *services.TLSCertPaths,
	blockchainOutputs []*blockchain.Output,
	selectors []uint64,
	ds datastore.MutableDataStore,
	fakeOut *services.FakeOutput,
	timeTrack *timing.TimeTracker,
) (cfg *Cfg, effects []devenvruntime.Effect, err error) {
	defer func() {
		dxTracker := initDxTracker()
		sendStartupMetrics(dxTracker, err, timeTrack.SinceStart().Seconds())
	}()

	// Collect aggregator endpoints from Out fields populated by the CommitteeCCV Phase 4 component.
	in.AggregatorEndpoints = make(map[string]string)
	in.AggregatorCACertFiles = make(map[string]string)
	for _, agg := range in.Aggregator {
		if agg.Out != nil {
			in.AggregatorEndpoints[agg.CommitteeName] = agg.Out.ExternalHTTPSUrl
			if agg.Out.TLSCACertFile != "" {
				in.AggregatorCACertFiles[agg.CommitteeName] = agg.Out.TLSCACertFile
			}
		}
	}

	// Collect indexer URLs from Out fields populated by the indexer Phase 4 component.
	externalURLs := make([]string, 0, len(in.Indexer))
	internalURLs := make([]string, 0, len(in.Indexer))
	for _, idxIn := range in.Indexer {
		if idxIn.Out != nil {
			externalURLs = append(externalURLs, idxIn.Out.ExternalHTTPURL)
			internalURLs = append(internalURLs, idxIn.Out.InternalHTTPURL)
		}
	}
	in.IndexerEndpoints = externalURLs
	in.IndexerInternalEndpoints = internalURLs

	/////////////////////////////
	// START: Launch executors //
	/////////////////////////////

	executorJobSpecs, err := generateExecutorJobSpecs(e, in, topology, ds)
	if err != nil {
		return nil, nil, err
	}

	for _, exec := range in.Executor {
		if exec == nil || exec.Mode != services.Standalone {
			continue
		}
		if exec.Out == nil || exec.Out.JDNodeID == "" {
			continue
		}
		reg, loaderErr := chainreg.GetRegistry().Get(exec.ChainFamily)
		if loaderErr != nil {
			return nil, nil, fmt.Errorf("chain registration for executor %s: %w", exec.ContainerName, loaderErr)
		}
		if reg.ChainConfigLoader == nil {
			return nil, nil, fmt.Errorf("chain config loader for family %s not found", exec.ChainFamily)
		}
		blockchainInfos, loaderErr := reg.ChainConfigLoader(blockchainOutputs)
		if loaderErr != nil {
			return nil, nil, fmt.Errorf("loading chain config for executor %s: %w", exec.ContainerName, loaderErr)
		}
		baseSpec, ok := executorJobSpecs[exec.ContainerName]
		if !ok {
			return nil, nil, fmt.Errorf("no job spec found for executor %s", exec.ContainerName)
		}
		jobSpec, specErr := executorsvc.RebuildExecutorJobSpecWithBlockchainInfos(baseSpec, blockchainInfos)
		if specErr != nil {
			return nil, nil, fmt.Errorf("building job spec for executor %s: %w", exec.ContainerName, specErr)
		}
		effects = append(effects, devenvruntime.JobProposalEffect{
			NOPAlias: exec.NOPAlias,
			NodeID:   exec.Out.JDNodeID,
			JobSpec:  jobSpec,
		})
	}

	///////////////////////////
	// END: Launch executors //
	///////////////////////////

	/////////////////////////////
	// START: Launch verifiers //
	/////////////////////////////

	verifierJobSpecs, err := generateVerifierJobSpecs(e, in, topology, sharedTLSCerts, ds)
	if err != nil {
		return nil, nil, err
	}

	for _, ver := range in.Verifier {
		if ver.Mode != services.Standalone {
			continue
		}
		if ver.Out == nil || ver.Out.JDNodeID == "" {
			return nil, nil, fmt.Errorf("verifier %s not registered with JD (missing JDNodeID)", ver.NOPAlias)
		}
		specs := verifierJobSpecs[ver.NOPAlias]
		if len(specs) == 0 {
			continue
		}
		baseSpec := specs[ver.NodeIndex%len(specs)]
		reg, loaderErr := chainreg.GetRegistry().Get(ver.ChainFamily)
		if loaderErr != nil {
			return nil, nil, fmt.Errorf("chain registration for verifier %s: %w", ver.NOPAlias, loaderErr)
		}
		if reg.ChainConfigLoader == nil {
			return nil, nil, fmt.Errorf("chain config loader for family %s not found", ver.ChainFamily)
		}
		blockchainInfos, loaderErr := reg.ChainConfigLoader(blockchainOutputs)
		if loaderErr != nil {
			return nil, nil, fmt.Errorf("loading chain config for verifier %s: %w", ver.NOPAlias, loaderErr)
		}
		jobSpec, specErr := committeeverifier.RebuildVerifierJobSpecWithBlockchainInfos(baseSpec, blockchainInfos)
		if specErr != nil {
			return nil, nil, fmt.Errorf("building job spec for verifier %s: %w", ver.NOPAlias, specErr)
		}
		effects = append(effects, devenvruntime.JobProposalEffect{
			NOPAlias: ver.NOPAlias,
			NodeID:   ver.Out.JDNodeID,
			JobSpec:  jobSpec,
		})
	}

	/////////////////////////////
	// END: Launch verifiers //
	/////////////////////////////

	///////////////////////////////////
	// START: Launch token verifiers //
	///////////////////////////////////

	// Generate token verifier configs using changeset (on-chain state as source of truth)
	for i, tokenVerifierInput := range in.TokenVerifier {
		if tokenVerifierInput == nil {
			continue
		}

		if fakeOut == nil {
			return nil, nil, fmt.Errorf("fake data provider is required for token verifiers to provide attestation API endpoints, but it was not created successfully")
		}

		template, err := tokenVerifierInput.GenerateTemplateConfig()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate template config for token verifier: %w", err)
		}

		// Use changeset to generate token verifier config from on-chain state
		cs := ccvchangesets.GenerateTokenVerifierConfig(ccvadapters.GetRegistry())
		output, err := cs.Apply(*e, ccvchangesets.GenerateTokenVerifierConfigInput{
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
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate token verifier config: %w", err)
		}

		// Get generated config from output datastore
		tokenVerifierCfg, err := ccvdeployment.GetTokenVerifierConfig(
			output.DataStore.Seal(), "TokenVerifier",
		)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get token verifier config from output: %w", err)
		}
		in.TokenVerifier[i].GeneratedConfig = tokenVerifierCfg
		e.DataStore = output.DataStore.Seal()
	}

	if fakeOut != nil {
		_, err = launchStandaloneTokenVerifiers(in, blockchainOutputs)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create standalone token verifiers: %w", err)
		}
	}

	///////////////////////////////////
	// END: Launch token verifiers //
	///////////////////////////////////

	e.DataStore = ds.Seal()

	// Save the env metadata to the output CLDF struct so that it can be used by tests.
	envMetadata, err := e.DataStore.EnvMetadata().Get()
	if err != nil && err != datastore.ErrEnvMetadataNotSet {
		return nil, nil, fmt.Errorf("failed to get env metadata from datastore: %w", err)
	}
	envMetadataJSON, err := json.Marshal(envMetadata)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal env metadata: %w", err)
	}
	in.CLDF.AddEnvMetadata(string(envMetadataJSON))

	timeTrack.Print()
	if err = PrintCLDFAddresses(in); err != nil {
		return nil, nil, err
	}

	return in, effects, Store(in)
}
