package ccv

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/jobs"
	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/chainconfig"
	committeeverifier "github.com/smartcontractkit/chainlink-ccv/build/devenv/services/committeeverifier"
	executorsvc "github.com/smartcontractkit/chainlink-ccv/build/devenv/services/executor"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/util"
	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	ccvadapters "github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	ccvchangesets "github.com/smartcontractkit/chainlink-ccv/deployment/changesets"
	ccvshared "github.com/smartcontractkit/chainlink-ccv/deployment/shared"
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

// phasedSetup carries all state produced by runPhasedEnvironmentSetup so that
// runPhasedEnvironmentFinish can complete the environment without re-deriving it.
type phasedSetup struct {
	In                *Cfg
	E                 *deployment.Environment
	Topology          *ccvdeployment.EnvironmentTopology
	SharedTLSCerts    *services.TLSCertPaths
	BlockchainOutputs []*blockchain.Output
	Selectors         []uint64
	DS                datastore.MutableDataStore
	Impls             []cciptestinterfaces.CCIP17Configuration
	FakeOut           *services.FakeOutput
	TimeTrack         *TimeTracker
}

// runPhasedEnvironmentSetup runs through aggregator config generation and
// indexer config generation. Aggregator container launch is delegated to the
// CommitteeCCV Phase 4 component, which reads "aggregators" and calls
// services.NewAggregator, mutating the shared *AggregatorInput pointers.
// Indexer container naming, TLS wiring, discovery config, and secrets are
// delegated to the indexer Phase 4 component. runPhasedEnvironmentFinish
// collects endpoints from the mutated Out fields on those shared pointers.
func runPhasedEnvironmentSetup(ctx context.Context, in *Cfg) (*phasedSetup, error) {
	var err error
	timeTrack := NewTimeTracker(Plog)
	ctx = L.WithContext(ctx)

	if err = in.expandForHA(); err != nil {
		return nil, fmt.Errorf("failed to expand HA configuration: %w", err)
	}

	// Fake container started by Phase 1 component; read its output here.
	var fakeOut *services.FakeOutput
	if in.Fake != nil {
		fakeOut = in.Fake.Out
	}

	///////////////////////////////////////
	// START: Resolve deployed blockchains
	// Networks themselves were brought up in Phase 1 by the blockchains
	// component; here we just build the per-chain CCIP17Configuration impls
	// and gather the deploy Outputs that downstream services need.
	///////////////////////////////////////

	impls := make([]cciptestinterfaces.CCIP17Configuration, len(in.Blockchains))
	blockchainOutputs := make([]*blockchain.Output, len(in.Blockchains))
	for i, bc := range in.Blockchains {
		if bc.Out == nil {
			return nil, fmt.Errorf("blockchain[%d] %q: phase 1 did not populate Out", i, bc.ContainerName)
		}
		impl, ierr := NewProductConfigurationFromNetwork(bc.Type)
		if ierr != nil {
			return nil, ierr
		}
		impls[i] = impl
		blockchainOutputs[i] = bc.Out
	}

	//////////////////////////////////////////////////
	// START: Generate Aggregator Credentials       //
	//////////////////////////////////////////////////

	// Generate HMAC credentials for all aggregator clients before launching
	// CL nodes, so they can receive the credentials via secrets.
	for _, agg := range in.Aggregator {
		creds, cerr := agg.EnsureClientCredentials()
		if cerr != nil {
			return nil, fmt.Errorf("failed to ensure client credentials for aggregator %s: %w", agg.CommitteeName, cerr)
		}

		// Set the aggregator output client credentials so that the verifier has access to it.
		if agg.Out == nil {
			agg.Out = &services.AggregatorOutput{}
		}
		agg.Out.ClientCredentials = creds

		for clientID, c := range creds {
			Plog.Debug().
				Str("aggregator", agg.CommitteeName).
				Str("clientID", clientID).
				Str("apiKey", c.APIKey[:8]+"...").
				Msg("Generated aggregator credentials")
		}
	}

	// Pricer container started and funded by Phase 3 pricer component.

	////////////////////////////
	// START: Launch CL Nodes //
	////////////////////////////

	// We launch the CL nodes first because they don't require any configuration from
	// the rest of the system to be up and running.
	// In addition, if we need to launch the nodes (i.e if some services are not standalone),
	// we need to launch the nodes first to get the onchain public keys which will then
	// be used to configure the rest of the system (aggregator, onchain committees, etc.).
	timeTrack.Record("[infra] deploying CL nodes")
	_, err = launchCLNodes(ctx, in, impls, in.Verifier, in.Aggregator)
	if err != nil {
		return nil, fmt.Errorf("failed to launch CL nodes: %w", err)
	}
	timeTrack.Record("[infra] deployed CL nodes")

	//////////////////////////////////////
	// START: Start JD Infrastructure   //
	//////////////////////////////////////

	timeTrack.Record("[infra] starting JD infrastructure")

	// Extract only CL-mode NOP aliases for JD/client operations
	// Standalone NOPs don't have CL nodes and don't need JD registration
	clModeNopAliases := make([]string, 0)
	if in.EnvironmentTopology != nil && in.EnvironmentTopology.NOPTopology != nil {
		for _, nop := range in.EnvironmentTopology.NOPTopology.NOPs {
			if nop.GetMode() == ccvshared.NOPModeCL {
				clModeNopAliases = append(clModeNopAliases, nop.Alias)
			}
		}
	} else {
		L.Warn().Msg("No environment topology defined, skipping NOP alias extraction")
	}

	// Create client lookup only for CL-mode NOPs (returns nil if no CL nodes)
	clientLookup, err := jobs.NewNodeSetClientLookup(in.NodeSets, clModeNopAliases)
	if err != nil {
		return nil, fmt.Errorf("failed to create NodeSet client lookup: %w", err)
	}
	in.ClientLookup = clientLookup

	if in.JDInfra == nil {
		return nil, fmt.Errorf("JD infrastructure was not started by Phase 2 component")
	}
	jdInfra := in.JDInfra

	// Only register and connect CL-mode NOPs with JD
	if clientLookup != nil {
		if err := jobs.RegisterNodesWithJD(ctx, jdInfra, clientLookup, clModeNopAliases); err != nil {
			return nil, fmt.Errorf("failed to register nodes with JD: %w", err)
		}

		chainIDs := make([]string, len(in.Blockchains))
		for i, bc := range in.Blockchains {
			chainIDs[i] = bc.ChainID
		}

		if err := jobs.ConnectNodesToJD(ctx, jdInfra, clientLookup, chainIDs); err != nil {
			return nil, fmt.Errorf("failed to connect nodes to JD: %w", err)
		}
	}
	timeTrack.Record("[infra] started JD infrastructure")

	/////////////////////////////////////////////
	// START: Launch verifiers early //
	// Verifiers generate their own keys on startup, so we need to start them
	// early and query /info to discover signing addresses before contract deployment.
	// Aggregator HMAC credentials are already available (generated above),
	// even though aggregator containers haven't started yet.
	/////////////////////////////////////////////

	_, err = launchStandaloneVerifiers(in, blockchainOutputs, jdInfra)
	if err != nil {
		return nil, fmt.Errorf("failed to launch standalone verifiers: %w", err)
	}

	// Register standalone verifiers with JD so they can receive job proposals.
	if err := registerStandaloneVerifiersWithJD(ctx, in.Verifier, jdInfra.OffchainClient); err != nil {
		return nil, err
	}

	/////////////////////////////
	// START: Deploy contracts //
	/////////////////////////////

	var selectors []uint64
	var e *deployment.Environment
	// the CLDF datastore is not initialized at this point because contracts are not deployed yet.
	// it will get populated in the loop below.
	in.CLDF.Init()

	cldfCfg := CLDFEnvironmentConfig{
		Blockchains:    in.Blockchains,
		DataStore:      in.CLDF.DataStore,
		OffchainClient: in.JDInfra.OffchainClient,
		NodeIDs:        in.JDInfra.GetNodeIDs(),
	}
	selectors, e, err = NewCLDFOperationsEnvironmentWithOffchain(cldfCfg)
	if err != nil {
		return nil, fmt.Errorf("creating CLDF operations environment: %w", err)
	}
	L.Info().Any("Selectors", selectors).Msg("Deploying for chain selectors")

	topology := buildEnvironmentTopology(in, e)
	if topology == nil {
		return nil, fmt.Errorf("failed to build environment topology")
	}

	timeTrack.Record("[infra] deploying blockchains")
	// Collect pool capabilities from all impls and compute valid cross-chain combinations.
	capsBySelector := make(map[uint64][]devenvcommon.PoolCapability, len(impls))
	for i, impl := range impls {
		networkInfo, lookupErr := chainsel.GetChainDetailsByChainIDAndFamily(in.Blockchains[i].ChainID, impl.ChainFamily())
		if lookupErr != nil {
			return nil, lookupErr
		}
		if tcp, ok := impl.(cciptestinterfaces.TokenConfigProvider); ok {
			capsBySelector[networkInfo.ChainSelector] = tcp.GetSupportedPools()
		} else {
			capsBySelector[networkInfo.ChainSelector] = nil
		}
	}
	combos := devenvcommon.ComputeTokenCombinations(capsBySelector, topology)

	ds := datastore.NewMemoryDataStore()
	for i, impl := range impls {
		var networkInfo chainsel.ChainDetails
		networkInfo, err = chainsel.GetChainDetailsByChainIDAndFamily(in.Blockchains[i].ChainID, impl.ChainFamily())
		if err != nil {
			return nil, err
		}
		L.Info().Uint64("Selector", networkInfo.ChainSelector).Msg("Deployed chain selector")
		// The goal here is to shift the nonce for the deployer to intentionally create different contract addresses on each chain.
		// This helps catch a class of bugs that occur if we assume all chains have the same contract addresses.
		// In practice we want to use CREATE2 and share the same contract addresses across chains. However not all chains support CREATE2.
		if bumper, ok := impl.(cciptestinterfaces.DeployerNonceBumper); ok && i > 0 {
			if err := bumper.BumpDeployerNonce(ctx, e, networkInfo.ChainSelector, i); err != nil {
				return nil, fmt.Errorf("failed to bump deployer nonce for chain %d: %w", networkInfo.ChainSelector, err)
			}
		}
		// Per-chain accumulator so we can report all addresses deployed in
		// this iteration (core contracts + tokens) to in.CLDF.
		chainDS := datastore.NewMemoryDataStore()

		var dsi datastore.DataStore
		dsi, err = DeployContractsForSelector(ctx, e, impl, networkInfo.ChainSelector, topology)
		if err != nil {
			return nil, err
		}
		if err = ds.Merge(dsi); err != nil {
			return nil, err
		}
		if err = chainDS.Merge(dsi); err != nil {
			return nil, err
		}
		e.DataStore = ds.Seal()

		// Deploy generic tokens and pools via the chain-agnostic path.
		// USDC and Lombard stay inside DeployContractsForSelector.
		tokenDS := datastore.NewMemoryDataStore()
		if tcp, ok := impl.(cciptestinterfaces.TokenConfigProvider); ok {
			if err = DeployTokensAndPools(tcp, e, networkInfo.ChainSelector, combos, tokenDS); err != nil {
				return nil, fmt.Errorf("deploy tokens and pools for selector %d: %w", networkInfo.ChainSelector, err)
			}
		}
		if err = ds.Merge(tokenDS.Seal()); err != nil {
			return nil, err
		}
		if err = chainDS.Merge(tokenDS.Seal()); err != nil {
			return nil, err
		}
		e.DataStore = ds.Seal()

		var addresses []datastore.AddressRef
		addresses, err = chainDS.Seal().Addresses().Fetch()
		if err != nil {
			return nil, err
		}
		var a []byte
		a, err = json.Marshal(addresses)
		if err != nil {
			return nil, err
		}
		in.CLDF.AddAddresses(string(a))
	}
	e.DataStore = ds.Seal()

	/////////////////////////////////////////
	// START: Connect chains to each other //
	/////////////////////////////////////////

	// Configure cross-chain token transfers: each chain impl builds its own
	// TokenTransferConfigs using chain-specific registry and CCV refs.
	if err = ConfigureAllTokenTransfers(impls, selectors, e, topology); err != nil {
		return nil, fmt.Errorf("configure all token transfers: %w", err)
	}

	var connectErr error
	if in.UseLegacyConfigureLane {
		connectErr = connectAllChainsLegacy(impls, in.Blockchains, selectors, e, topology)
	} else {
		connectErr = connectAllChainsCanonical(impls, in.Blockchains, selectors, e, topology)
	}
	if connectErr != nil {
		return nil, connectErr
	}

	/////////////////////////////////////////
	// START: Launch generic services //
	/////////////////////////////////////////

	if err := launchGenericServices(ctx, in, e, blockchainOutputs); err != nil {
		return nil, fmt.Errorf("failed to launch generic services: %w", err)
	}

	///////////////////////////////
	// START: Launch aggregators //
	///////////////////////////////

	in.AggregatorEndpoints = make(map[string]string)
	in.AggregatorCACertFiles = make(map[string]string)

	// Generate shared TLS certificates for all aggregators
	var sharedTLSCerts *services.TLSCertPaths
	if len(in.Aggregator) > 0 {
		var allHostnames []string
		for _, agg := range in.Aggregator {
			nginxName := fmt.Sprintf("%s-%s", agg.InstanceName(), services.AggregatorNginxContainerNameSuffix)
			aggName := fmt.Sprintf("%s-%s", agg.InstanceName(), services.AggregatorContainerNameSuffix)
			allHostnames = append(allHostnames, nginxName, aggName)
		}
		allHostnames = append(allHostnames, "localhost")

		tlsCertDir := filepath.Join(util.CCVConfigDir(), "tls-shared")
		sharedTLSCerts, err = services.GenerateTLSCertificates(allHostnames, tlsCertDir)
		if err != nil {
			return nil, fmt.Errorf("failed to generate shared TLS certificates: %w", err)
		}
	}

	// Generate aggregator configs using changesets (on-chain state as source of truth)
	for _, aggregatorInput := range in.Aggregator {
		aggregatorInput.SharedTLSCerts = sharedTLSCerts

		// Use changeset to generate committee config from on-chain state
		instanceName := aggregatorInput.InstanceName()
		committee, ok := topology.NOPTopology.Committees[aggregatorInput.CommitteeName]
		if !ok {
			return nil, fmt.Errorf("committee %q not found in topology", aggregatorInput.CommitteeName)
		}
		cs := ccvchangesets.GenerateAggregatorConfig(ccvadapters.GetRegistry())
		output, err := cs.Apply(*e, ccvchangesets.GenerateAggregatorConfigInput{
			ServiceIdentifier:  instanceName + "-aggregator",
			CommitteeQualifier: aggregatorInput.CommitteeName,
			ChainSelectors:     ccvchangesets.CommitteeChainSelectorsFromTopology(committee),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to generate aggregator config for %s (committee %s): %w", instanceName, aggregatorInput.CommitteeName, err)
		}

		// Get generated config from output datastore
		aggCfg, err := ccvdeployment.GetAggregatorConfig(output.DataStore.Seal(), instanceName+"-aggregator")
		if err != nil {
			return nil, fmt.Errorf("failed to get aggregator config from output: %w", err)
		}
		aggregatorInput.GeneratedCommittee = aggCfg
		e.DataStore = output.DataStore.Seal()
		// Aggregator container launch is handled by the CommitteeCCV Phase 4 component,
		// which reads "aggregators" from the phase snapshot and calls services.NewAggregator.
	}

	///////////////////////////
	// START: Prepare indexer inputs //
	// Generate indexer config using changeset (on-chain state as source of truth).
	// One shared config is generated; all indexers use the same config and duplicated secrets/auth.
	///////////////////////////
	if len(in.Aggregator) > 0 && len(in.Indexer) > 0 {
		firstIdx := in.Indexer[0]
		cs := ccvchangesets.GenerateIndexerConfig(ccvadapters.GetRegistry())
		output, err := cs.Apply(*e, ccvchangesets.GenerateIndexerConfigInput{
			ServiceIdentifier:                "indexer",
			CommitteeVerifierNameToQualifier: firstIdx.CommitteeVerifierNameToQualifier,
			CCTPVerifierNameToQualifier:      firstIdx.CCTPVerifierNameToQualifier,
			LombardVerifierNameToQualifier:   firstIdx.LombardVerifierNameToQualifier,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to generate indexer config: %w", err)
		}

		idxCfg, err := ccvdeployment.GetIndexerConfig(output.DataStore.Seal(), "indexer")
		if err != nil {
			return nil, fmt.Errorf("failed to get indexer config from output: %w", err)
		}
		e.DataStore = output.DataStore.Seal()
		for _, idxIn := range in.Indexer {
			idxIn.GeneratedCfg = idxCfg
		}
	}

	if len(in.Indexer) < 1 {
		return nil, fmt.Errorf("at least one indexer is required")
	}

	// Indexer container naming, DB wiring, TLS, discovery config, and secrets
	// are handled by the indexer Phase 4 component, which reads "aggregators"
	// and "shared_tls_certs" from the phase snapshot and mutates the shared
	// *IndexerInput pointers. runPhasedEnvironmentFinish reads idxIn.Out via
	// those same pointers for URL collection.

	return &phasedSetup{
		In:                in,
		E:                 e,
		Topology:          topology,
		SharedTLSCerts:    sharedTLSCerts,
		BlockchainOutputs: blockchainOutputs,
		Selectors:         selectors,
		DS:                ds,
		Impls:             impls,
		FakeOut:           fakeOut,
		TimeTrack:         timeTrack,
	}, nil
}

// runPhasedEnvironmentFinish runs from executor job-spec generation through job
// proposal acceptance. It expects each IndexerInput's Out field to be populated
// by the indexer Phase 4 component (via services.NewIndexer), so URL collection
// can proceed without re-launching containers.
func runPhasedEnvironmentFinish(ctx context.Context, setup *phasedSetup) (cfg *Cfg, effects []devenvruntime.Effect, err error) {
	defer func() {
		dxTracker := initDxTracker()
		sendStartupMetrics(dxTracker, err, setup.TimeTrack.SinceStart().Seconds())
	}()

	in := setup.In
	e := setup.E
	topology := setup.Topology
	sharedTLSCerts := setup.SharedTLSCerts
	blockchainOutputs := setup.BlockchainOutputs
	ds := setup.DS
	fakeOut := setup.FakeOut

	// Collect aggregator endpoints from Out fields populated by the CommitteeCCV Phase 4 component.
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
		loader, loaderErr := chainconfig.GetChainConfigLoader(exec.ChainFamily)
		if loaderErr != nil {
			return nil, nil, fmt.Errorf("chain config loader for executor %s: %w", exec.ContainerName, loaderErr)
		}
		blockchainInfos, loaderErr := loader(blockchainOutputs)
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
		loader, loaderErr := chainconfig.GetChainConfigLoader(ver.ChainFamily)
		if loaderErr != nil {
			return nil, nil, fmt.Errorf("chain config loader for verifier %s: %w", ver.NOPAlias, loaderErr)
		}
		blockchainInfos, loaderErr := loader(blockchainOutputs)
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
			ChainSelectors:    setup.Selectors,
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

	setup.TimeTrack.Print()
	if err = PrintCLDFAddresses(in); err != nil {
		return nil, nil, err
	}

	return in, effects, Store(in)
}
