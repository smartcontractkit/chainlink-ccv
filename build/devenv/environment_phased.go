package ccv

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/jobs"
	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	executorsvc "github.com/smartcontractkit/chainlink-ccv/build/devenv/services/executor"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/util"
	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	ccvadapters "github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	ccvchangesets "github.com/smartcontractkit/chainlink-ccv/deployment/changesets"
	ccvshared "github.com/smartcontractkit/chainlink-ccv/deployment/shared"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
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

	out, err := devenvruntime.NewEnvironment(ctx, rawConfig, L)
	if err != nil {
		return nil, err
	}

	cfg, ok := out[legacyCfgKey].(*Cfg)
	if !ok {
		return nil, fmt.Errorf("runtime did not return a *Cfg")
	}
	return cfg, nil
}

// runPhasedEnvironment is a fork of NewEnvironment's body. It is invoked by the
// legacy fallback component during the runtime's Phase 2 with a *Cfg whose
// Blockchains slice has already been deployed by the blockchains Phase 1
// component. As components are extracted from the monolith in subsequent PRs,
// the work in this function will shrink; the original NewEnvironment in
// environment_monolith.go remains the stable reference path.
func runPhasedEnvironment(ctx context.Context, cfg *Cfg) (in *Cfg, err error) {
	in = cfg
	timeTrack := NewTimeTracker(Plog)

	// track environment startup result and time using getDX app
	defer func() {
		dxTracker := initDxTracker()
		sendStartupMetrics(dxTracker, err, timeTrack.SinceStart().Seconds())
	}()

	ctx = L.WithContext(ctx)

	if err = in.expandForHA(); err != nil {
		return nil, fmt.Errorf("failed to expand HA configuration: %w", err)
	}

	// Executor config...
	if in.Executor != nil {
		for _, exec := range in.Executor {
			executorsvc.ApplyDefaults(exec)
		}
	}

	// Start fake data provider. Used for USDC verifier.
	fakeOut, err := services.NewFake(in.Fake)
	if err != nil {
		return nil, fmt.Errorf("failed to create fake data provider: %w", err)
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
		impl, err := NewProductConfigurationFromNetwork(bc.Type)
		if err != nil {
			return nil, err
		}
		impls[i] = impl
		blockchainOutputs[i] = bc.Out
	}

	///////////////////////////////////////
	// END: Resolve deployed blockchains //
	///////////////////////////////////////

	//////////////////////////////////////////////////
	// START: Generate Aggregator Credentials       //
	//////////////////////////////////////////////////

	// Generate HMAC credentials for all aggregator clients before launching
	// CL nodes, so they can receive the credentials via secrets.
	for _, agg := range in.Aggregator {
		creds, err := agg.EnsureClientCredentials()
		if err != nil {
			return nil, fmt.Errorf("failed to ensure client credentials for aggregator %s: %w", agg.CommitteeName, err)
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
	//////////////////////////////////////////
	// END: Generate Aggregator Credentials //
	//////////////////////////////////////////

	//////////////////////////////////
	// START: Deploy Pricer service //
	//////////////////////////////////
	if _, err := services.NewPricer(in.Pricer); err != nil {
		return nil, fmt.Errorf("failed to setup pricer service: %w", err)
	}

	if in.Pricer != nil {
		for i, impl := range impls {
			Plog.Info().Int("ImplIndex", i).Msg("Funding pricer key")
			err = impl.FundAddresses(
				ctx,
				in.Blockchains[i],
				[]protocol.UnknownAddress{common.HexToAddress(in.Pricer.Keystore.Address).Bytes()},
				big.NewInt(5),
			)
			if err != nil {
				return nil, fmt.Errorf("failed to fund pricer address: %w", err)
			}
			Plog.Info().Int("ImplIndex", i).Msg("Funded pricer address")
		}
	}

	////////////////////////////////
	// END: Deploy Pricer service //
	////////////////////////////////

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

	//////////////////////////
	// END: Launch CL Nodes //
	//////////////////////////

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

	jdInfra, err := jobs.StartJDInfrastructure(ctx, jobs.JDInfrastructureConfig{
		JDInput:  in.JD,
		NodeSets: in.NodeSets,
	})
	if err != nil {
		L.Error().Msg("Unable to start JD infrastructure." +
			"Make sure the container has been built with 'just build-jd-docker'.")
		return nil, fmt.Errorf("failed to start JD infrastructure: %w", err)
	}
	in.JDInfra = jdInfra

	// Only register and connect CL-mode NOPs with JD
	if jdInfra != nil && clientLookup != nil {
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

	/////////////////////////////////////
	// END: Start JD Infrastructure   //
	/////////////////////////////////////

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
	if jdInfra != nil && jdInfra.OffchainClient != nil {
		if err := registerStandaloneVerifiersWithJD(ctx, in.Verifier, jdInfra.OffchainClient); err != nil {
			return nil, err
		}
	}

	/////////////////////////////////////////////
	// END: Launch verifiers early            //
	/////////////////////////////////////////////

	/////////////////////////////
	// START: Deploy contracts //
	/////////////////////////////

	var selectors []uint64
	var e *deployment.Environment
	// the CLDF datastore is not initialized at this point because contracts are not deployed yet.
	// it will get populated in the loop below.
	in.CLDF.Init()

	cldfCfg := CLDFEnvironmentConfig{
		Blockchains: in.Blockchains,
		DataStore:   in.CLDF.DataStore,
	}
	if in.JDInfra != nil && in.JDInfra.OffchainClient != nil {
		cldfCfg.OffchainClient = in.JDInfra.OffchainClient
		cldfCfg.NodeIDs = in.JDInfra.GetNodeIDs()
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
	///////////////////////////
	// END: Deploy contracts //
	///////////////////////////

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
	// END: Connect chains to each other //
	/////////////////////////////////////////

	/////////////////////////////////////////
	// START: Launch generic services //
	/////////////////////////////////////////

	if err := launchGenericServices(ctx, in, e, blockchainOutputs); err != nil {
		return nil, fmt.Errorf("failed to launch generic services: %w", err)
	}

	/////////////////////////////////////////
	// END: Launch generic services //
	/////////////////////////////////////////

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
		var err error
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
		cs := ccvchangesets.GenerateAggregatorConfig(ccvadapters.GetRegistry())
		output, err := cs.Apply(*e, ccvchangesets.GenerateAggregatorConfigInput{
			Topology:           topology,
			ServiceIdentifier:  instanceName + "-aggregator",
			CommitteeQualifier: aggregatorInput.CommitteeName,
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

		out, err := services.NewAggregator(aggregatorInput)
		if err != nil {
			return nil, fmt.Errorf("failed to create aggregator service for committee %s: %w", aggregatorInput.CommitteeName, err)
		}
		in.AggregatorEndpoints[aggregatorInput.CommitteeName] = out.ExternalHTTPSUrl
		if out.TLSCACertFile != "" {
			in.AggregatorCACertFiles[aggregatorInput.CommitteeName] = out.TLSCACertFile
		}
		e.DataStore = output.DataStore.Seal()
	}

	///////////////////////////////
	// START: Launch aggregators //
	///////////////////////////////

	///////////////////////////
	// START: Launch indexer(s) //
	// start up the indexer(s) after the aggregators are up to avoid spamming of errors
	// in the logs when they start before the aggregators are up.
	///////////////////////////
	// Generate indexer config using changeset (on-chain state as source of truth).
	// One shared config is generated; all indexers use the same config and duplicated secrets/auth.
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

	// Ensure unique container names and DB host ports; always use indexer-1, indexer-2, ... for consistency.
	for i := range in.Indexer {
		if in.Indexer[i].ContainerName == "" {
			in.Indexer[i].ContainerName = fmt.Sprintf("indexer-%d", i+1)
		}
		if in.Indexer[i].DB != nil && in.Indexer[i].DB.HostPort == 0 && len(in.Indexer) > 1 {
			in.Indexer[i].DB.HostPort = services.DefaultIndexerDBPort + i
		}
		// Ensure StorageConnectionURL matches the DB container we create (indexer-1-db, indexer-2-db, ...).
		// Env.toml may have single-instance URLs; overwrite so migrations and storage use the correct host/credentials.
		idx := in.Indexer[i]
		dbName := idx.ContainerName
		if idx.DB != nil && idx.DB.Database != "" {
			dbName = idx.DB.Database
		}
		dbUser := idx.ContainerName
		if idx.DB != nil && idx.DB.Username != "" {
			dbUser = idx.DB.Username
		}
		dbPass := idx.ContainerName
		if idx.DB != nil && idx.DB.Password != "" {
			dbPass = idx.DB.Password
		}
		dbHost := idx.ContainerName + "-db"
		in.Indexer[i].StorageConnectionURL = fmt.Sprintf("postgresql://%s:%s@%s:5432/%s?sslmode=disable", dbUser, dbPass, dbHost, dbName)
	}

	if sharedTLSCerts == nil {
		return nil, fmt.Errorf("shared TLS certificates are required for indexer")
	}

	// Build discovery secrets from aggregators (same creds used for all indexers).
	// Ensure every discovery index 0..n-1 has an entry so the written secrets file has Discoveries.0, .1, ...;
	// otherwise the indexer can panic in CI with "discovery index 0 not found in secrets" when merging.
	discoverySecrets := make(map[string]config.DiscoverySecrets)
	verifierSecrets := make(map[string]config.VerifierSecrets)
	for idx, agg := range in.Aggregator {
		key := strconv.Itoa(idx)
		var disc config.DiscoverySecrets
		var ver config.VerifierSecrets
		if agg.Out != nil {
			if creds, ok := agg.Out.GetCredentialsForClient("indexer"); ok {
				disc = config.DiscoverySecrets{APIKey: creds.APIKey, Secret: creds.Secret}
				ver = config.VerifierSecrets{APIKey: creds.APIKey, Secret: creds.Secret}
			}
		}
		discoverySecrets[key] = disc
		verifierSecrets[key] = ver
	}

	externalURLs := make([]string, 0, len(in.Indexer))
	internalURLs := make([]string, 0, len(in.Indexer))

	for idxPos, idxIn := range in.Indexer {
		idxIn.TLSCACertFile = sharedTLSCerts.CACertFile

		idxIn.IndexerConfig.Discoveries = make([]config.DiscoveryConfig, len(in.Aggregator))
		for i, agg := range in.Aggregator {
			if agg.Out != nil {
				idxIn.IndexerConfig.Discoveries[i].Address = agg.Out.Address
				if creds, ok := agg.Out.GetCredentialsForClient("indexer"); ok {
					idxIn.IndexerConfig.Discoveries[i].APIKey = creds.APIKey
					idxIn.IndexerConfig.Discoveries[i].Secret = creds.Secret
				}
			}
			if idxIn.IndexerConfig.Discoveries[i].PollInterval == 0 {
				idxIn.IndexerConfig.Discoveries[i].PollInterval = 500
			}
			if idxIn.IndexerConfig.Discoveries[i].Timeout == 0 {
				idxIn.IndexerConfig.Discoveries[i].Timeout = 5000
			}
			if idxIn.IndexerConfig.Discoveries[i].NtpServer == "" {
				idxIn.IndexerConfig.Discoveries[i].NtpServer = "time.google.com"
			}
		}

		// Duplicate same secrets/auth for this indexer (Verifier push to indexer uses same creds).
		if idxIn.Secrets == nil {
			idxIn.Secrets = &config.SecretsConfig{
				Discoveries: make(map[string]config.DiscoverySecrets),
				Verifier:    make(map[string]config.VerifierSecrets),
			}
		}
		if idxIn.Secrets.Discoveries == nil {
			idxIn.Secrets.Discoveries = make(map[string]config.DiscoverySecrets)
		}
		if idxIn.Secrets.Verifier == nil {
			idxIn.Secrets.Verifier = make(map[string]config.VerifierSecrets)
		}
		maps.Copy(idxIn.Secrets.Discoveries, discoverySecrets)
		maps.Copy(idxIn.Secrets.Verifier, verifierSecrets)
		// Ensure storage secrets use the same DB URL we set on StorageConnectionURL (indexer loads secrets and overwrites config URI).
		idxIn.Secrets.Storage.Single.Postgres.URI = idxIn.StorageConnectionURL

		indexerOut, err := services.NewIndexer(idxIn)
		if err != nil {
			return nil, fmt.Errorf("failed to create indexer service (index %d): %w", idxPos, err)
		}
		externalURLs = append(externalURLs, indexerOut.ExternalHTTPURL)
		internalURLs = append(internalURLs, indexerOut.InternalHTTPURL)
	}

	in.IndexerEndpoints = externalURLs
	in.IndexerInternalEndpoints = internalURLs

	/////////////////////////
	// END: Launch indexer(s) //
	/////////////////////////

	/////////////////////////////
	// START: Launch executors //
	/////////////////////////////

	executorJobSpecs, err := generateExecutorJobSpecs(e, in, topology, ds)
	if err != nil {
		return nil, err
	}

	_, err = launchExecutors(in.Executor, blockchainOutputs, jdInfra)
	if err != nil {
		return nil, fmt.Errorf("failed to create executors: %w", err)
	}

	if err := fundExecutorTransmitters(ctx, in.Executor, in.Blockchains, impls); err != nil {
		return nil, fmt.Errorf("failed to fund executor transmitters: %w", err)
	}

	if jdInfra != nil && jdInfra.OffchainClient != nil {
		if err := registerExecutorsWithJD(ctx, in.Executor, jdInfra.OffchainClient); err != nil {
			return nil, err
		}
		if err := proposeJobsToExecutors(ctx, in.Executor, executorJobSpecs, blockchainOutputs, jdInfra.OffchainClient); err != nil {
			return nil, err
		}
	}

	///////////////////////////
	// END: Launch executors //
	///////////////////////////

	/////////////////////////////
	// START: Launch verifiers //
	/////////////////////////////

	verifierJobSpecs, err := generateVerifierJobSpecs(e, in, topology, sharedTLSCerts, ds)
	if err != nil {
		return nil, err
	}

	// Each verifier owns one aggregator (NodeIndex % numAggs). Select the
	// corresponding job spec so proposeJobsToStandaloneVerifiers gets a
	// single spec per container.
	ownedJobSpecs := make(map[string]bootstrap.JobSpec, len(verifierJobSpecs))
	for _, ver := range in.Verifier {
		specs := verifierJobSpecs[ver.NOPAlias]
		if len(specs) > 0 {
			ownedJobSpecs[ver.NOPAlias] = specs[ver.NodeIndex%len(specs)]
		}
	}

	// Propose jobs to standalone verifiers via JD
	if jdInfra != nil && jdInfra.OffchainClient != nil {
		if err := proposeJobsToStandaloneVerifiers(ctx, in.Verifier, ownedJobSpecs, blockchainOutputs, jdInfra.OffchainClient); err != nil {
			return nil, err
		}
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
			return nil, fmt.Errorf("fake data provider is required for token verifiers to provide attestation API endpoints, but it was not created successfully")
		}

		template, err := tokenVerifierInput.GenerateTemplateConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to generate template config for token verifier: %w", err)
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
			return nil, fmt.Errorf("failed to generate token verifier config: %w", err)
		}

		// Get generated config from output datastore
		tokenVerifierCfg, err := ccvdeployment.GetTokenVerifierConfig(
			output.DataStore.Seal(), "TokenVerifier",
		)
		if err != nil {
			return nil, fmt.Errorf("failed to get token verifier config from output: %w", err)
		}
		in.TokenVerifier[i].GeneratedConfig = tokenVerifierCfg
		e.DataStore = output.DataStore.Seal()
	}

	if fakeOut != nil {
		_, err = launchStandaloneTokenVerifiers(in, blockchainOutputs)
		if err != nil {
			return nil, fmt.Errorf("failed to create standalone token verifiers: %w", err)
		}
	}

	///////////////////////////////////
	// END: Launch token verifiers //
	///////////////////////////////////

	////////////////////////////////////////////////////
	// Jobs are now proposed via JD during changeset execution.
	// AcceptPendingJobs should be called after all changesets complete
	// to accept the proposed jobs on CL nodes.
	////////////////////////////////////////////////////

	e.DataStore = ds.Seal()

	if in.JDInfra != nil {
		if err := jobs.AcceptPendingJobs(ctx, in.ClientLookup); err != nil {
			return nil, fmt.Errorf("failed to accept pending jobs: %w", err)
		}

		if err := jobs.SyncAndVerifyJobProposals(e); err != nil {
			return nil, fmt.Errorf("failed to sync/verify job proposals: %w", err)
		}
	}

	timeTrack.Print()
	if err = PrintCLDFAddresses(in); err != nil {
		return nil, err
	}

	return in, Store(in)
}
