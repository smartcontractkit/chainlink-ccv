package ccv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccv/deployments"
	"github.com/smartcontractkit/chainlink-ccv/deployments/changesets"
	"github.com/smartcontractkit/chainlink-ccv/deployments/operations/shared"
	"github.com/smartcontractkit/chainlink-ccv/devenv/canton"
	"github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/devenv/evm"
	"github.com/smartcontractkit/chainlink-ccv/devenv/internal/util"
	"github.com/smartcontractkit/chainlink-ccv/devenv/jobs"
	"github.com/smartcontractkit/chainlink-ccv/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/clclient"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/clnode"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/jd"
	ns "github.com/smartcontractkit/chainlink-testing-framework/framework/components/simple_node_set"
)

const (
	CommonCLNodesConfig = `
			[Log]
			JSONConsole = true
			Level = 'info'
			[Pyroscope]
			ServerAddress = 'http://host.docker.internal:4040'
			Environment = 'local'
			[WebServer]
			SessionTimeout = '999h0m0s'
			HTTPWriteTimeout = '3m'
			SecureCookies = false
			HTTPPort = 6688
			AllowOrigins = 'http://localhost:3000'
			[WebServer.TLS]
			HTTPSPort = 0
			[WebServer.RateLimit]
			Authenticated = 5000
			Unauthenticated = 5000
			[JobPipeline]
			[JobPipeline.HTTPRequest]
			DefaultTimeout = '1m'
			[Log.File]
			MaxSize = '0b'
			[Feature]
			FeedsManager = true
			LogPoller = true
			UICSAKeys = true
			[OCR2]
			Enabled = true
			SimulateTransactions = false
			DefaultTransactionQueueDepth = 1
			[P2P.V2]
			Enabled = true
			ListenAddresses = ['0.0.0.0:6690']
`
)

type Cfg struct {
	CLDF               CLDF                           `toml:"cldf"                  validate:"required"`
	Pricer             *services.PricerInput          `toml:"pricer"                validate:"required"`
	Fake               *services.FakeInput            `toml:"fake"                  validate:"required"`
	Verifier           []*services.VerifierInput      `toml:"verifier"              validate:"required"`
	TokenVerifier      []*services.TokenVerifierInput `toml:"token_verifier"`
	Executor           []*services.ExecutorInput      `toml:"executor"              validate:"required"`
	Indexer            *services.IndexerInput         `toml:"indexer"               validate:"required"`
	Aggregator         []*services.AggregatorInput    `toml:"aggregator"            validate:"required"`
	JD                 *jd.Input                      `toml:"jd"                    validate:"required"`
	Blockchains        []*blockchain.Input            `toml:"blockchains"           validate:"required"`
	NodeSets           []*ns.Input                    `toml:"nodesets"              validate:"required"`
	CLNodesFundingETH  float64                        `toml:"cl_nodes_funding_eth"`
	CLNodesFundingLink float64                        `toml:"cl_nodes_funding_link"`
	// AggregatorEndpoints map the verifier qualifier to the aggregator URL for that verifier.
	AggregatorEndpoints map[string]string `toml:"aggregator_endpoints"`
	// AggregatorCACertFiles map the verifier qualifier to the CA cert file path for TLS verification.
	AggregatorCACertFiles map[string]string `toml:"aggregator_ca_cert_files"`
	// IndexerEndpoint is the external URL (localhost:port) for host access.
	IndexerEndpoint string `toml:"indexer_endpoint"`
	// IndexerInternalEndpoint is the internal Docker network URL for container-to-container access.
	IndexerInternalEndpoint string `toml:"indexer_internal_endpoint"`
	// EnvironmentTopology is the shared environment configuration for NOPs, committees, and executor pools.
	EnvironmentTopology *deployments.EnvironmentTopology `toml:"environment_topology" validate:"required"`
	// JDInfra holds the runtime JD infrastructure (not from config, populated at runtime).
	JDInfra *jobs.JDInfrastructure `toml:"-"`
	// ClientLookup provides ChainlinkClient lookup by NOP alias (populated at runtime).
	ClientLookup *jobs.NodeSetClientLookup `toml:"-"`
}

// NewAggregatorClientForCommittee creates an AggregatorClient for the specified committee.
// It automatically handles TLS configuration, using the CA cert file if available (devenv),
// or falling back to system certs (staging/prod).
func (c *Cfg) NewAggregatorClientForCommittee(logger zerolog.Logger, committeeName string) (*AggregatorClient, error) {
	endpoint, ok := c.AggregatorEndpoints[committeeName]
	if !ok {
		return nil, fmt.Errorf("no aggregator endpoint found for committee %s", committeeName)
	}

	caCertFile := c.AggregatorCACertFiles[committeeName]
	return NewAggregatorClient(logger, endpoint, caCertFile)
}

// checkKeys performs basic sanity checks on the private key being used depending on which chain is in
// the provided configuration.
func checkKeys(in *Cfg) error {
	evmSimChainIDs := []string{"1337", "2337", "3337"}

	// get the blockchains that are evm chains
	evmBlockchains := make([]*blockchain.Input, 0)
	for _, bc := range in.Blockchains {
		if bc.Type == "anvil" {
			evmBlockchains = append(evmBlockchains, bc)
		}
	}
	for _, bc := range evmBlockchains {
		if getNetworkPrivateKey() != DefaultAnvilKey && slices.Contains(evmSimChainIDs, bc.ChainID) {
			return errors.New("you are trying to run simulated chains with a key that do not belong to Anvil, please run 'unset PRIVATE_KEY'")
		}
		if getNetworkPrivateKey() == DefaultAnvilKey && !slices.Contains(evmSimChainIDs, bc.ChainID) {
			return errors.New("you are trying to run on real networks but is not using the Anvil private key, export your private key 'export PRIVATE_KEY=...'")
		}
	}

	return nil
}

func NewProductConfigurationFromNetwork(typ string) (cciptestinterfaces.CCIP17Configuration, error) {
	switch typ {
	case "anvil":
		return evm.NewEmptyCCIP17EVM(), nil
	case "canton":
		return canton.New(
			log.
				Output(zerolog.ConsoleWriter{Out: os.Stderr}).
				Level(zerolog.DebugLevel).
				With().
				Fields(map[string]any{"component": "Canton"}).
				Logger(),
		), nil
	default:
		return nil, errors.New("unknown devenv network type " + typ)
	}
}

// enrichEnvironmentTopology injects SignerAddress values from verifier inputs into the EnvironmentTopology.
// This is needed because signer addresses are only known after key generation or CL node launch.
// Each verifier's NOPAlias identifies which NOP in the topology it belongs to.
// Only the first verifier for each NOP sets the signer address (subsequent verifiers with the
// same NOPAlias are ignored to avoid overwriting with wrong keys due to round-robin wrap-around).
func enrichEnvironmentTopology(cfg *deployments.EnvironmentTopology, verifiers []*services.VerifierInput) {
	seenAliases := make(map[string]struct{})
	for _, ver := range verifiers {
		if _, seen := seenAliases[ver.NOPAlias]; seen {
			continue
		}
		if nop, ok := cfg.NOPTopology.GetNOP(ver.NOPAlias); ok {
			if nop.GetMode() == shared.NOPModeCL {
				// For CL mode the signer address should be fetch from JD
				continue
			}
			if nop.SignerAddressByFamily[chainsel.FamilyEVM] == "" {
				cfg.NOPTopology.SetNOPSignerAddress(ver.NOPAlias, chainsel.FamilyEVM, ver.SigningKeyPublic)
			}
			if nop.SignerAddressByFamily[chainsel.FamilyCanton] == "" {
				cfg.NOPTopology.SetNOPSignerAddress(ver.NOPAlias, chainsel.FamilyCanton, ver.SigningKeyPublic)
			}
			seenAliases[ver.NOPAlias] = struct{}{}
		}
	}
}

// buildEnvironmentTopology creates a copy of the EnvironmentTopology from the Cfg,
// enriches it with signer addresses, and returns it. This is used by both executor
// and verifier changesets as the single source of truth.
func buildEnvironmentTopology(in *Cfg) *deployments.EnvironmentTopology {
	if in.EnvironmentTopology == nil {
		return nil
	}
	envCfg := *in.EnvironmentTopology
	enrichEnvironmentTopology(&envCfg, in.Verifier)
	return &envCfg
}

// generateExecutorJobSpecs generates job specs for all executors using the changeset.
// It returns a map of container name -> job spec for use in CL mode.
// For standalone mode, it also sets GeneratedConfig on each executor.
// The ds parameter is a mutable datastore that will be updated with the changeset output.
func generateExecutorJobSpecs(
	ctx context.Context,
	e *deployment.Environment,
	in *Cfg,
	selectors []uint64,
	impls []cciptestinterfaces.CCIP17Configuration,
	topology *deployments.EnvironmentTopology,
	ds datastore.MutableDataStore,
) (map[string]string, error) {
	executorJobSpecs := make(map[string]string)

	if len(in.Executor) == 0 {
		return executorJobSpecs, nil
	}

	// Group executors by qualifier
	executorsByQualifier := make(map[string][]*services.ExecutorInput)
	for _, exec := range in.Executor {
		qualifier := exec.ExecutorQualifier
		if qualifier == "" {
			qualifier = devenvcommon.DefaultExecutorQualifier
		}
		executorsByQualifier[qualifier] = append(executorsByQualifier[qualifier], exec)
	}

	// Generate configs for each qualifier group
	for qualifier, qualifierExecutors := range executorsByQualifier {
		execNOPAliases := make([]string, 0, len(qualifierExecutors))
		for _, exec := range qualifierExecutors {
			execNOPAliases = append(execNOPAliases, exec.NOPAlias)
		}

		cs := changesets.ApplyExecutorConfig()
		output, err := cs.Apply(*e, changesets.ApplyExecutorConfigCfg{
			Topology:          topology,
			ExecutorQualifier: qualifier,
			ChainSelectors:    selectors,
			TargetNOPs:        shared.ConvertStringToNopAliases(execNOPAliases),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to generate executor configs for qualifier %s: %w", qualifier, err)
		}

		if err := ds.Merge(output.DataStore.Seal()); err != nil {
			return nil, fmt.Errorf("failed to merge executor job specs datastore: %w", err)
		}

		for _, exec := range qualifierExecutors {
			jobSpecID := shared.NewExecutorJobID(shared.NOPAlias(exec.NOPAlias), shared.ExecutorJobScope{ExecutorQualifier: qualifier})
			job, err := deployments.GetJob(output.DataStore.Seal(), shared.NOPAlias(exec.NOPAlias), jobSpecID.ToJobID())
			if err != nil {
				return nil, fmt.Errorf("failed to get executor job spec for %s: %w", exec.ContainerName, err)
			}
			jobSpec := job.Spec
			executorJobSpecs[exec.ContainerName] = jobSpec

			// Extract inner config from job spec for standalone mode
			execCfg, err := ParseExecutorConfigFromJobSpec(jobSpec)
			if err != nil {
				return nil, fmt.Errorf("failed to parse executor config from job spec: %w", err)
			}

			// Marshal the inner config back to TOML for standalone mode
			configBytes, err := toml.Marshal(execCfg)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal executor config: %w", err)
			}
			exec.GeneratedConfig = string(configBytes)
		}
	}

	// Set transmitter keys for standalone mode
	_, err := services.SetTransmitterPrivateKey(in.Executor)
	if err != nil {
		return nil, fmt.Errorf("failed to set transmitter private key: %w", err)
	}

	// Fund executor addresses for standalone mode
	addresses := make([]protocol.UnknownAddress, 0, len(in.Executor))
	for _, exec := range in.Executor {
		addresses = append(addresses, exec.GetTransmitterAddress())
	}
	Plog.Info().Any("Addresses", addresses).Int("ImplsLen", len(impls)).Msg("Funding executors")
	for i, impl := range impls {
		if in.Blockchains[i].Type == blockchain.TypeCanton {
			// Executor doesn't support Canton.
			continue
		}

		Plog.Info().Int("ImplIndex", i).Msg("Funding executor")
		err = impl.FundAddresses(ctx, in.Blockchains[i], addresses, big.NewInt(5))
		if err != nil {
			return nil, fmt.Errorf("failed to fund addresses for executors: %w", err)
		}
		Plog.Info().Int("ImplIndex", i).Msg("Funded executors")
	}

	return executorJobSpecs, nil
}

// generateVerifierJobSpecs generates job specs for all verifiers using the changeset.
// It returns a map of container name -> job spec for use in CL mode.
// For standalone mode, it also sets GeneratedConfig on each verifier.
// The ds parameter is a mutable datastore that will be updated with the changeset output.
func generateVerifierJobSpecs(
	e *deployment.Environment,
	in *Cfg,
	selectors []uint64,
	topology *deployments.EnvironmentTopology,
	sharedTLSCerts *services.TLSCertPaths,
	ds datastore.MutableDataStore,
) (map[string]string, error) {
	verifierJobSpecs := make(map[string]string)

	if len(in.Verifier) == 0 {
		return verifierJobSpecs, nil
	}

	// Group verifiers by committee for batch generation
	verifiersByCommittee := make(map[string][]*services.VerifierInput)
	for _, ver := range in.Verifier {
		verifiersByCommittee[ver.CommitteeName] = append(verifiersByCommittee[ver.CommitteeName], ver)
	}

	// Generate verifier configs per committee
	for committeeName, committeeVerifiers := range verifiersByCommittee {
		verNOPAliases := make([]shared.NOPAlias, 0, len(committeeVerifiers))
		for _, ver := range committeeVerifiers {
			verNOPAliases = append(verNOPAliases, shared.NOPAlias(ver.NOPAlias))
		}

		// Extract and validate DisableFinalityCheckers - all verifiers in the same
		// committee must have the same setting since it's applied at the committee level.
		disableFinalityCheckers, err := extractAndValidateDisableFinalityCheckers(committeeName, committeeVerifiers)
		if err != nil {
			return nil, err
		}

		cs := changesets.ApplyVerifierConfig()
		output, err := cs.Apply(*e, changesets.ApplyVerifierConfigCfg{
			Topology:                 topology,
			CommitteeQualifier:       committeeName,
			DefaultExecutorQualifier: devenvcommon.DefaultExecutorQualifier,
			ChainSelectors:           selectors,
			TargetNOPs:               verNOPAliases,
			DisableFinalityCheckers:  disableFinalityCheckers,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to generate verifier configs for committee %s: %w", committeeName, err)
		}

		if err := ds.Merge(output.DataStore.Seal()); err != nil {
			return nil, fmt.Errorf("failed to merge verifier job specs datastore: %w", err)
		}

		for _, ver := range committeeVerifiers {
			aggNames, err := topology.GetAggregatorNamesForCommittee(committeeName)
			if err != nil {
				return nil, err
			}
			// TODO: We assume that there is only one agg per committee, no HA setup support
			jobSpecID := shared.NewVerifierJobID(shared.NOPAlias(ver.NOPAlias), aggNames[0], shared.VerifierJobScope{CommitteeQualifier: committeeName})
			job, err := deployments.GetJob(output.DataStore.Seal(), shared.NOPAlias(ver.NOPAlias), jobSpecID.ToJobID())
			if err != nil {
				return nil, fmt.Errorf("failed to get verifier job spec for %s: %w", ver.ContainerName, err)
			}
			jobSpec := job.Spec
			verifierJobSpecs[ver.ContainerName] = jobSpec

			// Extract inner config from job spec for standalone mode
			verCfg, err := ParseVerifierConfigFromJobSpec(jobSpec)
			if err != nil {
				return nil, fmt.Errorf("failed to parse verifier config from job spec: %w", err)
			}

			// Marshal the inner config back to TOML for standalone mode
			configBytes, err := toml.Marshal(verCfg)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal verifier config: %w", err)
			}
			ver.GeneratedConfig = string(configBytes)

			if sharedTLSCerts != nil && !ver.InsecureAggregatorConnection {
				ver.TLSCACertFile = sharedTLSCerts.CACertFile
			}
		}
	}

	return verifierJobSpecs, nil
}

// NewEnvironment creates a new CCIP CCV environment locally in Docker.
func NewEnvironment() (in *Cfg, err error) {
	ctx := context.Background()
	timeTrack := NewTimeTracker(Plog)

	// track environment startup result and time using getDX app
	defer func() {
		dxTracker := initDxTracker()
		sendStartupMetrics(dxTracker, err, timeTrack.SinceStart().Seconds())
	}()

	ctx = L.WithContext(ctx)
	if err = framework.DefaultNetwork(nil); err != nil {
		return nil, err
	}

	/////////////////////////////
	// START: Read Config toml //
	/////////////////////////////

	configs := strings.Split(os.Getenv(EnvVarTestConfigs), ",")
	if len(configs) > 1 {
		L.Warn().Msg("Multiple configuration files detected, this feature may be unsupported in the future.")
	}
	in, err = Load[Cfg](configs)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	// Executor config...
	if in.Executor != nil {
		for _, exec := range in.Executor {
			services.ApplyExecutorDefaults(exec)
		}
	}

	/////////////////////////////
	// END: Read Config toml //
	/////////////////////////////

	// Start fake data provider. Used for USDC verifier.
	fakeOut, err := services.NewFake(in.Fake)
	if err != nil {
		return nil, fmt.Errorf("failed to create fake data provider: %w", err)
	}

	///////////////////////////////
	// START: Deploy blockchains //
	// The services crash if the RPC is not available.
	///////////////////////////////
	if err = checkKeys(in); err != nil {
		return nil, err
	}

	impls := make([]cciptestinterfaces.CCIP17Configuration, 0)
	for _, bc := range in.Blockchains {
		var impl cciptestinterfaces.CCIP17Configuration
		impl, err = NewProductConfigurationFromNetwork(bc.Type)
		if err != nil {
			return nil, err
		}
		impls = append(impls, impl)
	}

	blockchainOutputs := make([]*blockchain.Output, len(impls))
	for i, impl := range impls {
		out, err := impl.DeployLocalNetwork(ctx, in.Blockchains[i])
		if err != nil {
			return nil, fmt.Errorf("failed to deploy local networks: %w", err)
		}

		blockchainOutputs[i] = out
	}

	/////////////////////////////
	// END: Deploy blockchains //
	/////////////////////////////

	///////////////////////////////////////////
	// START: Generate Aggregator Credentials //
	// Generate HMAC credentials for all aggregator clients before launching
	// CL nodes, so they can receive the credentials via secrets.
	///////////////////////////////////////////
	for _, agg := range in.Aggregator {
		creds, err := agg.EnsureClientCredentials()
		if err != nil {
			return nil, fmt.Errorf("failed to ensure client credentials for aggregator %s: %w", agg.CommitteeName, err)
		}
		for clientID, c := range creds {
			Plog.Debug().
				Str("aggregator", agg.CommitteeName).
				Str("clientID", clientID).
				Str("apiKey", c.APIKey[:8]+"...").
				Msg("Generated aggregator credentials")
		}
	}
	/////////////////////////////////////////
	// END: Generate Aggregator Credentials //
	/////////////////////////////////////////

	///////////////////////////////
	// START: Deploy Pricer service //
	///////////////////////////////
	if _, err := services.NewPricer(in.Pricer); err != nil {
		return nil, fmt.Errorf("failed to setup pricer service: %w", err)
	}

	if in.Pricer != nil {
		for i, impl := range impls {
			if in.Blockchains[i].Type == blockchain.TypeCanton {
				continue
			}
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

	///////////////////////////////
	// END: Deploy Pricer service //
	///////////////////////////////

	////////////////////////////
	// START: Launch CL Nodes //
	// We launch the CL nodes first because they don't require any configuration from
	// the rest of the system to be up and running.
	// In addition, if we need to launch the nodes (i.e if some services are not standalone),
	// we need to launch the nodes first to get the onchain public keys which will then
	// be used to configure the rest of the system (aggregator, onchain committees, etc.).
	////////////////////////////

	timeTrack.Record("[infra] deploying CL nodes")
	_, err = launchCLNodes(ctx, in, impls, in.Verifier, in.Aggregator)
	if err != nil {
		return nil, fmt.Errorf("failed to launch CL nodes: %w", err)
	}
	timeTrack.Record("[infra] deployed CL nodes")

	//////////////////////////
	// END: Launch CL Nodes //
	//////////////////////////

	///////////////////////////////////////
	// START: Start JD Infrastructure   //
	///////////////////////////////////////

	timeTrack.Record("[infra] starting JD infrastructure")

	// Extract only CL-mode NOP aliases for JD/client operations
	// Standalone NOPs don't have CL nodes and don't need JD registration
	clModeNopAliases := make([]string, 0)
	if in.EnvironmentTopology != nil && in.EnvironmentTopology.NOPTopology != nil {
		for _, nop := range in.EnvironmentTopology.NOPTopology.NOPs {
			if nop.GetMode() == shared.NOPModeCL {
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
	// START: Assign signing keys to verifiers //
	/////////////////////////////////////////////
	for i := range in.Verifier {
		ver := services.ApplyVerifierDefaults(*in.Verifier[i])

		switch ver.Mode {
		case services.CL:
			// no-op signing key is fetched from JD with changeset
		case services.Standalone:
			// deterministic key generation algorithm.
			ver.SigningKey = util.XXXNewVerifierPrivateKey(ver.CommitteeName, ver.NodeIndex)

			privateKey, err := commit.ReadPrivateKeyFromString(ver.SigningKey)
			if err != nil {
				return nil, fmt.Errorf("failed to load private key: %w", err)
			}
			_, publicKey, err := commit.NewECDSAMessageSigner(privateKey)
			if err != nil {
				return nil, fmt.Errorf("failed to create message signer: %w", err)
			}
			ver.SigningKeyPublic = publicKey.String()

		default:
			return nil, fmt.Errorf("unsupported verifier mode: %s", ver.Mode)
		}

		// Apply changes back to input.
		in.Verifier[i] = &ver
	}
	/////////////////////////////////////////////
	// END: Assign signing keys to verifiers //
	/////////////////////////////////////////////

	/////////////////////////////////////////
	// START: Build shared EnvironmentTopology //
	// Used by contract deployment and off-chain config //
	/////////////////////////////////////////
	topology := buildEnvironmentTopology(in)

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

	timeTrack.Record("[infra] deploying blockchains")
	ds := datastore.NewMemoryDataStore()
	for i, impl := range impls {
		var networkInfo chainsel.ChainDetails
		networkInfo, err = chainsel.GetChainDetailsByChainIDAndFamily(in.Blockchains[i].ChainID, impl.ChainFamily())
		if err != nil {
			return nil, err
		}
		L.Info().Uint64("Selector", networkInfo.ChainSelector).Msg("Deployed chain selector")
		var dsi datastore.DataStore
		dsi, err = impl.DeployContractsForSelector(ctx, e, networkInfo.ChainSelector, topology)
		if err != nil {
			return nil, err
		}
		var addresses []datastore.AddressRef
		addresses, err = dsi.Addresses().Fetch()
		if err != nil {
			return nil, err
		}
		var a []byte
		a, err = json.Marshal(addresses)
		if err != nil {
			return nil, err
		}
		in.CLDF.AddAddresses(string(a))
		if err = ds.Merge(dsi); err != nil {
			return nil, err
		}
	}
	e.DataStore = ds.Seal()
	///////////////////////////
	// END: Deploy contracts //
	///////////////////////////

	/////////////////////////////////////////
	// START: Connect chains to each other //
	/////////////////////////////////////////

	for i, impl := range impls {
		if in.Blockchains[i].Type == blockchain.TypeCanton {
			// Canton contracts are not supported yet by the interface, tests need to connect them manually.
			continue
		}

		var networkInfo chainsel.ChainDetails
		networkInfo, err = chainsel.GetChainDetailsByChainIDAndFamily(in.Blockchains[i].ChainID, impl.ChainFamily())
		if err != nil {
			return nil, err
		}
		selsToConnect := make([]uint64, 0)
		for _, sel := range selectors {
			if sel != networkInfo.ChainSelector {
				selsToConnect = append(selsToConnect, sel)
			}
		}
		err = impl.ConnectContractsWithSelectors(ctx, e, networkInfo.ChainSelector, selsToConnect, topology)
		if err != nil {
			return nil, err
		}
	}

	/////////////////////////////////////////
	// END: Connect chains to each other //
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
			nginxName := fmt.Sprintf("%s-%s", agg.CommitteeName, services.AggregatorNginxContainerNameSuffix)
			aggName := fmt.Sprintf("%s-%s", agg.CommitteeName, services.AggregatorContainerNameSuffix)
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
		cs := changesets.GenerateAggregatorConfig()
		output, err := cs.Apply(*e, changesets.GenerateAggregatorConfigCfg{
			ServiceIdentifier:  aggregatorInput.CommitteeName + "-aggregator",
			CommitteeQualifier: aggregatorInput.CommitteeName,
			ChainSelectors:     selectors,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to generate aggregator config for committee %s: %w", aggregatorInput.CommitteeName, err)
		}

		// Get generated config from output datastore
		aggCfg, err := deployments.GetAggregatorConfig(output.DataStore.Seal(), aggregatorInput.CommitteeName+"-aggregator")
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
	// START: Launch indexer //
	// start up the indexer after the aggregators are up to avoid spamming of errors
	// in the logs when it starts before the aggregators are up.
	///////////////////////////
	// Generate indexer config using changeset (on-chain state as source of truth)
	if len(in.Aggregator) > 0 && in.Indexer != nil {
		cs := changesets.GenerateIndexerConfig()
		output, err := cs.Apply(*e, changesets.GenerateIndexerConfigCfg{
			ServiceIdentifier:                "indexer",
			CommitteeVerifierNameToQualifier: in.Indexer.CommitteeVerifierNameToQualifier,
			CCTPVerifierNameToQualifier:      in.Indexer.CCTPVerifierNameToQualifier,
			ChainSelectors:                   selectors,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to generate indexer config: %w", err)
		}

		idxCfg, err := deployments.GetIndexerConfig(output.DataStore.Seal(), "indexer")
		if err != nil {
			return nil, fmt.Errorf("failed to get indexer config from output: %w", err)
		}
		in.Indexer.GeneratedCfg = idxCfg
		e.DataStore = output.DataStore.Seal()
	}

	// Set TLS CA cert for indexer (all aggregators share the same CA)
	if sharedTLSCerts != nil {
		in.Indexer.TLSCACertFile = sharedTLSCerts.CACertFile
		// Update discovery config to use nginx TLS proxy
		if len(in.Aggregator) > 0 && in.Aggregator[0].Out != nil {
			in.Indexer.IndexerConfig.Discovery.Address = in.Aggregator[0].Out.Address
		}
	}

	// Inject generated credentials into indexer secrets for aggregator connections
	if in.Indexer != nil && in.Indexer.Secrets == nil {
		in.Indexer.Secrets = &config.SecretsConfig{
			Verifier: make(map[string]config.VerifierSecrets),
		}
	}
	if in.Indexer != nil && in.Indexer.Secrets != nil && in.Indexer.Secrets.Verifier == nil {
		in.Indexer.Secrets.Verifier = make(map[string]config.VerifierSecrets)
	}

	// Discovery uses the first aggregator's indexer credentials
	if len(in.Aggregator) > 0 {
		if creds, ok := in.Aggregator[0].Out.GetCredentialsForClient("indexer"); ok {
			in.Indexer.Secrets.Discovery.APIKey = creds.APIKey
			in.Indexer.Secrets.Discovery.Secret = creds.Secret
		}
	}

	// Each verifier config needs credentials from its corresponding aggregator
	for idx, agg := range in.Aggregator {
		if creds, ok := agg.Out.GetCredentialsForClient("indexer"); ok {
			in.Indexer.Secrets.Verifier[strconv.Itoa(idx)] = config.VerifierSecrets{
				APIKey: creds.APIKey,
				Secret: creds.Secret,
			}
		}
	}

	indexerOut, err := services.NewIndexer(in.Indexer)
	if err != nil {
		return nil, fmt.Errorf("failed to create indexer service: %w", err)
	}

	if in.Indexer != nil {
		in.IndexerEndpoint = indexerOut.ExternalHTTPURL
		in.IndexerInternalEndpoint = indexerOut.InternalHTTPURL
	}

	/////////////////////////
	// END: Launch indexer //
	/////////////////////////

	/////////////////////////////
	// START: Launch executors //
	/////////////////////////////

	_, err = generateExecutorJobSpecs(ctx, e, in, selectors, impls, topology, ds)
	if err != nil {
		return nil, err
	}

	_, err = launchStandaloneExecutors(in.Executor, blockchainOutputs)
	if err != nil {
		return nil, fmt.Errorf("failed to create standalone executor: %w", err)
	}

	///////////////////////////
	// END: Launch executors //
	///////////////////////////

	/////////////////////////////
	// START: Launch verifiers //
	/////////////////////////////

	_, err = generateVerifierJobSpecs(e, in, selectors, topology, sharedTLSCerts, ds)
	if err != nil {
		return nil, err
	}

	_, err = launchStandaloneVerifiers(in, blockchainOutputs)
	if err != nil {
		return nil, fmt.Errorf("failed to create standalone verifiers: %w", err)
	}

	/////////////////////////////
	// END: Launch verifiers //
	/////////////////////////////

	///////////////////////////////////
	// START: Launch token verifiers //
	///////////////////////////////////

	for i := range in.TokenVerifier {
		ver, err := services.ResolveContractsForTokenVerifier(e.DataStore, in.Blockchains, *in.TokenVerifier[i])
		if err != nil {
			return nil, fmt.Errorf("failed to lookup contracts: %w", err)
		}

		in.TokenVerifier[i] = &ver
	}

	if fakeOut != nil {
		_, err = launchStandaloneTokenVerifiers(in, fakeOut.InternalHTTPURL, blockchainOutputs)
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

// launchCLNodes encapsulates the logic required to launch the core node. It may be better to wrap this in a service.
// It returns the onchain public keys for each chain type for each CL node.
func launchCLNodes(
	ctx context.Context,
	in *Cfg,
	impls []cciptestinterfaces.CCIP17Configuration,
	vIn []*services.VerifierInput,
	aggregators []*services.AggregatorInput,
) (map[string][]string, error) {
	aggByCommittee := make(map[string]*services.AggregatorInput)
	for _, agg := range aggregators {
		aggByCommittee[agg.CommitteeName] = agg
	}

	// Exit early, there are no nodes configured.
	if len(in.NodeSets) == 0 {
		return nil, nil
	}

	hasAService := false
	for _, ver := range in.Verifier {
		hasAService = hasAService || (ver.Mode == services.CL)
	}

	for _, exec := range in.Executor {
		hasAService = hasAService || (exec.Mode == services.CL)
	}

	// Exit early, there are no services configured to deploy on a CL node.
	if !hasAService {
		return nil, nil
	}

	var err error
	clChainConfigs := make([]string, 0)
	clChainConfigs = append(clChainConfigs, CommonCLNodesConfig)
	for i, impl := range impls {
		var clChainConfig string
		clChainConfig, err = impl.ConfigureNodes(ctx, in.Blockchains[i])
		if err != nil {
			return nil, fmt.Errorf("failed to deploy local networks: %w", err)
		}
		clChainConfigs = append(clChainConfigs, clChainConfig)
	}
	allConfigs := strings.Join(clChainConfigs, "\n")

	for _, nodeSet := range in.NodeSets {
		for _, nodeSpec := range nodeSet.NodeSpecs {
			nodeSpec.Node.TestConfigOverrides = allConfigs
		}
	}

	// set the secret keys of the aggregator for each verifier ID
	nodeSpecs := make([]*clnode.Input, 0)
	for _, nodeSet := range in.NodeSets {
		nodeSpecs = append(nodeSpecs, nodeSet.NodeSpecs...)
	}
	aggSecretsPerNode := make(map[int][]AggregatorSecret)
	for _, ver := range vIn {
		index, ok := in.EnvironmentTopology.NOPTopology.GetNOPIndex(ver.NOPAlias)
		if !ok {
			return nil, fmt.Errorf("NOP alias %q not found in topology for verifier %s", ver.NOPAlias, ver.ContainerName)
		}
		if index >= len(nodeSpecs) {
			return nil, fmt.Errorf("node index %d from NOPAlias %s exceeds available nodes (%d)",
				index, ver.NOPAlias, len(nodeSpecs))
		}
		agg := aggByCommittee[ver.CommitteeName]
		apiKeys, err := agg.GetAPIKeys()
		if err != nil {
			return nil, fmt.Errorf("failed to get API keys for aggregator %s: %w", agg.CommitteeName, err)
		}
		Plog.Info().
			Int("index", index).
			Str("verifier", ver.ContainerName).
			Str("committee", ver.CommitteeName).
			Any("apiKeys", apiKeys).
			Msg("getting API keys for verifier")
		var found bool
		for _, apiClient := range apiKeys {
			if apiClient.ClientID == ver.ContainerName {
				if len(apiClient.APIKeyPairs) == 0 {
					return nil, fmt.Errorf("no API key pairs found for client %s", apiClient.ClientID)
				}
				apiKeyPair := apiClient.APIKeyPairs[0]
				verifierID := fmt.Sprintf("default-%s-verifier", ver.CommitteeName)
				Plog.Debug().
					Int("nodeIndex", index).
					Str("verifier", ver.ContainerName).
					Str("committee", ver.CommitteeName).
					Str("verifierID", verifierID).
					Str("apiKey", apiKeyPair.APIKey[:8]+"...").
					Msg("Passing aggregator credentials to CL node")
				aggSecretsPerNode[index] = append(aggSecretsPerNode[index], AggregatorSecret{
					VerifierID: verifierID,
					APIKey:     apiKeyPair.APIKey,
					APISecret:  apiKeyPair.Secret,
				})
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("failed to find API client for verifier %s on node %d", ver.ContainerName, index)
		}
	}
	idx := 0
	for i, nodeSet := range in.NodeSets {
		for j := range nodeSet.NodeSpecs {
			if len(aggSecretsPerNode[idx]) == 0 {
				return nil, fmt.Errorf("no aggregator secrets found for node %d", i+j)
			}

			secrets := Secrets{
				CCV: CCVSecrets{
					AggregatorSecrets: aggSecretsPerNode[idx],
				},
			}
			secretsToml, err := secrets.TomlString()
			if err != nil {
				return nil, fmt.Errorf("failed to marshal CCV secrets to TOML: %w", err)
			}
			in.NodeSets[i].NodeSpecs[j].Node.TestSecretsOverrides = secretsToml
			Plog.Info().Msg("overrode secrets for node")
			fmt.Println(secretsToml)
			idx++
		}
	}
	Plog.Info().Msg("Nodes network configuration is generated")

	for _, nodeset := range in.NodeSets {
		_, err = ns.NewSharedDBNodeSet(nodeset, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create new shared db node set: %w", err)
		}
	}
	// Fund nodes...
	for i, impl := range impls {
		if err = impl.FundNodes(ctx, in.NodeSets, in.Blockchains[i], big.NewInt(1), big.NewInt(5)); err != nil {
			return nil, fmt.Errorf("failed to fund nodes: %w", err)
		}
	}

	// Configured keys on CL nodes
	clClients := make([]*clclient.ChainlinkClient, 0)

	for _, ns := range in.NodeSets {
		nc, err := clclient.New(ns.Out.CLNodes)
		if err != nil {
			return nil, fmt.Errorf("failed to connect CL node clients")
		}
		clClients = append(clClients, nc...)
	}
	onchainPublicKeys := make(map[string][]string) // chainType -> onchain public keys
	for _, cc := range clClients {
		ocr2Keys, err := cc.MustReadOCR2Keys()
		if err != nil {
			return nil, fmt.Errorf("failed to read OCR2 keys: %w", err)
		}
		for _, keyData := range ocr2Keys.Data {
			onchainPublicKeys[keyData.Attributes.ChainType] = append(
				onchainPublicKeys[keyData.Attributes.ChainType],
				prefixWith0xIfNeeded(
					// the stringified keys have ocr2on_<chainType>_ as a prefix prior to actually getting
					// the hex public key, so needs to be trimmed first before we can use it everywhere
					// else.
					strings.TrimPrefix(
						keyData.Attributes.OnChainPublicKey,
						fmt.Sprintf("ocr2on_%s_", keyData.Attributes.ChainType),
					),
				),
			)
		}
		Plog.Info().Any("OCR2Keys", ocr2Keys.Data).Msg("Read OCR2 keys from node")
	}

	Plog.Info().Any("OnchainPublicKeys", onchainPublicKeys).Msg("Onchain public keys for all nodes")

	return onchainPublicKeys, nil
}

func launchStandaloneExecutors(in []*services.ExecutorInput, blockchainOutputs []*blockchain.Output) ([]*services.ExecutorOutput, error) {
	var outs []*services.ExecutorOutput
	// Start standalone executors if they are in standalone mode.
	for _, exec := range in {
		if exec != nil && exec.Mode == services.Standalone {
			out, err := services.NewExecutor(exec, blockchainOutputs)
			if err != nil {
				return nil, fmt.Errorf("failed to create executor service: %w", err)
			}
			outs = append(outs, out)
		}
	}
	return outs, nil
}

func launchStandaloneVerifiers(in *Cfg, blockchainOutputs []*blockchain.Output) ([]*services.VerifierOutput, error) {
	aggregatorOutputByCommittee := make(map[string]*services.AggregatorOutput)
	for _, agg := range in.Aggregator {
		if agg.Out != nil {
			aggregatorOutputByCommittee[agg.CommitteeName] = agg.Out
		}
	}

	var outs []*services.VerifierOutput
	// Start standalone verifiers if in standalone mode.
	for _, ver := range in.Verifier {
		if ver.Mode == services.Standalone {
			if aggOut, ok := aggregatorOutputByCommittee[ver.CommitteeName]; ok {
				ver.AggregatorOutput = aggOut
			}
			out, err := services.NewVerifier(ver, blockchainOutputs)
			if err != nil {
				return nil, fmt.Errorf("failed to create verifier service: %w", err)
			}
			ver.Out = out
			outs = append(outs, out)
		}
	}
	return outs, nil
}

func launchStandaloneTokenVerifiers(in *Cfg, fakeAttestationServiceURL string, blockchainOutputs []*blockchain.Output) ([]*services.TokenVerifierOutput, error) {
	var outs []*services.TokenVerifierOutput
	for _, ver := range in.TokenVerifier {
		if ver.Mode == services.Standalone {
			out, err := services.NewTokenVerifier(ver, fakeAttestationServiceURL, blockchainOutputs)
			if err != nil {
				return nil, fmt.Errorf("failed to create token verifier service: %w", err)
			}
			outs = append(outs, out)
		}
	}
	return outs, nil
}

func prefixWith0xIfNeeded(s string) string {
	if strings.HasPrefix(s, "0x") {
		return s
	}
	return "0x" + s
}

// TODO: this is copied from the toml secret structures in the CL node.
// We can't really import anything from there so this duplication is
// currently necessary.
type Secrets struct {
	CCV CCVSecrets `toml:",omitempty"`
}

func (c *Secrets) TomlString() (string, error) {
	data, err := toml.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("failed to marshal CCV secrets to TOML: %w", err)
	}
	return string(data), nil
}

type CCVSecrets struct {
	AggregatorSecrets []AggregatorSecret `toml:",omitempty"`
	IndexerSecret     *IndexerSecret     `toml:",omitempty"`
}

type AggregatorSecret struct {
	VerifierID string `toml:",omitempty"`
	APIKey     string `toml:",omitempty"`
	APISecret  string `toml:",omitempty"`
}

type IndexerSecret struct {
	APIKey    string `toml:",omitempty"`
	APISecret string `toml:",omitempty"`
}

// VerifierJobSpec represents the structure of a verifier job spec TOML.
type VerifierJobSpec struct {
	SchemaVersion           int    `toml:"schemaVersion"`
	Type                    string `toml:"type"`
	CommitteeVerifierConfig string `toml:"committeeVerifierConfig"`
}

// ParseVerifierConfigFromJobSpec extracts the inner commit.Config from a verifier job spec.
func ParseVerifierConfigFromJobSpec(jobSpec string) (*commit.Config, error) {
	var spec VerifierJobSpec
	if err := toml.Unmarshal([]byte(jobSpec), &spec); err != nil {
		return nil, fmt.Errorf("failed to parse job spec: %w", err)
	}

	var cfg commit.Config
	if err := toml.Unmarshal([]byte(spec.CommitteeVerifierConfig), &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse verifier config from job spec: %w", err)
	}

	return &cfg, nil
}

// ExecutorJobSpec represents the structure of an executor job spec TOML.
type ExecutorJobSpec struct {
	SchemaVersion  int    `toml:"schemaVersion"`
	Type           string `toml:"type"`
	ExecutorConfig string `toml:"executorConfig"`
}

// ParseExecutorConfigFromJobSpec extracts the inner executor.Configuration from an executor job spec.
func ParseExecutorConfigFromJobSpec(jobSpec string) (*executor.Configuration, error) {
	var spec ExecutorJobSpec
	if err := toml.Unmarshal([]byte(jobSpec), &spec); err != nil {
		return nil, fmt.Errorf("failed to parse job spec: %w", err)
	}

	var cfg executor.Configuration
	if err := toml.Unmarshal([]byte(spec.ExecutorConfig), &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse executor config from job spec: %w", err)
	}

	return &cfg, nil
}

// extractAndValidateDisableFinalityCheckers extracts DisableFinalityCheckers from verifiers
// in a committee and validates that all verifiers have the same setting.
func extractAndValidateDisableFinalityCheckers(committeeName string, verifiers []*services.VerifierInput) ([]string, error) {
	if len(verifiers) == 0 {
		return nil, nil
	}

	reference := verifiers[0].DisableFinalityCheckers
	for i := 1; i < len(verifiers); i++ {
		if !slicesEqual(reference, verifiers[i].DisableFinalityCheckers) {
			return nil, fmt.Errorf(
				"verifiers in committee %q have inconsistent disable_finality_checkers settings: "+
					"verifier %q has %v, but verifier %q has %v",
				committeeName,
				verifiers[0].ContainerName, reference,
				verifiers[i].ContainerName, verifiers[i].DisableFinalityCheckers,
			)
		}
	}

	return reference, nil
}

// slicesEqual compares two string slices for equality.
func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
