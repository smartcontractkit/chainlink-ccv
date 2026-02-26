package ccv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"

	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/evm"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/jobs"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/registry"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/committeeverifier"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/util"
	"github.com/smartcontractkit/chainlink-ccv/deployments"
	"github.com/smartcontractkit/chainlink-ccv/deployments/changesets"
	"github.com/smartcontractkit/chainlink-ccv/deployments/operations/shared"
	"github.com/smartcontractkit/chainlink-ccv/deployments/sequences"
	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/offchain"
	jobv1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/job"
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
	Verifier           []*committeeverifier.Input     `toml:"verifier"              validate:"required"`
	TokenVerifier      []*services.TokenVerifierInput `toml:"token_verifier"`
	Executor           []*services.ExecutorInput      `toml:"executor"              validate:"required"`
	Indexer            []*services.IndexerInput       `toml:"indexer"               validate:"required"`
	Aggregator         []*services.AggregatorInput    `toml:"aggregator"            validate:"required"`
	JD                 *jd.Input                      `toml:"jd"                    validate:"required"`
	Blockchains        []*blockchain.Input            `toml:"blockchains"           validate:"required"`
	NodeSets           []*ns.Input                    `toml:"nodesets"              validate:"required"`
	CLNodesFundingETH  float64                        `toml:"cl_nodes_funding_eth"`
	CLNodesFundingLink float64                        `toml:"cl_nodes_funding_link"`
	// HighAvailability enables devenv-level service redundancy. When true,
	// expandForHA() clones AggregatorInput / IndexerInput entries according
	// to their per-service redundancy counts and updates the topology.
	HighAvailability bool `toml:"high_availability"`
	// AggregatorEndpoints map the verifier qualifier to the aggregator URL for that verifier.
	AggregatorEndpoints map[string]string `toml:"aggregator_endpoints"`
	// AggregatorCACertFiles map the verifier qualifier to the CA cert file path for TLS verification.
	AggregatorCACertFiles map[string]string `toml:"aggregator_ca_cert_files"`
	// IndexerEndpoints holds external URLs for all indexers (localhost:port).
	IndexerEndpoints []string `toml:"indexer_endpoints"`
	// IndexerInternalEndpoints holds internal Docker network URLs for all indexers.
	IndexerInternalEndpoints []string `toml:"indexer_internal_endpoints"`
	// EnvironmentTopology is the shared environment configuration for NOPs, committees, and executor pools.
	EnvironmentTopology *deployments.EnvironmentTopology `toml:"environment_topology" validate:"required"`
	// JDInfra holds the runtime JD infrastructure (not from config, populated at runtime).
	JDInfra *jobs.JDInfrastructure `toml:"-"`
	// ClientLookup provides ChainlinkClient lookup by NOP alias (populated at runtime).
	ClientLookup *jobs.NodeSetClientLookup `toml:"-"`
}

// expandForHA clones AggregatorInput / IndexerInput entries based on their
// per-service redundancy counts and updates the EnvironmentTopology so that
// downstream changesets and service launches see the expanded set.
// When HighAvailability is false this is a no-op.
func (c *Cfg) expandForHA() error {
	if !c.HighAvailability {
		return nil
	}
	if err := c.expandAggregators(); err != nil {
		return fmt.Errorf("expanding aggregators for HA: %w", err)
	}
	if err := c.expandIndexers(); err != nil {
		return fmt.Errorf("expanding indexers for HA: %w", err)
	}
	return nil
}

func (c *Cfg) expandAggregators() error {
	if c.EnvironmentTopology == nil || c.EnvironmentTopology.NOPTopology == nil {
		return nil
	}

	// Find the current max port number so we can increment from there
	var maxHostPort, maxDBPort, maxRedisPort int
	for _, agg := range c.Aggregator {
		if agg.HostPort > maxHostPort {
			maxHostPort = agg.HostPort
		}
		if agg.DB != nil && agg.DB.HostPort > maxDBPort {
			maxDBPort = agg.DB.HostPort
		}
		if agg.Redis != nil && agg.Redis.HostPort > maxRedisPort {
			maxRedisPort = agg.Redis.HostPort
		}
	}

	nextHostPort := maxHostPort + 1
	nextDBPort := maxDBPort + 1
	nextRedisPort := maxRedisPort + 1

	var clones []*services.AggregatorInput

	for _, agg := range c.Aggregator {
		if agg.RedundantAggregators <= 0 {
			continue
		}

		committee, ok := c.EnvironmentTopology.NOPTopology.Committees[agg.CommitteeName]
		if !ok {
			return fmt.Errorf("committee %q not found in topology for aggregator %q", agg.CommitteeName, agg.InstanceName())
		}

		insecure := false
		if len(committee.Aggregators) > 0 {
			insecure = committee.Aggregators[0].InsecureAggregatorConnection
		}

		for i := range agg.RedundantAggregators {
			cloneName := fmt.Sprintf("%s-ha-%d", agg.InstanceName(), i+1)

			clone := &services.AggregatorInput{
				Image:                              agg.Image,
				Name:                               cloneName,
				HostPort:                           nextHostPort,
				SourceCodePath:                     agg.SourceCodePath,
				RootPath:                           agg.RootPath,
				CommitteeName:                      agg.CommitteeName,
				MonitoringOtelExporterHTTPEndpoint: agg.MonitoringOtelExporterHTTPEndpoint,
				AggregationChannelBufferSize:       agg.AggregationChannelBufferSize,
				BackgroundWorkerCount:              agg.BackgroundWorkerCount,
				APIClients:                         deepCopyAggregatorAPIClients(agg.APIClients),
			}

			if agg.DB != nil {
				clone.DB = &services.AggregatorDBInput{
					Image:    agg.DB.Image,
					HostPort: nextDBPort,
				}
			}

			if agg.Redis != nil {
				clone.Redis = &services.AggregatorRedisInput{
					Image:    agg.Redis.Image,
					HostPort: nextRedisPort,
				}
			}

			clone.Env = &services.AggregatorEnvConfig{
				StorageConnectionURL: fmt.Sprintf(
					"postgresql://%s:%s@%s-%s:5432/%s?sslmode=disable",
					services.DefaultAggregatorDBUsername,
					services.DefaultAggregatorDBPassword,
					cloneName, services.AggregatorDBContainerNameSuffix,
					services.DefaultAggregatorDBName,
				),
				RedisAddress: fmt.Sprintf("%s-%s:6379", cloneName, services.AggregatorRedisContainerNameSuffix),
				RedisDB:      "0",
			}
			if agg.Env != nil {
				clone.Env.RedisPassword = agg.Env.RedisPassword
				clone.Env.RedisDB = agg.Env.RedisDB
			}

			aggContainerName := fmt.Sprintf("%s-%s", cloneName, services.AggregatorContainerNameSuffix)
			cloneAddr := fmt.Sprintf("%s:%d", aggContainerName, services.DefaultAggregatorGRPCPort)
			committee.Aggregators = append(committee.Aggregators, deployments.AggregatorConfig{
				Name:                         cloneName,
				Address:                      cloneAddr,
				InsecureAggregatorConnection: insecure,
			})

			// Add a Verifier entry to every indexer that verifies this committee
			// so the indexer can pull verified data from the HA aggregator too.
			for _, idx := range c.Indexer {
				if idx.IndexerConfig == nil {
					continue
				}
				for _, ver := range idx.IndexerConfig.Verifiers {
					if ver.Type != config.ReaderTypeAggregator {
						continue
					}
					qual, ok := idx.CommitteeVerifierNameToQualifier[ver.Name]
					if !ok || qual != agg.CommitteeName {
						continue
					}
					haVerName := fmt.Sprintf("%s (HA-%d)", ver.Name, i+1)
					idx.IndexerConfig.Verifiers = append(idx.IndexerConfig.Verifiers, config.VerifierConfig{
						Type:             config.ReaderTypeAggregator,
						Name:             haVerName,
						BatchSize:        ver.BatchSize,
						MaxBatchWaitTime: ver.MaxBatchWaitTime,
						AggregatorReaderConfig: config.AggregatorReaderConfig{
							Address:            cloneAddr,
							InsecureConnection: ver.InsecureConnection,
						},
					})
					idx.CommitteeVerifierNameToQualifier[haVerName] = qual
					break
				}
			}

			clones = append(clones, clone)

			nextHostPort++
			nextDBPort++
			nextRedisPort++
		}

		c.EnvironmentTopology.NOPTopology.Committees[agg.CommitteeName] = committee
	}

	c.Aggregator = append(c.Aggregator, clones...)
	return nil
}

func (c *Cfg) expandIndexers() error {
	var maxPort, maxDBPort int
	for _, idx := range c.Indexer {
		if idx.Port > maxPort {
			maxPort = idx.Port
		}
		if idx.DB != nil && idx.DB.HostPort > maxDBPort {
			maxDBPort = idx.DB.HostPort
		}
	}

	nextPort := maxPort + 1
	nextDBPort := maxDBPort + 1

	var clones []*services.IndexerInput

	for _, idx := range c.Indexer {
		if idx.RedundantIndexers <= 0 {
			continue
		}

		for range idx.RedundantIndexers {
			clone := &services.IndexerInput{
				Image:                            idx.Image,
				Port:                             nextPort,
				SourceCodePath:                   idx.SourceCodePath,
				RootPath:                         idx.RootPath,
				CommitteeVerifierNameToQualifier: copyStringMap(idx.CommitteeVerifierNameToQualifier),
				CCTPVerifierNameToQualifier:      copyStringMap(idx.CCTPVerifierNameToQualifier),
				LombardVerifierNameToQualifier:   copyStringMap(idx.LombardVerifierNameToQualifier),
			}

			if idx.DB != nil {
				clone.DB = &services.DBInput{
					Image:    idx.DB.Image,
					HostPort: nextDBPort,
					Database: idx.DB.Database,
					Username: idx.DB.Username,
					Password: idx.DB.Password,
				}
			}

			if idx.IndexerConfig != nil {
				cfgCopy := *idx.IndexerConfig
				if idx.IndexerConfig.Storage.Single != nil {
					singleCopy := *idx.IndexerConfig.Storage.Single
					if idx.IndexerConfig.Storage.Single.Postgres != nil {
						pgCopy := *idx.IndexerConfig.Storage.Single.Postgres
						singleCopy.Postgres = &pgCopy
					}
					cfgCopy.Storage.Single = &singleCopy
				}
				clone.IndexerConfig = &cfgCopy
			}

			if idx.Secrets != nil {
				secCopy := *idx.Secrets
				clone.Secrets = &secCopy
			}

			clones = append(clones, clone)

			nextPort++
			nextDBPort++
		}
	}

	c.Indexer = append(c.Indexer, clones...)

	// Ensure the topology has an indexer address for every indexer instance.
	// Existing addresses are preserved; only missing entries are appended.
	if c.EnvironmentTopology != nil {
		totalIndexers := len(c.Indexer)
		for i := len(c.EnvironmentTopology.IndexerAddress); i < totalIndexers; i++ {
			addr := fmt.Sprintf("http://indexer-%d:%d", i+1, services.DefaultIndexerInternalPort)
			c.EnvironmentTopology.IndexerAddress = append(c.EnvironmentTopology.IndexerAddress, addr)
		}
	}

	return nil
}

func deepCopyAggregatorAPIClients(src []*services.AggregatorClientConfig) []*services.AggregatorClientConfig {
	if src == nil {
		return nil
	}
	dst := make([]*services.AggregatorClientConfig, len(src))
	for i, client := range src {
		c := *client
		c.Groups = make([]string, len(client.Groups))
		copy(c.Groups, client.Groups)
		c.APIKeyPairs = make([]*services.AggregatorAPIKeyPair, len(client.APIKeyPairs))
		for j, pair := range client.APIKeyPairs {
			p := *pair
			c.APIKeyPairs[j] = &p
		}
		dst[i] = &c
	}
	return dst
}

func copyStringMap(src map[string]string) map[string]string {
	if src == nil {
		return nil
	}
	dst := make(map[string]string, len(src))
	maps.Copy(dst, src)
	return dst
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
		// TODO: move evm to the impl factory registry.
		return evm.NewEmptyCCIP17EVM(), nil
	default:
		fac, err := registry.GetImplFactory(typ)
		if err != nil {
			return nil, fmt.Errorf("could not find impl factory for chain family %s: %w", typ, err)
		}
		return fac.NewEmpty(), nil
	}
}

// enrichEnvironmentTopology injects SignerAddress values from verifier inputs into the EnvironmentTopology.
// This is needed because signer addresses are only known after key generation or CL node launch.
// Each verifier's NOPAlias identifies which NOP in the topology it belongs to.
// Only the first verifier for each NOP sets the signer address (subsequent verifiers with the
// same NOPAlias are ignored to avoid overwriting with wrong keys due to round-robin wrap-around).
func enrichEnvironmentTopology(cfg *deployments.EnvironmentTopology, verifiers []*committeeverifier.Input) {
	seenAliases := make(map[string]struct{})
	for _, ver := range verifiers {
		if _, seen := seenAliases[ver.NOPAlias]; seen {
			continue
		}
		nop, ok := cfg.NOPTopology.GetNOP(ver.NOPAlias)
		if !ok || nop.GetMode() == shared.NOPModeCL {
			// For CL mode the signer address should be fetch from JD, or the NOP is not found
			continue
		}
		if nop.SignerAddressByFamily[chainsel.FamilyEVM] == "" {
			cfg.NOPTopology.SetNOPSignerAddress(ver.NOPAlias, chainsel.FamilyEVM, ver.Out.BootstrapKeys.ECDSAAddress)
		}
		if nop.SignerAddressByFamily[chainsel.FamilyCanton] == "" {
			cfg.NOPTopology.SetNOPSignerAddress(ver.NOPAlias, chainsel.FamilyCanton, ver.Out.BootstrapKeys.ECDSAPublicKey)
		}
		seenAliases[ver.NOPAlias] = struct{}{}
	}
}

// buildEnvironmentTopology creates a copy of the EnvironmentTopology from the Cfg,
// enriches it with signer addresses, and returns it. This is used by both executor
// and verifier changesets as the single source of truth.
// For each chain_config entry that lacks a FeeAggregator, the corresponding
// chain's deployer key is used as a fallback.
func buildEnvironmentTopology(in *Cfg, e *deployment.Environment) *deployments.EnvironmentTopology {
	if in.EnvironmentTopology == nil {
		return nil
	}
	envCfg := *in.EnvironmentTopology
	enrichEnvironmentTopology(&envCfg, in.Verifier)

	if envCfg.NOPTopology == nil {
		return &envCfg
	}

	evmChains := e.BlockChains.EVMChains()
	for name, committee := range envCfg.NOPTopology.Committees {
		if committee.ChainConfigs == nil {
			continue
		}
		for chainSel, chainCfg := range committee.ChainConfigs {
			if chainCfg.FeeAggregator == "" {
				sel, err := strconv.ParseUint(chainSel, 10, 64)
				if err != nil {
					continue
				}
				if chain, ok := evmChains[sel]; ok {
					chainCfg.FeeAggregator = chain.DeployerKey.From.Hex()
					committee.ChainConfigs[chainSel] = chainCfg
				}
			}
		}
		envCfg.NOPTopology.Committees[name] = committee
	}

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
// It returns a map of container name -> job specs (one per aggregator in the committee).
// For standalone mode, it also sets GeneratedConfig on each verifier from the job spec
// selected by NodeIndex (i.e. the aggregator this verifier is assigned to).
// The ds parameter is a mutable datastore that will be updated with the changeset output.
func generateVerifierJobSpecs(
	e *deployment.Environment,
	in *Cfg,
	selectors []uint64,
	topology *deployments.EnvironmentTopology,
	sharedTLSCerts *services.TLSCertPaths,
	ds datastore.MutableDataStore,
) (map[string][]string, error) {
	verifierJobSpecs := make(map[string][]string)

	if len(in.Verifier) == 0 {
		return verifierJobSpecs, nil
	}

	// Group verifiers by committee for batch generation
	verifiersByCommittee := make(map[string][]*committeeverifier.Input)
	for _, ver := range in.Verifier {
		verifiersByCommittee[ver.CommitteeName] = append(verifiersByCommittee[ver.CommitteeName], ver)
	}

	// Generate verifier configs per committee per chain family
	for committeeName, committeeVerifiers := range verifiersByCommittee {
		// Extract and validate DisableFinalityCheckers - all verifiers in the same
		// committee and same chain family must have the same setting since it's applied at the committee level.
		disableFinalityCheckersPerFamily, err := extractAndValidateDisableFinalityCheckers(committeeName, committeeVerifiers)
		if err != nil {
			return nil, err
		}

		families := make(map[string]struct{})
		for _, ver := range committeeVerifiers {
			families[ver.ChainFamily] = struct{}{}
		}

		for family := range families {
			verNOPAliases := make([]shared.NOPAlias, 0, len(committeeVerifiers))
			for _, ver := range committeeVerifiers {
				if ver.ChainFamily == family {
					verNOPAliases = append(verNOPAliases, shared.NOPAlias(ver.NOPAlias))
				}
			}

			disableFinalityCheckers := disableFinalityCheckersPerFamily[family]
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

			aggNames, err := topology.GetAggregatorNamesForCommittee(committeeName)
			if err != nil {
				return nil, err
			}

			// In HA topologies (multiple aggregators per committee) enforce a strict
			// 1:1 verifier-to-aggregator mapping. For single-aggregator committees
			// this constraint doesn't apply — all verifiers share the one aggregator.
			if len(aggNames) > 1 {
				if err := validateStandaloneVerifierNodeIndices(committeeName, committeeVerifiers, len(aggNames)); err != nil {
					return nil, err
				}
			}

			for _, ver := range committeeVerifiers {
				if ver.ChainFamily != family {
					continue
				}

				allJobSpecs := make([]string, 0, len(aggNames))
				for _, aggName := range aggNames {
					jobSpecID := shared.NewVerifierJobID(shared.NOPAlias(ver.NOPAlias), aggName, shared.VerifierJobScope{CommitteeQualifier: committeeName})
					job, err := deployments.GetJob(output.DataStore.Seal(), shared.NOPAlias(ver.NOPAlias), jobSpecID.ToJobID())
					if err != nil {
						return nil, fmt.Errorf("failed to get verifier job spec for %s aggregator %s: %w", ver.ContainerName, aggName, err)
					}
					allJobSpecs = append(allJobSpecs, job.Spec)
				}

				verifierJobSpecs[ver.NOPAlias] = allJobSpecs
				ver.GeneratedJobSpecs = allJobSpecs

				// NodeIndex selects which aggregator this verifier targets. For
				// single-aggregator committees the modulo collapses to 0, so all
				// verifiers share the one aggregator — matching the non-HA model.
				ownedAggIdx := ver.NodeIndex % len(aggNames)
				verCfg, err := ParseVerifierConfigFromJobSpec(allJobSpecs[ownedAggIdx])
				if err != nil {
					return nil, fmt.Errorf("failed to parse verifier config from job spec: %w", err)
				}
				configBytes, err := toml.Marshal(verCfg)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal verifier config: %w", err)
				}
				ver.GeneratedConfig = string(configBytes)

				// Store the VerifierID in the output for test access
				if ver.Out != nil {
					ver.Out.VerifierID = verCfg.VerifierID
				}

				if sharedTLSCerts != nil && !ver.InsecureAggregatorConnection {
					ver.TLSCACertFile = sharedTLSCerts.CACertFile
				}
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

	if err = in.expandForHA(); err != nil {
		return nil, fmt.Errorf("failed to expand HA configuration: %w", err)
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
		cs := changesets.GenerateAggregatorConfig()
		output, err := cs.Apply(*e, changesets.GenerateAggregatorConfigCfg{
			ServiceIdentifier:  instanceName + "-aggregator",
			CommitteeQualifier: aggregatorInput.CommitteeName,
			ChainSelectors:     selectors,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to generate aggregator config for %s (committee %s): %w", instanceName, aggregatorInput.CommitteeName, err)
		}

		// Get generated config from output datastore
		aggCfg, err := deployments.GetAggregatorConfig(output.DataStore.Seal(), instanceName+"-aggregator")
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
		cs := changesets.GenerateIndexerConfig()
		output, err := cs.Apply(*e, changesets.GenerateIndexerConfigCfg{
			ServiceIdentifier:                "indexer",
			CommitteeVerifierNameToQualifier: firstIdx.CommitteeVerifierNameToQualifier,
			CCTPVerifierNameToQualifier:      firstIdx.CCTPVerifierNameToQualifier,
			LombardVerifierNameToQualifier:   firstIdx.LombardVerifierNameToQualifier,
			ChainSelectors:                   selectors,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to generate indexer config: %w", err)
		}

		idxCfg, err := deployments.GetIndexerConfig(output.DataStore.Seal(), "indexer")
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

	verifierJobSpecs, err := generateVerifierJobSpecs(e, in, selectors, topology, sharedTLSCerts, ds)
	if err != nil {
		return nil, err
	}

	// Each verifier owns one aggregator (NodeIndex % numAggs). Select the
	// corresponding job spec so proposeJobsToStandaloneVerifiers gets a
	// single spec per container.
	ownedJobSpecs := make(map[string]string, len(verifierJobSpecs))
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
		cs := changesets.GenerateTokenVerifierConfig()
		output, err := cs.Apply(*e, changesets.GenerateTokenVerifierConfigCfg{
			ServiceIdentifier: "TokenVerifier",
			ChainSelectors:    selectors,
			PyroscopeURL:      template.PyroscopeURL,
			Monitoring: shared.MonitoringInput{
				Enabled: template.Monitoring.Enabled,
				Type:    template.Monitoring.Type,
				Beholder: shared.BeholderInput{
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
			Lombard: sequences.LombardConfigInput{
				VerifierID:     "LombardVerifier",
				Qualifier:      devenvcommon.LombardContractsQualifier,
				AttestationAPI: fakeOut.InternalHTTPURL + "/lombard",
			},
			CCTP: sequences.CCTPConfigInput{
				VerifierID:     "CCTPVerifier",
				Qualifier:      devenvcommon.CCTPContractsQualifier,
				AttestationAPI: fakeOut.InternalHTTPURL + "/cctp",
			},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to generate token verifier config: %w", err)
		}

		// Get generated config from output datastore
		tokenVerifierCfg, err := deployments.GetTokenVerifierConfig(
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

// launchCLNodes encapsulates the logic required to launch the core node. It may be better to wrap this in a service.
// It returns the onchain public keys for each chain type for each CL node.
func launchCLNodes(
	ctx context.Context,
	in *Cfg,
	impls []cciptestinterfaces.CCIP17Configuration,
	vIn []*committeeverifier.Input,
	aggregators []*services.AggregatorInput,
) (map[string][]string, error) {
	aggsByCommittee := make(map[string][]*services.AggregatorInput)
	for _, agg := range aggregators {
		aggsByCommittee[agg.CommitteeName] = append(aggsByCommittee[agg.CommitteeName], agg)
	}

	// Build a lookup from (committeeName, aggIndex) → topology aggregator Name.
	// The changeset uses the topology Name (not AggregatorInput.InstanceName()) to
	// construct VerifierIDs, so secrets must use the same names. The ordering of
	// aggsByCommittee[c] matches committee.Aggregators because both the original
	// entries (TOML order) and expansion clones (appended by expandForHA) share
	// the same insertion order.
	topoAggNames := make(map[string][]string)
	if in.EnvironmentTopology != nil && in.EnvironmentTopology.NOPTopology != nil {
		for name, committee := range in.EnvironmentTopology.NOPTopology.Committees {
			names := make([]string, len(committee.Aggregators))
			for i, a := range committee.Aggregators {
				names[i] = a.Name
			}
			topoAggNames[name] = names
		}
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

		committeeAggs := aggsByCommittee[ver.CommitteeName]
		if len(committeeAggs) == 0 {
			return nil, fmt.Errorf("no aggregators found for committee %q (verifier %s)", ver.CommitteeName, ver.ContainerName)
		}
		committeeTopoNames := topoAggNames[ver.CommitteeName]

		for aggIdx, agg := range committeeAggs {
			// Use the topology aggregator Name for VerifierID construction.
			// The changeset builds VerifierIDs from topology names, so secrets
			// must match. Fall back to InstanceName() when no topology exists.
			aggName := agg.InstanceName()
			if aggIdx < len(committeeTopoNames) {
				aggName = committeeTopoNames[aggIdx]
			}

			apiKeys, err := agg.GetAPIKeys()
			if err != nil {
				return nil, fmt.Errorf("failed to get API keys for aggregator %s: %w", agg.InstanceName(), err)
			}
			Plog.Info().
				Int("index", index).
				Str("verifier", ver.ContainerName).
				Str("aggregator", agg.InstanceName()).
				Str("topoName", aggName).
				Str("committee", ver.CommitteeName).
				Any("apiKeys", apiKeys).
				Msg("getting API keys for verifier")
			var found bool
			for _, apiClient := range apiKeys {
				if apiClient.ClientID == ver.ContainerName {
					if len(apiClient.APIKeyPairs) == 0 {
						return nil, fmt.Errorf("no API key pairs found for client %s on aggregator %s", apiClient.ClientID, agg.InstanceName())
					}
					apiKeyPair := apiClient.APIKeyPairs[0]
					verifierID := shared.NewVerifierJobID(
						shared.NOPAlias(ver.NOPAlias),
						aggName,
						shared.VerifierJobScope{CommitteeQualifier: ver.CommitteeName},
					).GetVerifierID()
					Plog.Debug().
						Int("nodeIndex", index).
						Str("verifier", ver.ContainerName).
						Str("aggregator", agg.InstanceName()).
						Str("topoName", aggName).
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
				return nil, fmt.Errorf("failed to find API client for verifier %s on aggregator %s", ver.ContainerName, agg.InstanceName())
			}
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

func launchStandaloneVerifiers(in *Cfg, blockchainOutputs []*blockchain.Output, jdInfra *jobs.JDInfrastructure) ([]*committeeverifier.Output, error) {
	// Collect aggregator outputs per committee in insertion order so that NodeIndex maps
	// each verifier to the correct aggregator. A map[string]*Output would lose duplicates
	// since HA committees have multiple aggregators under the same committee name.
	aggregatorsByCommittee := make(map[string][]*services.AggregatorOutput)
	for _, agg := range in.Aggregator {
		if agg.Out != nil {
			aggregatorsByCommittee[agg.CommitteeName] = append(aggregatorsByCommittee[agg.CommitteeName], agg.Out)
		}
	}

	// Apply defaults to verifiers so that we can use them in the standalone mode.
	for i := range in.Verifier {
		ver := committeeverifier.ApplyDefaults(*in.Verifier[i])
		in.Verifier[i] = &ver
	}

	outs := make([]*committeeverifier.Output, 0, len(in.Verifier))
	// Start standalone verifiers if in standalone mode.
	for _, ver := range in.Verifier {
		if ver.Mode != services.Standalone {
			continue
		}

		aggOuts := aggregatorsByCommittee[ver.CommitteeName]
		if len(aggOuts) == 0 {
			return nil, fmt.Errorf(
				"verifier %q (committee %q): no aggregator outputs found — ensure the aggregator started successfully",
				ver.ContainerName, ver.CommitteeName,
			)
		}
		aggIdx := ver.NodeIndex % len(aggOuts)
		ver.AggregatorOutput = aggOuts[aggIdx]
		out, err := committeeverifier.New(ver, blockchainOutputs, jdInfra)
		if err != nil {
			return nil, fmt.Errorf("failed to create verifier service: %w", err)
		}
		ver.Out = out
		outs = append(outs, out)
	}
	return outs, nil
}

func launchStandaloneTokenVerifiers(in *Cfg, blockchainOutputs []*blockchain.Output) ([]*services.TokenVerifierOutput, error) {
	var outs []*services.TokenVerifierOutput
	for _, ver := range in.TokenVerifier {
		if ver.Mode == services.Standalone {
			out, err := services.NewTokenVerifier(ver, blockchainOutputs)
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
func extractAndValidateDisableFinalityCheckers(committeeName string, verifiers []*committeeverifier.Input) (disableFinalityCheckersPerFamily map[string][]string, err error) {
	if len(verifiers) == 0 {
		return nil, nil
	}

	disableFinalityCheckersPerFamily = make(map[string][]string)
	for _, ver := range verifiers {
		// if already set, check if its the same value
		if _, ok := disableFinalityCheckersPerFamily[ver.ChainFamily]; ok {
			if !slicesEqual(disableFinalityCheckersPerFamily[ver.ChainFamily], ver.DisableFinalityCheckers) {
				return nil, fmt.Errorf(
					"verifiers in committee %q within the same chain family %s have inconsistent disable_finality_checkers settings",
					committeeName, ver.ChainFamily,
				)
			}
		}
		disableFinalityCheckersPerFamily[ver.ChainFamily] = ver.DisableFinalityCheckers
	}

	return disableFinalityCheckersPerFamily, nil
}

// validateStandaloneVerifierNodeIndices validates that the node_index assignments for
// standalone verifiers in a single committee are consistent with the number of aggregators.
func validateStandaloneVerifierNodeIndices(committeeName string, verifiers []*committeeverifier.Input, numAggregators int) error {
	seen := make(map[int]string, len(verifiers)) // node_index → container_name

	for _, ver := range verifiers {
		if ver.NodeIndex >= numAggregators {
			return fmt.Errorf(
				"committee %q: verifier %q has node_index=%d but committee only has %d aggregator(s) — "+
					"node_index must be in [0, %d)",
				committeeName, ver.ContainerName, ver.NodeIndex, numAggregators, numAggregators,
			)
		}

		if existing, dup := seen[ver.NodeIndex]; dup {
			return fmt.Errorf(
				"committee %q: verifiers %q and %q both have node_index=%d — "+
					"each verifier must have a unique node_index so that every aggregator has exactly one writer",
				committeeName, existing, ver.ContainerName, ver.NodeIndex,
			)
		}
		seen[ver.NodeIndex] = ver.ContainerName
	}

	if len(verifiers) != numAggregators {
		return fmt.Errorf(
			"committee %q: %d standalone verifier(s) configured but %d aggregator(s) defined — "+
				"the standalone model requires exactly one verifier per aggregator (1:1 mapping)",
			committeeName, len(verifiers), numAggregators,
		)
	}

	return nil
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

// registerStandaloneVerifiersWithJD registers standalone verifiers with JD in parallel
// and waits for them to establish their WSRPC connections.
// TODO: this is common for all bootstrapped apps, make more general?
func registerStandaloneVerifiersWithJD(ctx context.Context, verifiers []*committeeverifier.Input, jdClient offchain.Client) error {
	// Filter to standalone verifiers only
	var standaloneVerifiers []*committeeverifier.Input
	for _, ver := range verifiers {
		if ver.Mode == services.Standalone {
			standaloneVerifiers = append(standaloneVerifiers, ver)
		}
	}

	if len(standaloneVerifiers) == 0 {
		return nil
	}

	// Use errgroup for parallel registration and connection waiting
	g, gCtx := errgroup.WithContext(ctx)
	var mu sync.Mutex

	for _, ver := range standaloneVerifiers {
		g.Go(func() error {
			if ver.Out == nil || ver.Out.BootstrapKeys.CSAPublicKey == "" {
				return fmt.Errorf("bootstrap %s started but CSAPublicKey not available", ver.ContainerName)
			}

			reg := &jobs.BootstrapJDRegistration{
				Name:         ver.ContainerName,
				CSAPublicKey: ver.Out.BootstrapKeys.CSAPublicKey,
			}
			if err := jobs.RegisterBootstrapWithJD(gCtx, jdClient, reg); err != nil {
				return fmt.Errorf("failed to register bootstrap %s with JD: %w", ver.ContainerName, err)
			}

			// Store the JD node ID in the verifier output for later use when proposing jobs.
			mu.Lock()
			ver.Out.JDNodeID = reg.NodeID
			mu.Unlock()

			// Wait for bootstrap to connect to JD
			if err := jobs.WaitForBootstrapConnection(gCtx, jdClient, reg.NodeID, 60*time.Second); err != nil {
				return fmt.Errorf("bootstrap %s failed to connect to JD: %w", ver.ContainerName, err)
			}

			return nil
		})
	}

	return g.Wait()
}

// proposeJobsToStandaloneVerifiers proposes jobs to standalone verifiers via JD in parallel.
// Each verifier receives its job spec with blockchain infos injected.
func proposeJobsToStandaloneVerifiers(
	ctx context.Context,
	verifiers []*committeeverifier.Input,
	verifierJobSpecs map[string]string,
	blockchainOutputs []*blockchain.Output,
	jdClient offchain.Client,
) error {
	// Filter to standalone verifiers only
	var standaloneVerifiers []*committeeverifier.Input
	for _, ver := range verifiers {
		if ver.Mode == services.Standalone {
			standaloneVerifiers = append(standaloneVerifiers, ver)
		}
	}

	if len(standaloneVerifiers) == 0 {
		return nil
	}

	// Convert blockchain outputs to infos for standalone verifier config
	blockchainInfos, err := services.ConvertBlockchainOutputsToInfo(blockchainOutputs)
	if err != nil {
		return fmt.Errorf("failed to convert blockchain outputs to infos: %w", err)
	}

	// Use errgroup for parallel job proposals
	g, gCtx := errgroup.WithContext(ctx)

	for _, ver := range standaloneVerifiers {
		g.Go(func() error {
			// propose to all families
			if ver.Out == nil || ver.Out.JDNodeID == "" {
				return fmt.Errorf("verifier %s not registered with JD (missing JDNodeID)", ver.NOPAlias)
			}
			nodeID := ver.Out.JDNodeID

			// Get the base job spec
			baseJobSpec, ok := verifierJobSpecs[ver.NOPAlias]
			if !ok {
				return fmt.Errorf("no job spec found for verifier %s", ver.NOPAlias)
			}

			// For standalone verifiers, we need to inject blockchain_infos into the config
			// because they don't have CL node chain configuration
			jobSpec, err := ver.RebuildVerifierJobSpecWithBlockchainInfos(baseJobSpec, blockchainInfos)
			if err != nil {
				return fmt.Errorf("failed to add blockchain infos to job spec for %s: %w", ver.NOPAlias, err)
			}

			L.Info().Msgf("Proposing job to verifier %s: %s", ver.NOPAlias, jobSpec)

			resp, err := jdClient.ProposeJob(gCtx, &jobv1.ProposeJobRequest{
				NodeId: nodeID,
				Spec:   jobSpec,
			})
			if err != nil {
				return fmt.Errorf("failed to propose job to verifier %s: %w", ver.NOPAlias, err)
			}
			L.Info().
				Str("verifier", ver.NOPAlias).
				Str("nodeID", nodeID).
				Str("proposalID", resp.Proposal.Id).
				Msg("Proposed job to verifier via JD")

			return nil
		})
	}

	return g.Wait()
}
