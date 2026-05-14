package ccv

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/bootstrap"

	_ "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/adapters"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainimpl"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	_ "github.com/smartcontractkit/chainlink-ccv/build/devenv/components/blockchains"
	_ "github.com/smartcontractkit/chainlink-ccv/build/devenv/components/chainlinknode"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/jobs"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/chainconfig"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/committeeverifier"
	executorsvc "github.com/smartcontractkit/chainlink-ccv/build/devenv/services/executor"
	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	ccvadapters "github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	ccvchangesets "github.com/smartcontractkit/chainlink-ccv/deployment/changesets"
	ccvshared "github.com/smartcontractkit/chainlink-ccv/deployment/shared"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/offchain"
	jobv1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/job"
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
	Executor           []*executorsvc.Input           `toml:"executor"              validate:"required"`
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
	// UseLegacyConfigureLane selects the legacy lanes.ConnectChains path
	// instead of the canonical ConfigureChainsForLanesFromTopology changeset.
	UseLegacyConfigureLane bool `toml:"use_legacy_configure_lane"`
	// AggregatorEndpoints map the verifier qualifier to the aggregator URL for that verifier.
	AggregatorEndpoints map[string]string `toml:"aggregator_endpoints"`
	// AggregatorCACertFiles map the verifier qualifier to the CA cert file path for TLS verification.
	AggregatorCACertFiles map[string]string `toml:"aggregator_ca_cert_files"`
	// IndexerEndpoints holds external URLs for all indexers (localhost:port).
	IndexerEndpoints []string `toml:"indexer_endpoints"`
	// IndexerInternalEndpoints holds internal Docker network URLs for all indexers.
	IndexerInternalEndpoints []string `toml:"indexer_internal_endpoints"`
	// EnvironmentTopology is the shared environment configuration for NOPs, committees, and executor pools.
	EnvironmentTopology *ccvdeployment.EnvironmentTopology `toml:"environment_topology" validate:"required"`
	// JDInfra holds the runtime JD infrastructure (not from config, populated at runtime).
	JDInfra *jobs.JDInfrastructure `toml:"-"`
	// ClientLookup provides ChainlinkClient lookup by NOP alias (populated at runtime).
	ClientLookup *jobs.NodeSetClientLookup `toml:"-"`

	// GenericServices is a map of chain selector to its generic service definition.
	GenericServices map[uint64]*GenericServiceDefinition `toml:"generic_services" validate:"required"`
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
			committee.Aggregators = append(committee.Aggregators, ccvdeployment.AggregatorConfig{
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

	evmBlockchains := make([]*blockchain.Input, 0)
	for _, bc := range in.Blockchains {
		family, err := blockchain.TypeToFamily(bc.Type)
		if err != nil {
			return fmt.Errorf("failed to resolve blockchain family for type %q: %w", bc.Type, err)
		}
		if string(family) == blockchain.FamilyEVM {
			evmBlockchains = append(evmBlockchains, bc)
		}
	}
	for _, bc := range evmBlockchains {
		if getNetworkPrivateKey() != devenvcommon.DefaultAnvilKey && slices.Contains(evmSimChainIDs, bc.ChainID) {
			return errors.New("you are trying to run simulated chains with a key that do not belong to Anvil, please run 'unset PRIVATE_KEY'")
		}
		if getNetworkPrivateKey() == devenvcommon.DefaultAnvilKey && !slices.Contains(evmSimChainIDs, bc.ChainID) {
			return errors.New("you are trying to run on real networks but is not using the Anvil private key, export your private key 'export PRIVATE_KEY=...'")
		}
	}

	return nil
}

func NewProductConfigurationFromNetwork(typ string) (cciptestinterfaces.CCIP17Configuration, error) {
	resolved, err := blockchain.TypeToFamily(typ)
	if err != nil {
		// typ might already be a family name — try the factory directly before giving up.
		if fac, facErr := chainimpl.GetImplFactory(typ); facErr == nil {
			return fac.NewEmpty(), nil
		}
		return nil, fmt.Errorf("unknown blockchain type %q (not a recognized type or family): %w", typ, err)
	}
	family := string(resolved)
	fac, err := chainimpl.GetImplFactory(family)
	if err != nil {
		return nil, fmt.Errorf("could not find impl factory for chain type %s (family %s): %w", typ, family, err)
	}
	return fac.NewEmpty(), nil
}

// enrichEnvironmentTopology injects SignerAddress values from verifier inputs into the EnvironmentTopology.
// This is needed because signer addresses are only known after key generation or CL node launch.
// Each verifier's NOPAlias identifies which NOP in the topology it belongs to.
// Only the first verifier for each NOP sets the signer address (subsequent verifiers with the
// same NOPAlias are ignored to avoid overwriting with wrong keys due to round-robin wrap-around).
//
// Signer key selection is delegated to each registered ImplFactory via DefaultSignerKey,
// so adding a new chain family requires no changes here.
func enrichEnvironmentTopology(cfg *ccvdeployment.EnvironmentTopology, verifiers []*committeeverifier.Input) {
	factories := chainimpl.GetAllImplFactories()

	seenAliases := make(map[string]struct{})
	for _, ver := range verifiers {
		if _, seen := seenAliases[ver.NOPAlias]; seen {
			continue
		}
		nop, ok := cfg.NOPTopology.GetNOP(ver.NOPAlias)
		if !ok || nop.GetMode() == ccvshared.NOPModeCL {
			continue
		}

		for family, factory := range factories {
			if nop.SignerAddressByFamily[family] != "" {
				continue
			}
			signerKey := factory.DefaultSignerKey(ver.Out.BootstrapKeys)
			if signerKey != "" {
				cfg.NOPTopology.SetNOPSignerAddress(ver.NOPAlias, family, signerKey)
			}
		}

		seenAliases[ver.NOPAlias] = struct{}{}
	}
}

// buildEnvironmentTopology creates a copy of the EnvironmentTopology from the Cfg,
// enriches it with signer addresses, and returns it. This is used by both executor
// and verifier changesets as the single source of truth.
// For each chain_config entry that lacks a FeeAggregator, the corresponding
// chain's deployer key is used as a fallback via the registered ImplFactory.
func buildEnvironmentTopology(in *Cfg, e *deployment.Environment) *ccvdeployment.EnvironmentTopology {
	if in.EnvironmentTopology == nil {
		return nil
	}
	envCfg := *in.EnvironmentTopology
	enrichEnvironmentTopology(&envCfg, in.Verifier)

	if envCfg.NOPTopology == nil {
		return &envCfg
	}

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
				family, err := chainsel.GetSelectorFamily(sel)
				if err != nil {
					continue
				}
				fac, err := chainimpl.GetImplFactory(family)
				if err != nil {
					continue
				}
				if addr := fac.DefaultFeeAggregator(e, sel); addr != "" {
					chainCfg.FeeAggregator = addr
					committee.ChainConfigs[chainSel] = chainCfg
				}
			}
		}
		envCfg.NOPTopology.Committees[name] = committee
	}

	return &envCfg
}

// generateExecutorJobSpecs generates job specs for all executors using the changeset.
// It returns a map of container name -> job spec.
// The ds parameter is a mutable datastore that will be updated with the changeset output.
func generateExecutorJobSpecs(
	e *deployment.Environment,
	in *Cfg,
	topology *ccvdeployment.EnvironmentTopology,
	ds datastore.MutableDataStore,
) (map[string]bootstrap.JobSpec, error) {
	executorJobSpecs := make(map[string]bootstrap.JobSpec)

	if len(in.Executor) == 0 {
		return executorJobSpecs, nil
	}

	// Group executors by qualifier
	executorsByQualifier := make(map[string][]*executorsvc.Input)
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

		pool, ok := topology.ExecutorPools[qualifier]
		if !ok {
			return nil, fmt.Errorf("executor pool %q not found in topology", qualifier)
		}
		cs := ccvchangesets.ApplyExecutorConfig(ccvadapters.GetRegistry())
		output, err := cs.Apply(*e, ccvchangesets.ApplyExecutorConfigInput{
			ExecutorQualifier: qualifier,
			NOPs:              ccvchangesets.NOPInputsFromTopology(topology),
			Pool:              ccvchangesets.ExecutorPoolInputFromTopology(pool),
			IndexerAddress:    topology.IndexerAddress,
			PyroscopeURL:      topology.PyroscopeURL,
			Monitoring:        topology.Monitoring,
			TargetNOPs:        ccvshared.ConvertStringToNopAliases(execNOPAliases),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to generate executor configs for qualifier %s: %w", qualifier, err)
		}

		if err := ds.Merge(output.DataStore.Seal()); err != nil {
			return nil, fmt.Errorf("failed to merge executor job specs datastore: %w", err)
		}

		for _, exec := range qualifierExecutors {
			jobSpecID := ccvshared.NewExecutorJobID(ccvshared.NOPAlias(exec.NOPAlias), ccvshared.ExecutorJobScope{ExecutorQualifier: qualifier})
			job, err := ccvdeployment.GetJob(output.DataStore.Seal(), ccvshared.NOPAlias(exec.NOPAlias), jobSpecID.ToJobID())
			if err != nil {
				return nil, fmt.Errorf("failed to get executor job spec for %s: %w", exec.ContainerName, err)
			}

			// TODO: Use bootstrap.JobSpec in CLD to avoid this conversion here
			var executorSpec ExecutorJobSpec
			{
				md, err := toml.Decode(job.Spec, &executorSpec)
				if err != nil {
					return nil, fmt.Errorf("failed to decode verifier job spec for %s: %w", exec.ContainerName, err)
				}
				if len(md.Undecoded()) > 0 {
					L.Warn().
						Str("spec", job.Spec).
						Str("undecoded fields", fmt.Sprintf("%v", md.Undecoded())).
						Msg("Undecoded fields in executor job spec")
					return nil, fmt.Errorf("unknown fields in executor job spec for %s: %v", exec.ContainerName, md.Undecoded())
				}
				executorJobSpecs[exec.ContainerName] = executorSpec.ToBootstrapJobSpec()
			}
		}
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
	topology *ccvdeployment.EnvironmentTopology,
	sharedTLSCerts *services.TLSCertPaths,
	ds datastore.MutableDataStore,
) (map[string][]bootstrap.JobSpec, error) {
	verifierJobSpecs := make(map[string][]bootstrap.JobSpec)

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
			verNOPAliases := make([]ccvshared.NOPAlias, 0, len(committeeVerifiers))
			for _, ver := range committeeVerifiers {
				if ver.ChainFamily == family {
					verNOPAliases = append(verNOPAliases, ccvshared.NOPAlias(ver.NOPAlias))
				}
			}

			disableFinalityCheckers := disableFinalityCheckersPerFamily[family]
			committee, ok := topology.NOPTopology.Committees[committeeName]
			if !ok {
				return nil, fmt.Errorf("committee %q not found in topology", committeeName)
			}
			cs := ccvchangesets.ApplyVerifierConfig(ccvadapters.GetRegistry())
			output, err := cs.Apply(*e, ccvchangesets.ApplyVerifierConfigInput{
				CommitteeQualifier:       committeeName,
				DefaultExecutorQualifier: devenvcommon.DefaultExecutorQualifier,
				NOPs:                     ccvchangesets.NOPInputsFromTopology(topology),
				Committee:                ccvchangesets.CommitteeInputFromTopologyPerFamily(committee, family),
				PyroscopeURL:             topology.PyroscopeURL,
				Monitoring:               topology.Monitoring,
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

				allJobSpecs := make([]bootstrap.JobSpec, 0, len(aggNames))
				for _, aggName := range aggNames {
					jobSpecID := ccvshared.NewVerifierJobID(ccvshared.NOPAlias(ver.NOPAlias), aggName, ccvshared.VerifierJobScope{CommitteeQualifier: committeeName})
					job, err := ccvdeployment.GetJob(output.DataStore.Seal(), ccvshared.NOPAlias(ver.NOPAlias), jobSpecID.ToJobID())
					if err != nil {
						return nil, fmt.Errorf("failed to get verifier job spec for %s aggregator %s: %w", ver.ContainerName, aggName, err)
					}

					// TODO: Use bootstrap.JobSpec in CLD to avoid this conversion here
					var verifierJobSpec VerifierJobSpec
					md, err := toml.Decode(job.Spec, &verifierJobSpec)
					if err != nil {
						return nil, fmt.Errorf("failed to decode verifier job spec for %s: %w", ver.ContainerName, err)
					}
					if len(md.Undecoded()) > 0 {
						L.Warn().
							Str("spec", job.Spec).
							Str("undecoded fields", fmt.Sprintf("%v", md.Undecoded())).
							Msg("Undecoded fields in executor job spec")
						return nil, fmt.Errorf("unknown fields in verifier job spec for %s aggregator: %v", ver.ContainerName, md.Undecoded())
					}

					allJobSpecs = append(allJobSpecs, verifierJobSpec.ToBootstrapJobSpec())
				}

				verifierJobSpecs[ver.NOPAlias] = allJobSpecs
				ver.GeneratedJobSpecs = allJobSpecs

				// NodeIndex selects which aggregator this verifier targets. For
				// single-aggregator committees the modulo collapses to 0, so all
				// verifiers share the one aggregator — matching the non-HA model.
				ownedAggIdx := ver.NodeIndex % len(aggNames)
				var verCfg commit.Config
				if err := toml.Unmarshal([]byte(allJobSpecs[ownedAggIdx].AppConfig), &verCfg); err != nil {
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
					verifierID := ccvshared.NewVerifierJobID(
						ccvshared.NOPAlias(ver.NOPAlias),
						aggName,
						ccvshared.VerifierJobScope{CommitteeQualifier: ver.CommitteeName},
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

// fundExecutorTransmitters funds the EVM transmitter addresses of all executors after launch.
// Addresses are derived from the keystore key exposed by the bootstrap HTTP server.
func fundExecutorTransmitters(
	ctx context.Context,
	executors []*executorsvc.Input,
	blockchains []*blockchain.Input,
	impls []cciptestinterfaces.CCIP17Configuration,
) error {
	addressesByFamily := make(map[string][]protocol.UnknownAddress)
	for _, exec := range executors {
		if exec == nil {
			continue
		}
		if exec.Out == nil || exec.Out.BootstrapKeys.EVMTransmitterAddress == "" {
			continue
		}
		family := exec.ChainFamily
		if family == "" {
			family = chainsel.FamilyEVM
		}
		addrBytes, err := hex.DecodeString(exec.Out.BootstrapKeys.EVMTransmitterAddress)
		if err != nil {
			return fmt.Errorf("invalid EVM transmitter address for executor %s: %w", exec.ContainerName, err)
		}
		addressesByFamily[family] = append(addressesByFamily[family], protocol.UnknownAddress(addrBytes))
	}

	for i, impl := range impls {
		if i >= len(blockchains) {
			break
		}
		family, famErr := blockchain.TypeToFamily(blockchains[i].Type)
		if famErr != nil {
			continue
		}
		fac, facErr := chainimpl.GetImplFactory(string(family))
		if facErr != nil || !fac.SupportsFunding() {
			continue
		}
		addresses := addressesByFamily[string(family)]
		if len(addresses) == 0 {
			continue
		}
		Plog.Info().Int("ImplIndex", i).Msg("Funding executor transmitters")
		if err := impl.FundAddresses(ctx, blockchains[i], addresses, big.NewInt(5)); err != nil {
			return fmt.Errorf("failed to fund executor transmitters: %w", err)
		}
		Plog.Info().Int("ImplIndex", i).Msg("Funded executor transmitters")
	}
	return nil
}

// launchExecutors starts executor containers for all Standalone-mode inputs.
func launchExecutors(in []*executorsvc.Input, blockchainOutputs []*blockchain.Output, jdInfra *jobs.JDInfrastructure) ([]*executorsvc.Output, error) {
	var outs []*executorsvc.Output
	for _, exec := range in {
		if exec != nil && exec.Mode == services.Standalone {
			out, err := executorsvc.New(exec, blockchainOutputs, jdInfra)
			if err != nil {
				return nil, fmt.Errorf("failed to create executor %s: %w", exec.ContainerName, err)
			}
			exec.Out = out
			outs = append(outs, out)
		}
	}
	return outs, nil
}

// registerExecutorsWithJD registers executors with the Job Distributor
// and waits for them to establish their WSRPC connections.
func registerExecutorsWithJD(ctx context.Context, executors []*executorsvc.Input, jdClient offchain.Client) error {
	var standalone []*executorsvc.Input
	for _, exec := range executors {
		if exec.Mode == services.Standalone {
			standalone = append(standalone, exec)
		}
	}

	if len(standalone) == 0 {
		return nil
	}

	g, gCtx := errgroup.WithContext(ctx)
	var mu sync.Mutex

	for _, exec := range standalone {
		g.Go(func() error {
			if exec.Out == nil || exec.Out.BootstrapKeys.CSAPublicKey == "" {
				return fmt.Errorf("bootstrapped executor %s started but CSAPublicKey not available", exec.ContainerName)
			}

			reg := &jobs.BootstrapJDRegistration{
				Name:         exec.ContainerName,
				CSAPublicKey: exec.Out.BootstrapKeys.CSAPublicKey,
			}
			if err := jobs.RegisterBootstrapWithJD(gCtx, jdClient, reg); err != nil {
				return fmt.Errorf("failed to register executor %s with JD: %w", exec.ContainerName, err)
			}

			mu.Lock()
			exec.Out.JDNodeID = reg.NodeID
			mu.Unlock()

			if err := jobs.WaitForBootstrapConnection(gCtx, jdClient, reg.NodeID, 60*time.Second); err != nil {
				return fmt.Errorf("executor %s failed to connect to JD: %w", exec.ContainerName, err)
			}

			return nil
		})
	}

	return g.Wait()
}

// proposeJobsToExecutors proposes executor job specs to executors via JD.
// Each executor receives its job spec with blockchain infos injected for its chain family.
func proposeJobsToExecutors(
	ctx context.Context,
	executors []*executorsvc.Input,
	executorJobSpecs map[string]bootstrap.JobSpec,
	blockchainOutputs []*blockchain.Output,
	jdClient offchain.Client,
) error {
	var standalone []*executorsvc.Input
	for _, exec := range executors {
		if exec.Mode == services.Standalone {
			standalone = append(standalone, exec)
		}
	}

	if len(standalone) == 0 {
		return nil
	}

	g, gCtx := errgroup.WithContext(ctx)

	for _, exec := range standalone {
		g.Go(func() error {
			if exec.Out == nil || exec.Out.JDNodeID == "" {
				return fmt.Errorf("executor %s not registered with JD (missing JDNodeID)", exec.ContainerName)
			}
			nodeID := exec.Out.JDNodeID

			loader, err := chainconfig.GetChainConfigLoader(exec.ChainFamily)
			if err != nil {
				return fmt.Errorf("failed to get chain config loader for family %s: %w", exec.ChainFamily, err)
			}

			blockchainInfos, err := loader(blockchainOutputs)
			if err != nil {
				return fmt.Errorf("failed to load chain config for family %s: %w", exec.ChainFamily, err)
			}

			baseJobSpec, ok := executorJobSpecs[exec.ContainerName]
			if !ok {
				return fmt.Errorf("no job spec found for executor %s", exec.ContainerName)
			}

			jobSpec, err := executorsvc.RebuildExecutorJobSpecWithBlockchainInfos(baseJobSpec, blockchainInfos)
			if err != nil {
				return fmt.Errorf("failed to add blockchain infos to job spec for %s: %w", exec.ContainerName, err)
			}

			L.Info().Msgf("Proposing job to executor %s (node %s)", exec.ContainerName, nodeID)

			resp, err := jdClient.ProposeJob(gCtx, &jobv1.ProposeJobRequest{
				NodeId: nodeID,
				Spec:   jobSpec,
			})
			if err != nil {
				return fmt.Errorf("failed to propose job to executor %s: %w", exec.ContainerName, err)
			}
			L.Info().
				Str("executor", exec.ContainerName).
				Str("nodeID", nodeID).
				Str("proposalID", resp.Proposal.Id).
				Msg("Proposed job to executor via JD")

			return nil
		})
	}

	return g.Wait()
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
	Name                    string `toml:"name"`
	ExternalJobID           string `toml:"externalJobID"`
	SchemaVersion           int    `toml:"schemaVersion"`
	Type                    string `toml:"type"`
	CommitteeVerifierConfig string `toml:"committeeVerifierConfig"`
}

func (vjs VerifierJobSpec) ToBootstrapJobSpec() bootstrap.JobSpec {
	return bootstrap.JobSpec{
		Name:          vjs.Name,
		ExternalJobID: vjs.ExternalJobID,
		SchemaVersion: vjs.SchemaVersion,
		Type:          vjs.Type,
		AppConfig:     vjs.CommitteeVerifierConfig,
	}
}

// ExecutorJobSpec represents the structure of an executor job spec TOML.
type ExecutorJobSpec struct {
	Name           string `toml:"name"`
	ExternalJobID  string `toml:"externalJobID"`
	SchemaVersion  int    `toml:"schemaVersion"`
	Type           string `toml:"type"`
	ExecutorConfig string `toml:"executorConfig"`
}

func (ejs ExecutorJobSpec) ToBootstrapJobSpec() bootstrap.JobSpec {
	return bootstrap.JobSpec{
		Name:          ejs.Name,
		ExternalJobID: ejs.ExternalJobID,
		SchemaVersion: ejs.SchemaVersion,
		Type:          ejs.Type,
		AppConfig:     ejs.ExecutorConfig,
	}
}

// extractAndValidateDisableFinalityCheckers extracts DisableFinalityCheckers from verifiers
// in a committee and validates that all verifiers have the same setting.
func extractAndValidateDisableFinalityCheckers(committeeName string, verifiers []*committeeverifier.Input) (disableFinalityCheckersPerFamily map[string][]string, err error) {
	if len(verifiers) == 0 {
		return nil, nil
	}

	disableFinalityCheckersPerFamily = make(map[string][]string)
	for _, ver := range verifiers {
		// if already set, check if it's the same value
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
	verifierJobSpecs map[string]bootstrap.JobSpec,
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

	// Use errgroup for parallel job proposals
	g, gCtx := errgroup.WithContext(ctx)

	for _, ver := range standaloneVerifiers {
		g.Go(func() error {
			// propose to all families
			if ver.Out == nil || ver.Out.JDNodeID == "" {
				return fmt.Errorf("verifier %s not registered with JD (missing JDNodeID)", ver.NOPAlias)
			}
			nodeID := ver.Out.JDNodeID

			loader, err := chainconfig.GetChainConfigLoader(ver.ChainFamily)
			if err != nil {
				return fmt.Errorf("failed to get chain config loader for family %s: %w", ver.ChainFamily, err)
			}

			blockchainInfos, err := loader(blockchainOutputs)
			if err != nil {
				return fmt.Errorf("failed to load chain config for family %s: %w", ver.ChainFamily, err)
			}

			// Get the base job spec
			baseJobSpec, ok := verifierJobSpecs[ver.NOPAlias]
			if !ok {
				return fmt.Errorf("no job spec found for verifier %s", ver.NOPAlias)
			}

			// For standalone verifiers, we need to inject blockchain_infos into the config
			// because they don't have CL node chain configuration
			jobSpec, err := committeeverifier.RebuildVerifierJobSpecWithBlockchainInfos(baseJobSpec, blockchainInfos)
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
