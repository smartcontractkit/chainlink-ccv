package monolith

import (
	"fmt"
	"maps"
	"strconv"

	"github.com/rs/zerolog"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/jobs"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	committeeverifier "github.com/smartcontractkit/chainlink-ccv/build/devenv/services/committeeverifier"
	executorsvc "github.com/smartcontractkit/chainlink-ccv/build/devenv/services/executor"
	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	ccvshared "github.com/smartcontractkit/chainlink-ccv/deployment/shared"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
	jd "github.com/smartcontractkit/chainlink-testing-framework/framework/components/jd"
	ns "github.com/smartcontractkit/chainlink-testing-framework/framework/components/simple_node_set"
)

// ProtocolContractsCfg holds config for the protocol_contracts Phase 3 component.
type ProtocolContractsCfg struct {
	// UseLegacyConfigureLane selects the legacy lanes.ConnectChains path
	// instead of the canonical ConfigureChainsForLanesFromTopology changeset.
	UseLegacyConfigureLane bool `toml:"use_legacy_configure_lane"`
}

type Cfg struct {
	// Version is incremented on breaking config schema changes so downstream
	// consumers can detect incompatible configs. Version 0 (implicit/absent)
	// predates the [protocol_contracts] section.
	Version            int                            `toml:"version"`
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
	// ExpandForHA() clones AggregatorInput / IndexerInput entries according
	// to their per-service redundancy counts and updates the topology.
	HighAvailability  bool                 `toml:"high_availability"`
	ProtocolContracts ProtocolContractsCfg `toml:"protocol_contracts"`
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
	// GenericServices is a map of chain selector to its generic service definition.
	GenericServices map[uint64]*chainreg.GenericServiceDefinition `toml:"generic_services" validate:"required"`
	// JDInfra holds the runtime JD infrastructure (not from config, populated at runtime).
	JDInfra *jobs.JDInfrastructure `toml:"-"`
	// ClientLookup provides ChainlinkClient lookup by NOP alias (populated at runtime).
	ClientLookup *jobs.NodeSetClientLookup `toml:"-"`
}

// ExpandForHA clones AggregatorInput / IndexerInput entries based on their
// per-service redundancy counts and updates the EnvironmentTopology so that
// downstream changesets and service launches see the expanded set.
// When HighAvailability is false this is a no-op.
func (c *Cfg) ExpandForHA() error {
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

func NewProductConfigurationFromNetwork(typ string) (cciptestinterfaces.CCIP17Configuration, error) {
	resolved, err := blockchain.TypeToFamily(typ)
	if err != nil {
		// typ might already be a family name — try the factory directly before giving up.
		if reg, regErr := chainreg.GetRegistry().Get(typ); regErr == nil && reg.ImplFactory != nil {
			return reg.ImplFactory.NewEmpty(), nil
		}
		return nil, fmt.Errorf("unknown blockchain type %q (not a recognized type or family): %w", typ, err)
	}
	family := string(resolved)
	reg, err := chainreg.GetRegistry().Get(family)
	if err != nil {
		return nil, fmt.Errorf("could not find chain registration for chain type %s (family %s): %w", typ, family, err)
	}
	if reg.ImplFactory == nil {
		return nil, fmt.Errorf("implementation factory for family %s not found", family)
	}
	return reg.ImplFactory.NewEmpty(), nil
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
	factories := chainreg.GetRegistry().GetAllImplFactories()

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

// BuildEnvironmentTopology creates a copy of the EnvironmentTopology from the Cfg,
// enriches it with signer addresses, and returns it. This is used by both executor
// and verifier changesets as the single source of truth.
// For each chain_config entry that lacks a FeeAggregator, the corresponding
// chain's deployer key is used as a fallback via the registered ImplFactory.
func BuildEnvironmentTopology(in *Cfg, e *deployment.Environment) *ccvdeployment.EnvironmentTopology {
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
				reg, err := chainreg.GetRegistry().Get(family)
				if err != nil || reg.ImplFactory == nil {
					continue
				}
				if addr := reg.ImplFactory.DefaultFeeAggregator(e, sel); addr != "" {
					chainCfg.FeeAggregator = addr
					committee.ChainConfigs[chainSel] = chainCfg
				}
			}
		}
		envCfg.NOPTopology.Committees[name] = committee
	}

	return &envCfg
}
