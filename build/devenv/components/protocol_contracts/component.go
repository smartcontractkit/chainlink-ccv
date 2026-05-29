package protocol_contracts

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/pelletier/go-toml/v2"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	ccldf "github.com/smartcontractkit/chainlink-ccv/build/devenv/cldf"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	ccdeploy "github.com/smartcontractkit/chainlink-ccv/build/devenv/deploy"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/jobs"
	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/timing"
	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

// Version is the protocol_contracts component config schema version. Exactly
// this version is supported; configs declaring any other version are rejected.
const Version = 1

func init() {
	if err := devenvruntime.Register("protocol_contracts", factory); err != nil {
		panic(fmt.Sprintf("protocol_contracts component: %v", err))
	}
}

func factory(_ map[string]any) (devenvruntime.Component, error) {
	// Default logger; overridden by the runtime via SetLogger if available.
	return &component{
		lggr: zlog.Output(zerolog.ConsoleWriter{Out: os.Stderr}).Level(zerolog.DebugLevel).With().Str("component", "protocol_contracts").Logger(),
	}, nil
}

type component struct {
	lggr zerolog.Logger
}

func (p *component) SetLogger(lggr zerolog.Logger) {
	p.lggr = lggr.With().Str("component", "protocol_contracts").Logger()
}

func (p *component) ValidateConfig(componentConfig any) error {
	_, err := decodeConfig(componentConfig)
	return err
}

// RunPhase2 deploys contracts and configures lanes. Infrastructure services
// (verifier launch, JD registration, credential generation) are handled by the
// CommitteeCCV Phase 3 component, which runs after this.
//
// NOTE: DeployContractsForSelector currently deploys CommitteeVerifier
// proxy/resolver and MockReceivers when the topology includes committees.
// Extracting CommitteeVerifier deployment into a standalone component (using the
// DeployCommitteeVerifier changeset) is tracked as a follow-up.
func (p *component) RunPhase2(
	ctx context.Context,
	globalConfig map[string]any,
	componentConfig any,
	priorOutputs map[string]any,
) (map[string]any, []devenvruntime.Effect, error) {
	blockchains, ok := priorOutputs["blockchains"].([]*blockchain.Input)
	if !ok {
		return nil, nil, fmt.Errorf("phase 1 did not produce []*blockchain.Input under \"blockchains\"")
	}
	cldf := &ccldf.CLDF{}
	jdInfra, ok := priorOutputs["jd"].(*jobs.JDInfrastructure)
	if !ok {
		return nil, nil, fmt.Errorf("phase 2 did not produce *jobs.JDInfrastructure under \"jd\"")
	}
	// Topology lives under [protocol_contracts.environment_topology]; read it from
	// this component's own config rather than the top-level raw config.
	cfg, err := decodeConfig(componentConfig)
	if err != nil {
		return nil, nil, err
	}
	envTopology := cfg.EnvironmentTopology
	if envTopology == nil {
		return nil, nil, fmt.Errorf("environment_topology is required but not found in config")
	}
	timeTrack := timing.New(p.lggr)
	ctx = p.lggr.WithContext(ctx)

	impls := make([]cciptestinterfaces.CCIP17Configuration, len(blockchains))
	for i, bc := range blockchains {
		if bc.Out == nil {
			return nil, nil, fmt.Errorf("blockchain[%d] %q: phase 1 did not populate Out", i, bc.ContainerName)
		}
		impl, ierr := chainreg.NewProductConfigurationFromNetwork(bc.Type)
		if ierr != nil {
			return nil, nil, ierr
		}
		impls[i] = impl
	}

	cldf.Init()
	cldfCfg := ccldf.CLDFEnvironmentConfig{
		Blockchains:    blockchains,
		DataStore:      cldf.DataStore,
		OffchainClient: jdInfra.OffchainClient,
		NodeIDs:        jdInfra.GetNodeIDs(),
	}
	selectors, e, err := ccldf.NewCLDFOperationsEnvironmentWithOffchain(cldfCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("creating CLDF operations environment: %w", err)
	}
	p.lggr.Info().Any("Selectors", selectors).Msg("Deploying for chain selectors")

	topology := ccdeploy.BuildEnvironmentTopology(envTopology, nil, e)
	if topology == nil {
		return nil, nil, fmt.Errorf("failed to build environment topology")
	}

	timeTrack.Record("[contracts] deploying chains")

	capsBySelector := make(map[uint64][]devenvcommon.PoolCapability, len(impls))
	for i, impl := range impls {
		networkInfo, lookupErr := chainsel.GetChainDetailsByChainIDAndFamily(blockchains[i].ChainID, impl.ChainFamily())
		if lookupErr != nil {
			return nil, nil, lookupErr
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
		networkInfo, nerr := chainsel.GetChainDetailsByChainIDAndFamily(blockchains[i].ChainID, impl.ChainFamily())
		if nerr != nil {
			return nil, nil, nerr
		}
		p.lggr.Info().Uint64("Selector", networkInfo.ChainSelector).Msg("Deploying chain selector")
		// Shift the deployer nonce intentionally so each chain gets different
		// contract addresses, catching bugs that assume address uniformity.
		if bumper, ok := impl.(cciptestinterfaces.DeployerNonceBumper); ok && i > 0 {
			if err := bumper.BumpDeployerNonce(ctx, e, networkInfo.ChainSelector, i); err != nil {
				return nil, nil, fmt.Errorf("failed to bump deployer nonce for chain %d: %w", networkInfo.ChainSelector, err)
			}
		}
		chainDS := datastore.NewMemoryDataStore()

		dsi, derr := ccdeploy.DeployContractsForSelector(ctx, e, impl, networkInfo.ChainSelector, topology)
		if derr != nil {
			return nil, nil, derr
		}
		if err = ds.Merge(dsi); err != nil {
			return nil, nil, err
		}
		if err = chainDS.Merge(dsi); err != nil {
			return nil, nil, err
		}
		e.DataStore = ds.Seal()

		tokenDS := datastore.NewMemoryDataStore()
		if tcp, ok := impl.(cciptestinterfaces.TokenConfigProvider); ok {
			if err = ccdeploy.DeployTokensAndPools(tcp, e, networkInfo.ChainSelector, combos, tokenDS); err != nil {
				return nil, nil, fmt.Errorf("deploy tokens and pools for selector %d: %w", networkInfo.ChainSelector, err)
			}
		}
		if err = ds.Merge(tokenDS.Seal()); err != nil {
			return nil, nil, err
		}
		if err = chainDS.Merge(tokenDS.Seal()); err != nil {
			return nil, nil, err
		}
		e.DataStore = ds.Seal()

		var addresses []datastore.AddressRef
		addresses, err = chainDS.Seal().Addresses().Fetch()
		if err != nil {
			return nil, nil, err
		}
		var a []byte
		a, err = json.Marshal(addresses)
		if err != nil {
			return nil, nil, err
		}
		cldf.AddAddresses(string(a))
	}
	e.DataStore = ds.Seal()

	if err = ccdeploy.ConfigureAllTokenTransfers(impls, selectors, e, topology); err != nil {
		return nil, nil, fmt.Errorf("configure all token transfers: %w", err)
	}

	timeTrack.Record("[contracts] deployed")

	// Lane configuration (ConnectAllChains) is deferred to CommitteeCCV Phase 3 because it
	// calls ApplyVerifierConfig which fetches verifier signing keys from JD. Verifiers are not
	// launched and registered until Phase 3, so this step cannot run here.

	// Finalize CLDF: snapshot env metadata and print deployed addresses.
	envMetadata, err := e.DataStore.EnvMetadata().Get()
	if err != nil && err != datastore.ErrEnvMetadataNotSet {
		return nil, nil, fmt.Errorf("getting env metadata: %w", err)
	}
	envMetadataJSON, err := json.Marshal(envMetadata)
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling env metadata: %w", err)
	}
	cldf.AddEnvMetadata(string(envMetadataJSON))
	if err := cldf.PrintAddresses(); err != nil {
		return nil, nil, err
	}

	return map[string]any{
		"_cldf":       cldf,
		"_env":        e,
		"_topology":   topology,
		"_selectors":  selectors,
		"_ds":         ds,
		"_impls":      impls,
		"_time_track": timeTrack,
	}, nil, nil
}

// config is the [protocol_contracts] component config.
type config struct {
	Version int `toml:"version"`
	// UseLegacyConfigureLane is consumed by the committeeccv component via the
	// global config; it is decoded here so the strict round-trip accepts it.
	UseLegacyConfigureLane bool                               `toml:"use_legacy_configure_lane"`
	EnvironmentTopology    *ccvdeployment.EnvironmentTopology `toml:"environment_topology"`
}

// decodeConfig round-trips the raw TOML component config into a typed config and
// verifies its declared version.
func decodeConfig(raw any) (config, error) {
	b, err := toml.Marshal(raw)
	if err != nil {
		return config{}, fmt.Errorf("re-encoding protocol_contracts config: %w", err)
	}
	var cfg config
	if err := toml.Unmarshal(b, &cfg); err != nil {
		return config{}, fmt.Errorf("decoding protocol_contracts config: %w", err)
	}
	if err := devenvruntime.CheckConfigVersion(cfg.Version, Version); err != nil {
		return config{}, err
	}
	return cfg, nil
}
