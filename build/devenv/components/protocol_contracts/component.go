package protocol_contracts

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"

	"github.com/Masterminds/semver/v3"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	ccldf "github.com/smartcontractkit/chainlink-ccv/build/devenv/cldf"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	blockchainscomp "github.com/smartcontractkit/chainlink-ccv/build/devenv/components/blockchains"
	jdcomp "github.com/smartcontractkit/chainlink-ccv/build/devenv/components/jd"
	ccdeploy "github.com/smartcontractkit/chainlink-ccv/build/devenv/deploy"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/jobs"
	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/timing"
	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	ccvadapters "github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	ccvchangesets "github.com/smartcontractkit/chainlink-ccv/deployment/changesets"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

// Key is the TOML key used to register this component with the runtime.
const Key = "protocol_contracts"

// Version is the protocol_contracts component config schema version. Exactly
// this version is supported; configs declaring any other version are rejected.
const Version = 1

func init() {
	if err := devenvruntime.Register(Key, factory); err != nil {
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

// RunPhase2 deploys the core protocol contracts (via the DeployProtocolContracts
// changeset) and the per-chain tokens/pools. Committee verifiers, their resolvers,
// and mock receivers are deployed in Phase 3 (committeeccv) because they are not
// part of the protocol-contract set. Infrastructure services (verifier launch, JD
// registration, credential generation) are also handled by the CommitteeCCV Phase 3
// component, which runs after this.
func (p *component) RunPhase2(
	ctx context.Context,
	globalConfig map[string]any,
	componentConfig any,
	priorOutputs map[string]any,
) (map[string]any, []devenvruntime.Effect, error) {
	blockchains, ok := priorOutputs[blockchainscomp.Key].([]*blockchain.Input)
	if !ok {
		return nil, nil, fmt.Errorf("phase 1 did not produce []*blockchain.Input under %q", blockchainscomp.Key)
	}
	cldf := &ccldf.CLDF{}
	jdInfra, ok := priorOutputs[jdcomp.Key].(*jobs.JDInfrastructure)
	if !ok {
		return nil, nil, fmt.Errorf("phase 1 did not produce *jobs.JDInfrastructure under %q", jdcomp.Key)
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

		dsi, derr := deployProtocolContractsForSelector(ctx, e, impl, networkInfo.ChainSelector, topology, cfg.Deploy)
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
		// TODO: migrate this to an address-registration effect so deployed
		// addresses are registered to the datastore deterministically instead of
		// by mutating the shared CLDF accumulator
		// (see .scratch/phased-devenv-cleanup/issues/24).
		cldf.AddAddresses(string(a))
	}
	e.DataStore = ds.Seal()

	timeTrack.Record("[contracts] deployed")

	// Token transfer configuration (ConfigureAllTokenTransfers) and lane configuration
	// (ConnectAllChains) are both deferred to CommitteeCCV Phase 3: each wires token pools /
	// lanes to the CommitteeVerifier resolver, which is now deployed in Phase 3. (Lane config
	// additionally calls ApplyVerifierConfig, which needs verifier signing keys from JD —
	// available only after verifiers launch in Phase 3.)

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
		// Public keys (serialized to the output file): cldf carries the deployed
		// addresses + env metadata; environment_topology is read by tests. The
		// remaining "_"-prefixed keys are runtime-only and stripped on serialize.
		"cldf":                 cldf,
		"environment_topology": topology,
		"_env":                 e,
		"_selectors":           selectors,
		"_ds":                  ds,
		"_impls":               impls,
		"_time_track":          timeTrack,
	}, nil, nil
}

// config is the [protocol_contracts] component config.
type config struct {
	Version int `toml:"version"`
	// UseLegacyConfigureLane is consumed by the committeeccv component via the
	// global config; it is decoded here so the strict round-trip accepts it.
	UseLegacyConfigureLane bool                               `toml:"use_legacy_configure_lane"`
	EnvironmentTopology    *ccvdeployment.EnvironmentTopology `toml:"environment_topology"`
	// Deploy carries the per-chain protocol-contract deploy parameters fed to the
	// chain-agnostic DeployProtocolContracts changeset.
	Deploy deployCfg `toml:"deploy"`
}

// deployCfg holds the protocol-contract deploy tunables sourced from
// [protocol_contracts.deploy]. FamilyExtras passes chain-family-specific
// overrides straight through to the changeset (e.g. the "evm" sub-map is read by
// the EVM ProtocolContractsDeployAdapter).
type deployCfg struct {
	DeployTestRouter bool           `toml:"deploy_test_router"`
	Executors        []executorCfg  `toml:"executors"`
	FamilyExtras     map[string]any `toml:"family_extras"`
}

// executorCfg is a single executor instance to deploy.
type executorCfg struct {
	Qualifier string `toml:"qualifier"`
	Version   string `toml:"version"`
}

func decodeConfig(raw any) (config, error) {
	cfg, err := devenvruntime.DecodeConfig[config](raw, Key)
	if err != nil {
		return config{}, err
	}
	if err := devenvruntime.CheckConfigVersion(cfg.Version, Version); err != nil {
		return config{}, err
	}
	return cfg, nil
}

// deployProtocolContractsForSelector deploys the core protocol contracts on a
// single chain via the chain-agnostic DeployProtocolContracts changeset. It is a
// near-copy of deploy.DeployContractsForSelector with the kitchen-sink
// DeployChainContracts call replaced — committee verifiers and mock receivers are
// no longer deployed here (committeeccv handles them in Phase 3). The chain impl
// still provides the pre-hook (e.g. CREATE2 factory) and post-hook (e.g.
// USDC/Lombard pools); deploy tunables come from the component config.
func deployProtocolContractsForSelector(
	ctx context.Context,
	env *deployment.Environment,
	impl cciptestinterfaces.OnChainConfigurable,
	selector uint64,
	topology *ccvdeployment.EnvironmentTopology,
	deploy deployCfg,
) (datastore.DataStore, error) {
	runningDS := datastore.NewMemoryDataStore()

	env.OperationsBundle = operations.NewBundle(
		func() context.Context { return context.Background() },
		env.Logger,
		operations.NewMemoryReporter(),
	)

	// TODO: move pre-deploy contract logic to a dedicated component.
	// 1. Pre-hook (e.g. EVM deploys CREATE2 factory here).
	preDS, err := impl.PreDeployContractsForSelector(ctx, env, selector, topology)
	if err != nil {
		return nil, fmt.Errorf("pre-deploy for selector %d: %w", selector, err)
	}
	if preDS != nil {
		if err := runningDS.Merge(preDS); err != nil {
			return nil, fmt.Errorf("merge pre-deploy DS: %w", err)
		}
		merged, err := mergeIntoSealed(env.DataStore, preDS)
		if err != nil {
			return nil, fmt.Errorf("update env DS with pre-deploy: %w", err)
		}
		env.DataStore = merged
	}

	// 2. Resolve the deployer contract (e.g. CREATE2 factory) from the chain impl.
	// Only DeployerContract is used; the remaining ccip-shaped fields are ignored
	// because deploy params now come from the component config.
	chainCfg, err := impl.GetDeployChainContractsCfg(env, selector, topology)
	if err != nil {
		return nil, fmt.Errorf("get deploy config for selector %d: %w", selector, err)
	}
	if chainCfg.DeployerContract == nil || *chainCfg.DeployerContract == "" {
		return nil, fmt.Errorf("deployer contract not resolved for selector %d", selector)
	}

	executors, err := toCCVExecutors(deploy.Executors)
	if err != nil {
		return nil, fmt.Errorf("selector %d: %w", selector, err)
	}

	// 3. Deploy protocol contracts via the chain-agnostic ccv changeset.
	out, err := ccvchangesets.DeployProtocolContracts().Apply(*env, ccvchangesets.DeployProtocolContractsInput{
		ChainSelectors: []uint64{selector},
		ChainCfgs: map[uint64]ccvchangesets.DeployProtocolContractsPerChainCfg{
			selector: {
				DeployerContract: *chainCfg.DeployerContract,
				DeployTestRouter: deploy.DeployTestRouter,
				DeployerKeyOwned: true,
				Executors:        executors,
				FamilyExtras:     deploy.FamilyExtras,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("deploy protocol contracts for selector %d: %w", selector, err)
	}
	if err := runningDS.Merge(out.DataStore.Seal()); err != nil {
		return nil, fmt.Errorf("merge deploy output DS: %w", err)
	}
	merged, err := mergeIntoSealed(env.DataStore, out.DataStore.Seal())
	if err != nil {
		return nil, fmt.Errorf("update env DS with deploy output: %w", err)
	}
	env.DataStore = merged

	// TODO: move post-deploy contract logic to a dedicated component.
	// 4. Post-hook (e.g. EVM deploys USDC/Lombard pools here).
	postDS, err := impl.PostDeployContractsForSelector(ctx, env, selector, topology)
	if err != nil {
		return nil, fmt.Errorf("post-deploy for selector %d: %w", selector, err)
	}
	if postDS != nil {
		if err := runningDS.Merge(postDS); err != nil {
			return nil, fmt.Errorf("merge post-deploy DS: %w", err)
		}
		merged, err := mergeIntoSealed(env.DataStore, postDS)
		if err != nil {
			return nil, fmt.Errorf("update env DS with post-deploy: %w", err)
		}
		env.DataStore = merged
	}

	return runningDS.Seal(), nil
}

// toCCVExecutors converts the component's executor config into the chain-agnostic
// executor deploy params. When no executors are configured it falls back to the
// default + custom executor qualifiers at version 2.0.0.
func toCCVExecutors(execs []executorCfg) ([]ccvadapters.ExecutorDeployParams, error) {
	if len(execs) == 0 {
		execs = []executorCfg{
			{Qualifier: devenvcommon.DefaultExecutorQualifier, Version: "2.0.0"},
			{Qualifier: devenvcommon.CustomExecutorQualifier, Version: "2.0.0"},
		}
	}
	result := make([]ccvadapters.ExecutorDeployParams, 0, len(execs))
	for _, e := range execs {
		v, err := semver.NewVersion(e.Version)
		if err != nil {
			return nil, fmt.Errorf("executor %q: invalid version %q: %w", e.Qualifier, e.Version, err)
		}
		result = append(result, ccvadapters.ExecutorDeployParams{
			Qualifier: e.Qualifier,
			Version:   v,
		})
	}
	return result, nil
}

// mergeIntoSealed creates a new DataStore by merging all provided stores in order
// and returns the sealed result. Local copy of the unexported deploy.mergeIntoSealed.
func mergeIntoSealed(stores ...datastore.DataStore) (datastore.DataStore, error) {
	tmp := datastore.NewMemoryDataStore()
	for _, s := range stores {
		if err := tmp.Merge(s); err != nil {
			return nil, err
		}
	}
	return tmp.Seal(), nil
}
