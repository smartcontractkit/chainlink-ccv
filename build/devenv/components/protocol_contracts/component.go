package protocol_contracts

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/Masterminds/semver/v3"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"

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
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
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

	// Synthesize committee topology from committeeccv config when none is provided.
	if envTopology.NOPTopology == nil || len(envTopology.NOPTopology.Committees) == 0 {
		synthesized, synthErr := synthesizeCommittees(globalConfig, selectors)
		if synthErr != nil {
			return nil, nil, fmt.Errorf("synthesizing committees from committeeccv config: %w", synthErr)
		}
		envTopology = injectCommittees(envTopology, synthesized)
	}

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

// committeeDeploySpec mirrors committeeccv.CommitteeDeployConfig without importing that package.
type committeeDeploySpec struct {
	Qualifier                    string `toml:"qualifier"`
	VerifierVersion              string `toml:"verifier_version"`
	Threshold                    uint8  `toml:"threshold"`
	InsecureAggregatorConnection bool   `toml:"insecure_aggregator_connection"`
}

// committeeVerifierSpec is a partial mirror of committeeverifier.Input.
type committeeVerifierSpec struct {
	NOPAlias      string `toml:"nop_alias"`
	CommitteeName string `toml:"committee_name"`
}

// committeeAggregatorSpec is a partial mirror of services.AggregatorInput.
type committeeAggregatorSpec struct {
	Name          string `toml:"name"`
	CommitteeName string `toml:"committee_name"`
}

// committeeccvPartial decodes only the fields needed for committee synthesis.
type committeeccvPartial struct {
	Committees  []committeeDeploySpec     `toml:"committee"`
	Verifiers   []committeeVerifierSpec   `toml:"verifier"`
	Aggregators []committeeAggregatorSpec `toml:"aggregator"`
}

// synthesizeCommittees builds a CommitteeConfig map from committeeccv config entries,
// using the given chain selectors to populate per-chain configs. It returns nil when no
// [[committeeccv.committee]] entries are present, signaling that synthesis is not needed.
func synthesizeCommittees(globalConfig map[string]any, selectors []uint64) (map[string]ccvdeployment.CommitteeConfig, error) {
	partial, err := devenvruntime.DecodeConfig[committeeccvPartial](globalConfig["committeeccv"], "committeeccv")
	if err != nil {
		return nil, fmt.Errorf("decoding committeeccv config for synthesis: %w", err)
	}
	if len(partial.Committees) == 0 {
		return nil, nil
	}

	// Index verifier NOPAliases per committee qualifier.
	nopsByCommittee := make(map[string][]string)
	for _, v := range partial.Verifiers {
		nopsByCommittee[v.CommitteeName] = append(nopsByCommittee[v.CommitteeName], v.NOPAlias)
	}

	// Index aggregator container address per committee qualifier.
	aggAddrByCommittee := make(map[string]string)
	for _, a := range partial.Aggregators {
		instanceName := a.Name
		if instanceName == "" {
			instanceName = a.CommitteeName
		}
		aggAddrByCommittee[a.CommitteeName] = fmt.Sprintf("%s-aggregator:50051", instanceName)
	}

	committees := make(map[string]ccvdeployment.CommitteeConfig, len(partial.Committees))
	for _, spec := range partial.Committees {
		if spec.Qualifier == "" {
			return nil, fmt.Errorf("committeeccv.committee entry missing qualifier")
		}
		ver, verErr := semver.NewVersion(spec.VerifierVersion)
		if verErr != nil {
			return nil, fmt.Errorf("committee %q: invalid verifier_version %q: %w", spec.Qualifier, spec.VerifierVersion, verErr)
		}
		nopAliases := nopsByCommittee[spec.Qualifier]
		if len(nopAliases) == 0 {
			return nil, fmt.Errorf("committee %q: no verifiers found in committeeccv config for synthesis", spec.Qualifier)
		}
		aggAddr, ok := aggAddrByCommittee[spec.Qualifier]
		if !ok {
			return nil, fmt.Errorf("committee %q: no aggregator found in committeeccv config for synthesis", spec.Qualifier)
		}
		chainCfgs := make(map[string]ccvdeployment.ChainCommitteeConfig, len(selectors))
		for _, sel := range selectors {
			chainCfgs[strconv.FormatUint(sel, 10)] = ccvdeployment.ChainCommitteeConfig{
				NOPAliases: nopAliases,
				Threshold:  spec.Threshold,
			}
		}
		committees[spec.Qualifier] = ccvdeployment.CommitteeConfig{
			Qualifier:       spec.Qualifier,
			VerifierVersion: ver,
			ChainConfigs:    chainCfgs,
			Aggregators: []ccvdeployment.AggregatorConfig{
				{
					Name:                         spec.Qualifier,
					Address:                      aggAddr,
					InsecureAggregatorConnection: spec.InsecureAggregatorConnection,
				},
			},
		}
	}
	return committees, nil
}

// injectCommittees returns a shallow copy of envTopology with the supplied committees
// set on the NOPTopology. Returns the original pointer unchanged when committees is empty.
func injectCommittees(envTopology *ccvdeployment.EnvironmentTopology, committees map[string]ccvdeployment.CommitteeConfig) *ccvdeployment.EnvironmentTopology {
	if len(committees) == 0 {
		return envTopology
	}
	topoWithCommittees := *envTopology
	if topoWithCommittees.NOPTopology == nil {
		topoWithCommittees.NOPTopology = &ccvdeployment.NOPTopology{}
	} else {
		nopCopy := *topoWithCommittees.NOPTopology
		topoWithCommittees.NOPTopology = &nopCopy
	}
	topoWithCommittees.NOPTopology.Committees = committees
	return &topoWithCommittees
}
