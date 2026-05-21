package protocol_contracts

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

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
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/committeeverifier"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/timing"
	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	ccvadapters "github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	ccvchangesets "github.com/smartcontractkit/chainlink-ccv/deployment/changesets"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

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

func (p *component) ValidateConfig(_ any) error { return nil }

// RunPhase3 deploys contracts, configures lanes, and generates aggregator/indexer
// configs. Infrastructure work (CL nodes, JD registration, verifier launch,
// credential generation) was completed by legacy RunPhase2.
//
// NOTE: DeployContractsForSelector currently deploys CommitteeVerifier
// proxy/resolver and MockReceivers when the topology includes committees.
// Extracting CommitteeVerifier deployment into a standalone component (using the
// DeployCommitteeVerifier changeset) is tracked as a follow-up.
func (p *component) RunPhase3(
	ctx context.Context,
	_ map[string]any,
	_ any,
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
	envTopology, ok := priorOutputs["_environment_topology"].(*ccvdeployment.EnvironmentTopology)
	if !ok {
		return nil, nil, fmt.Errorf("phase 2 did not produce *EnvironmentTopology under \"_environment_topology\"")
	}
	verifiers, _ := priorOutputs["verifiers"].([]*committeeverifier.Input)
	useLegacyConfigureLane, _ := priorOutputs["_use_legacy_configure_lane"].(bool)
	aggregators, _ := priorOutputs["_aggregators_with_creds"].([]*services.AggregatorInput)
	sharedTLSCerts, _ := priorOutputs["shared_tls_certs"].(*services.TLSCertPaths)

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

	topology := ccdeploy.BuildEnvironmentTopology(envTopology, verifiers, e)
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

	var connectErr error
	if useLegacyConfigureLane {
		connectErr = ccdeploy.ConnectAllChainsLegacy(impls, blockchains, selectors, e, topology)
	} else {
		connectErr = ccdeploy.ConnectAllChainsCanonical(impls, blockchains, selectors, e, topology)
	}
	if connectErr != nil {
		return nil, nil, connectErr
	}

	timeTrack.Record("[contracts] deployed")

	for _, aggregatorInput := range aggregators {
		aggregatorInput.SharedTLSCerts = sharedTLSCerts

		instanceName := aggregatorInput.InstanceName()
		committee, ok := topology.NOPTopology.Committees[aggregatorInput.CommitteeName]
		if !ok {
			return nil, nil, fmt.Errorf("committee %q not found in topology", aggregatorInput.CommitteeName)
		}
		cs := ccvchangesets.GenerateAggregatorConfig(ccvadapters.GetRegistry())
		output, err := cs.Apply(*e, ccvchangesets.GenerateAggregatorConfigInput{
			ServiceIdentifier:  instanceName + "-aggregator",
			CommitteeQualifier: aggregatorInput.CommitteeName,
			ChainSelectors:     ccvchangesets.CommitteeChainSelectorsFromTopology(committee),
		})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate aggregator config for %s (committee %s): %w", instanceName, aggregatorInput.CommitteeName, err)
		}

		aggCfg, err := ccvdeployment.GetAggregatorConfig(output.DataStore.Seal(), instanceName+"-aggregator")
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get aggregator config from output: %w", err)
		}
		aggregatorInput.GeneratedCommittee = aggCfg
		e.DataStore = output.DataStore.Seal()
		// Aggregator container launch is handled by the CommitteeCCV Phase 4 component,
		// which reads "aggregators" from the phase snapshot and calls services.NewAggregator.
	}

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
		"aggregators": aggregators,
		"_cldf":       cldf,
		"_env":        e,
		"_topology":   topology,
		"_selectors":  selectors,
		"_ds":         ds,
		"_impls":      impls,
		"_time_track": timeTrack,
	}, nil, nil
}
