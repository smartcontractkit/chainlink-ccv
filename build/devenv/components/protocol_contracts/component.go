package protocol_contracts

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	chainsel "github.com/smartcontractkit/chain-selectors"
	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/jobs"
	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	committeeverifier "github.com/smartcontractkit/chainlink-ccv/build/devenv/services/committeeverifier"
	executorsvc "github.com/smartcontractkit/chainlink-ccv/build/devenv/services/executor"
	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	ccvchangesets "github.com/smartcontractkit/chainlink-ccv/deployment/changesets"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
	ns "github.com/smartcontractkit/chainlink-testing-framework/framework/components/simple_node_set"
)

func init() {
	if err := devenvruntime.Register("protocol_contracts", factory); err != nil {
		panic(fmt.Sprintf("protocol_contracts component: %v", err))
	}
}

func factory(_ map[string]any) (devenvruntime.Component, error) {
	return &component{}, nil
}

type component struct{}

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
	configs := strings.Split(os.Getenv(ccv.EnvVarTestConfigs), ",")
	if len(configs) > 1 {
		ccv.L.Warn().Msg("Multiple configuration files detected, this feature may be unsupported in the future.")
	}
	in, err := ccv.Load[ccv.Cfg](configs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	bcs, ok := priorOutputs["blockchains"].([]*blockchain.Input)
	if !ok {
		return nil, nil, fmt.Errorf("phase 1 did not produce []*blockchain.Input under \"blockchains\"")
	}
	in.Blockchains = bcs

	if nss, ok := priorOutputs["nodesets"].([]*ns.Input); ok {
		in.NodeSets = nss
	}

	if jdInfra, ok := priorOutputs["jd"].(*jobs.JDInfrastructure); ok {
		in.JDInfra = jdInfra
	}

	if execs, ok := priorOutputs["executor"].([]*executorsvc.Input); ok {
		in.Executor = execs
	}

	if fake, ok := priorOutputs["fake"].(*services.FakeInput); ok {
		in.Fake = fake
	}

	if pricer, ok := priorOutputs["pricer"].(*services.PricerInput); ok {
		in.Pricer = pricer
	}

	// expandForHA expands both aggregators and indexers. We call it first so
	// indexers are correctly expanded, then replace in.Aggregator with the
	// Phase 2 output that is already expanded and credentialed.
	if err = in.ExpandForHA(); err != nil {
		return nil, nil, fmt.Errorf("failed to expand HA configuration: %w", err)
	}
	if aggsWithCreds, ok := priorOutputs["_aggregators_with_creds"].([]*services.AggregatorInput); ok {
		in.Aggregator = aggsWithCreds
	}
	if verifiers, ok := priorOutputs["verifiers"].([]*committeeverifier.Input); ok {
		in.Verifier = verifiers
	}
	sharedTLSCerts, _ := priorOutputs["shared_tls_certs"].(*services.TLSCertPaths)

	timeTrack := ccv.NewTimeTracker(ccv.Plog)
	ctx = ccv.L.WithContext(ctx)

	var fakeOut *services.FakeOutput
	if in.Fake != nil {
		fakeOut = in.Fake.Out
	}

	impls := make([]cciptestinterfaces.CCIP17Configuration, len(in.Blockchains))
	blockchainOutputs := make([]*blockchain.Output, len(in.Blockchains))
	for i, bc := range in.Blockchains {
		if bc.Out == nil {
			return nil, nil, fmt.Errorf("blockchain[%d] %q: phase 1 did not populate Out", i, bc.ContainerName)
		}
		impl, ierr := ccv.NewProductConfigurationFromNetwork(bc.Type)
		if ierr != nil {
			return nil, nil, ierr
		}
		impls[i] = impl
		blockchainOutputs[i] = bc.Out
	}

	in.CLDF.Init()
	cldfCfg := ccv.CLDFEnvironmentConfig{
		Blockchains:    in.Blockchains,
		DataStore:      in.CLDF.DataStore,
		OffchainClient: in.JDInfra.OffchainClient,
		NodeIDs:        in.JDInfra.GetNodeIDs(),
	}
	selectors, e, err := ccv.NewCLDFOperationsEnvironmentWithOffchain(cldfCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("creating CLDF operations environment: %w", err)
	}
	ccv.L.Info().Any("Selectors", selectors).Msg("Deploying for chain selectors")

	topology := ccv.BuildEnvironmentTopology(in, e)
	if topology == nil {
		return nil, nil, fmt.Errorf("failed to build environment topology")
	}

	timeTrack.Record("[contracts] deploying chains")

	capsBySelector := make(map[uint64][]devenvcommon.PoolCapability, len(impls))
	for i, impl := range impls {
		networkInfo, lookupErr := chainsel.GetChainDetailsByChainIDAndFamily(in.Blockchains[i].ChainID, impl.ChainFamily())
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
		networkInfo, nerr := chainsel.GetChainDetailsByChainIDAndFamily(in.Blockchains[i].ChainID, impl.ChainFamily())
		if nerr != nil {
			return nil, nil, nerr
		}
		ccv.L.Info().Uint64("Selector", networkInfo.ChainSelector).Msg("Deploying chain selector")
		// Shift the deployer nonce intentionally so each chain gets different
		// contract addresses, catching bugs that assume address uniformity.
		if bumper, ok := impl.(cciptestinterfaces.DeployerNonceBumper); ok && i > 0 {
			if err := bumper.BumpDeployerNonce(ctx, e, networkInfo.ChainSelector, i); err != nil {
				return nil, nil, fmt.Errorf("failed to bump deployer nonce for chain %d: %w", networkInfo.ChainSelector, err)
			}
		}
		chainDS := datastore.NewMemoryDataStore()

		dsi, derr := ccv.DeployContractsForSelector(ctx, e, impl, networkInfo.ChainSelector, topology)
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
			if err = ccv.DeployTokensAndPools(tcp, e, networkInfo.ChainSelector, combos, tokenDS); err != nil {
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
		in.CLDF.AddAddresses(string(a))
	}
	e.DataStore = ds.Seal()

	if err = ccv.ConfigureAllTokenTransfers(impls, selectors, e, topology); err != nil {
		return nil, nil, fmt.Errorf("configure all token transfers: %w", err)
	}

	var connectErr error
	if in.ProtocolContracts.UseLegacyConfigureLane {
		connectErr = ccv.ConnectAllChainsLegacy(impls, in.Blockchains, selectors, e, topology)
	} else {
		connectErr = ccv.ConnectAllChainsCanonical(impls, in.Blockchains, selectors, e, topology)
	}
	if connectErr != nil {
		return nil, nil, connectErr
	}

	timeTrack.Record("[contracts] deployed")

	in.AggregatorEndpoints = make(map[string]string)
	in.AggregatorCACertFiles = make(map[string]string)

	for _, aggregatorInput := range in.Aggregator {
		aggregatorInput.SharedTLSCerts = sharedTLSCerts

		instanceName := aggregatorInput.InstanceName()
		committee, ok := topology.NOPTopology.Committees[aggregatorInput.CommitteeName]
		if !ok {
			return nil, nil, fmt.Errorf("committee %q not found in topology", aggregatorInput.CommitteeName)
		}
		cs := ccvchangesets.GenerateAggregatorConfig()
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

	if len(in.Aggregator) > 0 && len(in.Indexer) > 0 {
		firstIdx := in.Indexer[0]
		cs := ccvchangesets.GenerateIndexerConfig()
		output, err := cs.Apply(*e, ccvchangesets.GenerateIndexerConfigInput{
			ServiceIdentifier:                "indexer",
			CommitteeVerifierNameToQualifier: firstIdx.CommitteeVerifierNameToQualifier,
			CCTPVerifierNameToQualifier:      firstIdx.CCTPVerifierNameToQualifier,
			LombardVerifierNameToQualifier:   firstIdx.LombardVerifierNameToQualifier,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate indexer config: %w", err)
		}

		idxCfg, err := ccvdeployment.GetIndexerConfig(output.DataStore.Seal(), "indexer")
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get indexer config from output: %w", err)
		}
		e.DataStore = output.DataStore.Seal()
		for _, idxIn := range in.Indexer {
			idxIn.GeneratedCfg = idxCfg
		}
	}

	if len(in.Indexer) < 1 {
		return nil, nil, fmt.Errorf("at least one indexer is required")
	}

	return map[string]any{
		"aggregators":              in.Aggregator,
		"_prepared_indexer_inputs": in.Indexer,
		"_protocol_setup": &ccv.PhasedSetup{
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
		},
	}, nil, nil
}
