package ccv

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/jobs"
	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	executorsvc "github.com/smartcontractkit/chainlink-ccv/build/devenv/services/executor"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/util"
	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	ccvshared "github.com/smartcontractkit/chainlink-ccv/deployment/shared"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
	ns "github.com/smartcontractkit/chainlink-testing-framework/framework/components/simple_node_set"
)

// legacyCfgKey is the output map key under which the legacy fallback component
// stores the fully-initialized *Cfg so that NewPhasedEnvironment can extract it.
const legacyCfgKey = "_legacy_cfg"

func init() {
	devenvruntime.SetFallback(legacyFactory)
}

func legacyFactory(_ map[string]any) (devenvruntime.Component, error) {
	return &legacyComponent{}, nil
}

type legacyComponent struct{}

func (l *legacyComponent) ValidateConfig(_ any) error { return nil }

// RunPhase2 handles credential generation, CL node launch, JD registration,
// and verifier launch. Contract deployment and config generation are deferred
// to the protocol_contracts Phase 3 component.
func (l *legacyComponent) RunPhase2(
	ctx context.Context,
	_ map[string]any,
	_ any,
	priorOutputs map[string]any,
) (map[string]any, []devenvruntime.Effect, error) {
	configs := strings.Split(os.Getenv(EnvVarTestConfigs), ",")
	if len(configs) > 1 {
		L.Warn().Msg("Multiple configuration files detected, this feature may be unsupported in the future.")
	}
	in, err := Load[Cfg](configs)
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

	if err = in.ExpandForHA(); err != nil {
		return nil, nil, fmt.Errorf("failed to expand HA configuration: %w", err)
	}

	// Build per-chain impls — needed by launchCLNodes.
	impls := make([]cciptestinterfaces.CCIP17Configuration, len(in.Blockchains))
	blockchainOutputs := make([]*blockchain.Output, len(in.Blockchains))
	for i, bc := range in.Blockchains {
		if bc.Out == nil {
			return nil, nil, fmt.Errorf("blockchain[%d] %q: phase 1 did not populate Out", i, bc.ContainerName)
		}
		impl, ierr := chainreg.NewProductConfigurationFromNetwork(bc.Type)
		if ierr != nil {
			return nil, nil, ierr
		}
		impls[i] = impl
		blockchainOutputs[i] = bc.Out
	}

	// Generate HMAC credentials for all aggregators before launching CL nodes,
	// so the nodes can receive credentials via secrets.
	for _, agg := range in.Aggregator {
		creds, cerr := agg.EnsureClientCredentials()
		if cerr != nil {
			return nil, nil, fmt.Errorf("failed to ensure client credentials for aggregator %s: %w", agg.CommitteeName, cerr)
		}
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

	_, err = launchCLNodes(ctx, in, impls, in.Verifier, in.Aggregator)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to launch CL nodes: %w", err)
	}

	// Extract only CL-mode NOP aliases for JD/client operations.
	// Standalone NOPs don't have CL nodes and don't need JD registration.
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

	clientLookup, err := jobs.NewNodeSetClientLookup(in.NodeSets, clModeNopAliases)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create NodeSet client lookup: %w", err)
	}

	if in.JDInfra == nil {
		return nil, nil, fmt.Errorf("JD infrastructure was not started by Phase 1 jd component")
	}
	jdInfra := in.JDInfra

	if clientLookup != nil {
		if err := jobs.RegisterNodesWithJD(ctx, jdInfra, clientLookup, clModeNopAliases); err != nil {
			return nil, nil, fmt.Errorf("failed to register nodes with JD: %w", err)
		}
		chainIDs := make([]string, len(in.Blockchains))
		for i, bc := range in.Blockchains {
			chainIDs[i] = bc.ChainID
		}
		if err := jobs.ConnectNodesToJD(ctx, jdInfra, clientLookup, chainIDs); err != nil {
			return nil, nil, fmt.Errorf("failed to connect nodes to JD: %w", err)
		}
	}

	_, err = launchStandaloneVerifiers(in, blockchainOutputs, jdInfra)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to launch standalone verifiers: %w", err)
	}
	if err := registerStandaloneVerifiersWithJD(ctx, in.Verifier, jdInfra.OffchainClient); err != nil {
		return nil, nil, err
	}

	// Generate shared TLS certificates from aggregator hostnames. This depends
	// only on container naming — not on deployed contract addresses — so it
	// belongs here alongside other credential infrastructure.
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
		sharedTLSCerts, err = services.GenerateTLSCertificates(allHostnames, tlsCertDir)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate shared TLS certificates: %w", err)
		}
	}

	return map[string]any{
		"verifiers":                  in.Verifier,
		"_aggregators_with_creds":    in.Aggregator,
		"_cl_client_lookup":          clientLookup,
		"shared_tls_certs":           sharedTLSCerts,
		"_cfg":                       in,
		"_cldf":                      &in.CLDF,
		"_environment_topology":      in.EnvironmentTopology,
		"_use_legacy_configure_lane": in.ProtocolContracts.UseLegacyConfigureLane,
		"_indexer_inputs":            in.Indexer,
	}, nil, nil
}

// RunPhase4 assembles a PhasedSetup from the individual keys published by
// legacy RunPhase2 and protocol_contracts RunPhase3, launches generic services,
// and calls runPhasedEnvironmentFinish to complete wiring.
func (l *legacyComponent) RunPhase4(
	ctx context.Context,
	_ map[string]any,
	_ any,
	priorOutputs map[string]any,
) (map[string]any, []devenvruntime.Effect, error) {
	in, ok := priorOutputs["_cfg"].(*Cfg)
	if !ok {
		return nil, nil, fmt.Errorf("phase 2 did not produce *Cfg under \"_cfg\"")
	}
	e, ok := priorOutputs["_env"].(*deployment.Environment)
	if !ok {
		return nil, nil, fmt.Errorf("phase 3 did not produce *deployment.Environment under \"_env\"")
	}
	topology, ok := priorOutputs["_topology"].(*ccvdeployment.EnvironmentTopology)
	if !ok {
		return nil, nil, fmt.Errorf("phase 3 did not produce *EnvironmentTopology under \"_topology\"")
	}
	sharedTLSCerts, _ := priorOutputs["shared_tls_certs"].(*services.TLSCertPaths)
	blockchainOutputs, _ := priorOutputs["_blockchain_outputs"].([]*blockchain.Output)
	selectors, _ := priorOutputs["_selectors"].([]uint64)
	ds, _ := priorOutputs["_ds"].(datastore.MutableDataStore)
	fakeOut, _ := priorOutputs["_fake_out"].(*services.FakeOutput)
	timeTrack, _ := priorOutputs["_time_track"].(*TimeTracker)

	// The executor Phase 3 component launched containers and registered with JD
	// (setting exec.Out and exec.Out.JDNodeID). Replace the Phase 2 slice
	// with those processed inputs so runPhasedEnvironmentFinish can
	// propose job specs to the correct JD node IDs.
	if execs, ok := priorOutputs["executor"].([]*executorsvc.Input); ok {
		in.Executor = execs
	}

	// Restore the CL client lookup from Phase 2 into the in-memory Cfg so that
	// launchGenericServices and runPhasedEnvironmentFinish can reference CL nodes.
	if clientLookup, ok := priorOutputs["_cl_client_lookup"].(*jobs.NodeSetClientLookup); ok {
		in.ClientLookup = clientLookup
	}

	if err := launchGenericServices(ctx, in, e, blockchainOutputs); err != nil {
		return nil, nil, fmt.Errorf("failed to launch generic services: %w", err)
	}

	cfg, phaseEffects, err := runPhasedEnvironmentFinish(ctx, in, e, topology, sharedTLSCerts, blockchainOutputs, selectors, ds, fakeOut, timeTrack)
	if err != nil {
		return nil, nil, err
	}
	return map[string]any{legacyCfgKey: cfg}, phaseEffects, nil
}
