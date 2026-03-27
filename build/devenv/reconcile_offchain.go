package ccv

import (
	"context"
	"fmt"

	"google.golang.org/grpc/credentials/insecure"

	ccipAdapters "github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/adapters"
	ccipChangesets "github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/changesets"
	ccipOffchain "github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/offchain"
	"github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/offchain/shared"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/jobs"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/offchainloader"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/offchain"
	cldfjd "github.com/smartcontractkit/chainlink-deployments-framework/offchain/jd"
	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

// ConfigureOffchainOptions controls off-chain configuration after an environment change (on-chain or topology).
//
// By default (RestartTomlConsumers nil), after TOML is regenerated this function updates aggregator
// generated TOML in running containers, writes fresh standalone config files to disk, then restarts
// only TOML-bound Docker services: aggregators,
// indexers, standalone executors, and standalone verifiers.
// Set RestartTomlConsumers to a non-nil false when Docker is unavailable or to avoid restarting consumers
// (e.g. out-of-band reload or diagnostics).
type ConfigureOffchainOptions struct {
	FundExecutors bool

	// RestartTomlConsumers when nil means true: docker restart TOML-bound service containers after a successful reconcile.
	RestartTomlConsumers *bool
}

func (o ConfigureOffchainOptions) effectiveRestartTomlConsumers() bool {
	if o.RestartTomlConsumers == nil {
		return true
	}
	return *o.RestartTomlConsumers
}

// ConfigureTopologyLanesAndOffchain applies on-chain lane changes from topology and params, then runs off-chain
// regeneration (aggregator, indexer, executor, verifier) and restarts TOML-bound Docker services by default.
func ConfigureTopologyLanesAndOffchain(
	ctx context.Context,
	e *deployment.Environment,
	in *Cfg,
	topology *ccipOffchain.EnvironmentTopology,
	selectors []uint64,
	blockchains []*blockchain.Input,
	impls []cciptestinterfaces.CCIP17Configuration,
	laneParams ReconfigureLanesParams,
	sharedTLSCerts *services.TLSCertPaths,
	offchainOpts ConfigureOffchainOptions,
) error {
	if err := reconfigureLanesFromTopology(ctx, e, topology, selectors, blockchains, impls, laneParams); err != nil {
		return fmt.Errorf("configure topology lanes and offchain: on-chain: %w", err)
	}
	if err := configureOffchainAfterOnChainChange(ctx, e, in, impls, topology, sharedTLSCerts, offchainOpts); err != nil {
		return fmt.Errorf("configure topology lanes and offchain: off-chain: %w", err)
	}
	return nil
}

// configureOffchainAfterOnChainChange re-runs GenerateAggregatorConfig, GenerateIndexerConfig,
// executor and verifier job-spec changesets, merges outputs into e.DataStore, and by default restarts TOML-bound Docker services.
func configureOffchainAfterOnChainChange(
	ctx context.Context,
	e *deployment.Environment,
	in *Cfg,
	impls []cciptestinterfaces.CCIP17Configuration,
	topology *ccipOffchain.EnvironmentTopology,
	sharedTLSCerts *services.TLSCertPaths,
	opts ConfigureOffchainOptions,
) error {
	if e == nil || in == nil || topology == nil {
		return fmt.Errorf("reconcile: environment, config, and topology are required")
	}
	mds := datastore.NewMemoryDataStore()
	if err := mds.Merge(e.DataStore); err != nil {
		return fmt.Errorf("reconcile: merge initial datastore: %w", err)
	}
	if _, err := configureOffchainFromTopology(e, in, topology, sharedTLSCerts, mds); err != nil {
		return fmt.Errorf("reconcile: configure offchain: %w", err)
	}
	if opts.FundExecutors {
		if err := fundStandaloneExecutorAddresses(ctx, in, impls); err != nil {
			return fmt.Errorf("reconcile: fund standalone executors: %w", err)
		}
	}
	if err := acceptPendingJobsAndSync(ctx, e, in); err != nil {
		return fmt.Errorf("reconcile: accept pending jobs: %w", err)
	}

	if opts.effectiveRestartTomlConsumers() {
		if err := configureTomlBoundServiceFiles(ctx, in); err != nil {
			return fmt.Errorf("reconcile: configure TOML-bound services: %w", err)
		}
		if err := restartTomlBoundServices(ctx, in); err != nil {
			return fmt.Errorf("reconcile: restart toml-bound services: %w", err)
		}
	}
	return nil
}

type restartable interface {
	Restart(context.Context) error
}

type refreshable interface {
	RefreshConfig(context.Context) error
}

func restartTomlBoundServices(ctx context.Context, in *Cfg) error {
	if in == nil {
		return nil
	}
	restartables := make([]restartable, 0, len(in.Aggregator)+len(in.Indexer)+len(in.Executor)+len(in.Verifier))
	for _, service := range in.Aggregator {
		if service != nil {
			restartables = append(restartables, service)
		}
	}
	for _, service := range in.Indexer {
		if service != nil {
			restartables = append(restartables, service)
		}
	}
	for _, service := range in.Executor {
		if service != nil {
			restartables = append(restartables, service)
		}
	}
	for _, service := range in.Verifier {
		if service != nil {
			restartables = append(restartables, service)
		}
	}
	for _, service := range restartables {
		if err := service.Restart(ctx); err != nil {
			return err
		}
	}
	return nil
}

// OpenDeploymentEnvironmentFromCfg builds selectors and a CLDF operations environment from a loaded env-out Cfg.
func OpenDeploymentEnvironmentFromCfg(cfg *Cfg) ([]uint64, *deployment.Environment, error) {
	if cfg == nil {
		return nil, nil, fmt.Errorf("open deployment environment: cfg is nil")
	}
	var (
		offchainClient offchain.Client
		nodeIDs        []string
	)
	jdClient, err := jdClientFromCfg(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("open deployment environment: %w", err)
	}
	if jdClient != nil {
		offchainClient = jdClient
		nodeIDs, err = jdNodeIDs(jdClient)
		if err != nil {
			return nil, nil, fmt.Errorf("open deployment environment: list JD nodes: %w", err)
		}
	}
	if cfg.ClientLookup == nil {
		clAliases := clModeNOPAliases(cfg.EnvironmentTopology)
		if len(clAliases) > 0 {
			clientLookup, err := jobs.NewNodeSetClientLookup(cfg.NodeSets, clAliases)
			if err != nil {
				return nil, nil, fmt.Errorf("open deployment environment: build CL client lookup: %w", err)
			}
			cfg.ClientLookup = clientLookup
		}
	}
	return NewCLDFOperationsEnvironmentWithOffchain(CLDFEnvironmentConfig{
		Blockchains:    cfg.Blockchains,
		DataStore:      cfg.CLDF.DataStore,
		OffchainClient: offchainClient,
		NodeIDs:        nodeIDs,
	})
}

// ImplConfigurationsFromCfg returns one CCIP17Configuration per blockchain (same order as connectAllChains / NewEnvironment).
func ImplConfigurationsFromCfg(in *Cfg) ([]cciptestinterfaces.CCIP17Configuration, error) {
	if in == nil {
		return nil, fmt.Errorf("impl configurations: cfg is nil")
	}
	impls := make([]cciptestinterfaces.CCIP17Configuration, 0, len(in.Blockchains))
	for _, bc := range in.Blockchains {
		impl, err := NewProductConfigurationFromNetwork(bc.Type)
		if err != nil {
			return nil, err
		}
		impls = append(impls, impl)
	}
	return impls, nil
}

func configureOffchainFromTopology(
	e *deployment.Environment,
	in *Cfg,
	topology *ccipOffchain.EnvironmentTopology,
	sharedTLSCerts *services.TLSCertPaths,
	ds datastore.MutableDataStore,
) (map[string][]string, error) {
	if e == nil || in == nil || topology == nil {
		return nil, fmt.Errorf("environment, config, and topology are required")
	}
	if ds == nil {
		ds = datastore.NewMemoryDataStore()
		if err := ds.Merge(e.DataStore); err != nil {
			return nil, fmt.Errorf("merge initial datastore: %w", err)
		}
	}

	ResetMemoryOperationsBundle(e)

	for _, aggregatorInput := range in.Aggregator {
		if sharedTLSCerts != nil {
			aggregatorInput.SharedTLSCerts = sharedTLSCerts
		}
		e.DataStore = ds.Seal()
		instanceName := aggregatorInput.InstanceName()
		output, err := ccipChangesets.GenerateAggregatorConfig(ccipAdapters.GetAggregatorConfigRegistry()).Apply(*e, ccipChangesets.GenerateAggregatorConfigInput{
			ServiceIdentifier:  instanceName + "-aggregator",
			CommitteeQualifier: aggregatorInput.CommitteeName,
			Topology:           topology,
		})
		if err != nil {
			return nil, fmt.Errorf("generate aggregator config %s: %w", instanceName, err)
		}
		aggCfg, err := offchainloader.GetAggregatorConfig(output.DataStore.Seal(), instanceName+"-aggregator")
		if err != nil {
			return nil, fmt.Errorf("get aggregator config %s: %w", instanceName, err)
		}
		aggregatorInput.GeneratedCommittee = aggCfg
		if err := ds.Merge(output.DataStore.Seal()); err != nil {
			return nil, fmt.Errorf("merge aggregator datastore: %w", err)
		}
	}

	if len(in.Aggregator) > 0 && len(in.Indexer) > 0 {
		e.DataStore = ds.Seal()
		firstIdx := in.Indexer[0]
		output, err := ccipChangesets.GenerateIndexerConfig(ccipAdapters.GetIndexerConfigRegistry()).Apply(*e, ccipChangesets.GenerateIndexerConfigInput{
			ServiceIdentifier:                "indexer",
			CommitteeVerifierNameToQualifier: firstIdx.CommitteeVerifierNameToQualifier,
			CCTPVerifierNameToQualifier:      firstIdx.CCTPVerifierNameToQualifier,
			LombardVerifierNameToQualifier:   firstIdx.LombardVerifierNameToQualifier,
		})
		if err != nil {
			return nil, fmt.Errorf("generate indexer config: %w", err)
		}
		idxCfg, err := offchainloader.GetIndexerConfig(output.DataStore.Seal(), "indexer")
		if err != nil {
			return nil, fmt.Errorf("get indexer config: %w", err)
		}
		for _, idxIn := range in.Indexer {
			idxIn.GeneratedCfg = idxCfg
		}
		if err := ds.Merge(output.DataStore.Seal()); err != nil {
			return nil, fmt.Errorf("merge indexer datastore: %w", err)
		}
	}

	e.DataStore = ds.Seal()
	if err := generateExecutorJobSpecs(e, in, topology, ds); err != nil {
		return nil, fmt.Errorf("executor job specs: %w", err)
	}
	e.DataStore = ds.Seal()

	verifierJobSpecs, err := generateVerifierJobSpecs(e, in, topology, sharedTLSCerts, ds)
	if err != nil {
		return nil, fmt.Errorf("verifier job specs: %w", err)
	}
	e.DataStore = ds.Seal()
	in.CLDF.DataStore = e.DataStore

	return verifierJobSpecs, nil
}

func configureTomlBoundServiceFiles(ctx context.Context, in *Cfg) error {
	if in == nil {
		return nil
	}
	refreshables := make([]refreshable, 0, len(in.Aggregator)+len(in.Indexer))
	for _, service := range in.Aggregator {
		if service != nil {
			refreshables = append(refreshables, service)
		}
	}
	for _, service := range in.Indexer {
		if service != nil {
			refreshables = append(refreshables, service)
		}
	}
	for _, service := range refreshables {
		if err := service.RefreshConfig(ctx); err != nil {
			return fmt.Errorf("refresh TOML-bound service config: %w", err)
		}
	}
	return nil
}

func acceptPendingJobsAndSync(ctx context.Context, e *deployment.Environment, in *Cfg) error {
	if err := jobs.AcceptPendingJobs(ctx, in.ClientLookup); err != nil {
		return err
	}
	return nil
}

func clModeNOPAliases(topology *ccipOffchain.EnvironmentTopology) []string {
	if topology == nil || topology.NOPTopology == nil {
		return nil
	}
	aliases := make([]string, 0, len(topology.NOPTopology.NOPs))
	for _, nop := range topology.NOPTopology.NOPs {
		if nop.GetMode() == shared.NOPModeCL {
			alias := nop.Alias
			if alias == "" {
				alias = nop.Name
			}
			aliases = append(aliases, alias)
		}
	}
	return aliases
}

func jdClientFromCfg(cfg *Cfg) (offchain.Client, error) {
	if cfg == nil || cfg.JD == nil || cfg.JD.Out == nil {
		return nil, nil
	}
	client, err := cldfjd.NewJDClient(cldfjd.JDConfig{
		GRPC:  cfg.JD.Out.ExternalGRPCUrl,
		WSRPC: cfg.JD.Out.ExternalWSRPCUrl,
		Creds: insecure.NewCredentials(),
	})
	if err != nil {
		return nil, fmt.Errorf("create JD client from env-out: %w", err)
	}
	return client, nil
}

func jdNodeIDs(client offchain.Client) ([]string, error) {
	if client == nil {
		return nil, nil
	}
	resp, err := client.ListNodes(context.Background(), &nodev1.ListNodesRequest{})
	if err != nil {
		return nil, err
	}
	nodeIDs := make([]string, 0, len(resp.Nodes))
	for _, node := range resp.Nodes {
		if node != nil && node.Id != "" {
			nodeIDs = append(nodeIDs, node.Id)
		}
	}
	return nodeIDs, nil
}
