package committeeccv

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strconv"

	"github.com/pelletier/go-toml/v2"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	ccldf "github.com/smartcontractkit/chainlink-ccv/build/devenv/cldf"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	blockchainscomp "github.com/smartcontractkit/chainlink-ccv/build/devenv/components/blockchains"
	jdcomp "github.com/smartcontractkit/chainlink-ccv/build/devenv/components/jd"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/components/observability"
	pccomp "github.com/smartcontractkit/chainlink-ccv/build/devenv/components/protocol_contracts"
	ccdeploy "github.com/smartcontractkit/chainlink-ccv/build/devenv/deploy"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/jobs"
	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/committeeverifier"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/util"
	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	ccvadapters "github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	ccvchangesets "github.com/smartcontractkit/chainlink-ccv/deployment/changesets"
	ccvshared "github.com/smartcontractkit/chainlink-ccv/deployment/shared"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	ctfblockchain "github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

const Key = "committeeccv"

// Version is the committeeccv component config schema version. Exactly this
// version is supported; configs declaring any other version are rejected.
const Version = 1

func init() {
	if err := devenvruntime.Register(Key, factory); err != nil {
		panic(fmt.Sprintf("committeeccv component: %v", err))
	}
}

func factory(_ map[string]any) (devenvruntime.Component, error) {
	return &component{}, nil
}

type component struct{}

func (c *component) ValidateConfig(componentConfig any) error {
	_, err := decodeConfig(componentConfig)
	return err
}

// RunPhase3 performs the full CommitteeCCV setup:
//  1. Generates HMAC client credentials for each aggregator.
//  2. Launches standalone verifier containers and registers them with JD.
//  3. Generates shared TLS certificates from aggregator container names.
//  4. Assigns TLS certificates to aggregators and enriches the topology with verifier keys.
//  5. Generates aggregator committee configuration via changeset.
//  6. Launches full aggregator containers.
//  7. Generates verifier job specs and emits JobProposalEffect for each standalone verifier.
//
// Outputs "aggregators", "verifiers", and "_shared_tls_certs" for Phase 4 (Indexer) consumption.
func (c *component) RunPhase3(
	ctx context.Context,
	globalConfig map[string]any,
	componentConfig any,
	priorOutputs map[string]any,
) (map[string]any, []devenvruntime.Effect, error) {
	cfg, err := decodeConfig(componentConfig)
	if err != nil {
		return nil, nil, err
	}
	aggregators, verifiers := cfg.Aggregator, cfg.Verifier
	if len(aggregators) == 0 && len(verifiers) == 0 {
		return map[string]any{}, nil, nil
	}
	inputs, err := parsePhase3Inputs(priorOutputs, globalConfig)
	if err != nil {
		return nil, nil, err
	}
	// Work on a copy of the shared Phase-2 environment.
	localEnv := *inputs.env
	if err := ensureAggregatorCredentials(aggregators); err != nil {
		return nil, nil, err
	}
	return runPhase3Core(ctx, inputs, aggregators, verifiers, &localEnv)
}

// phase3Inputs holds the decoded prior-phase outputs consumed by both the
// standalone and CL-node CommitteeCCV components.
type phase3Inputs struct {
	jdInfra                *jobs.JDInfrastructure
	blockchains            []*ctfblockchain.Input
	blockchainOutputs      []*ctfblockchain.Output
	env                    *deployment.Environment
	topology               *ccvdeployment.EnvironmentTopology
	obs                    *observability.Observability
	ds                     datastore.MutableDataStore
	impls                  []cciptestinterfaces.CCIP17Configuration
	selectors              []uint64
	useLegacyConfigureLane bool
	// cldf is the Phase-2 CLDF accumulator, carried forward so Phase-3 deploys
	// (committee verifiers, mock receivers) can append their addresses to the
	// serialized output. Nil when the prior phase did not publish it.
	// TODO: migrate this to an address-registration effect so deployed addresses
	// are registered to the datastore deterministically instead of by mutating the
	// shared CLDF accumulator.
	cldf *ccldf.CLDF
}

func parsePhase3Inputs(priorOutputs, globalConfig map[string]any) (phase3Inputs, error) {
	jdInfra, ok := priorOutputs[jdcomp.Key].(*jobs.JDInfrastructure)
	if !ok || jdInfra == nil {
		return phase3Inputs{}, fmt.Errorf("committeeccv: jd not found in phase outputs")
	}
	blockchains, ok := priorOutputs[blockchainscomp.Key].([]*ctfblockchain.Input)
	if !ok {
		return phase3Inputs{}, fmt.Errorf("committeeccv: blockchains not found in phase outputs")
	}
	blockchainOutputs := blockchainscomp.Outputs(blockchains)
	e, ok := priorOutputs["_env"].(*deployment.Environment)
	if !ok || e == nil {
		return phase3Inputs{}, fmt.Errorf("committeeccv: _env not found in phase outputs")
	}
	topology, ok := priorOutputs["environment_topology"].(*ccvdeployment.EnvironmentTopology)
	if !ok || topology == nil {
		return phase3Inputs{}, fmt.Errorf("committeeccv: environment_topology not found in phase outputs")
	}
	obs, ok := priorOutputs[observability.Key].(*observability.Observability)
	if !ok || obs == nil {
		return phase3Inputs{}, fmt.Errorf("committeeccv: observability not found in phase outputs")
	}
	ds, ok := priorOutputs["_ds"].(datastore.MutableDataStore)
	if !ok {
		return phase3Inputs{}, fmt.Errorf("committeeccv: _ds not found in phase outputs")
	}
	impls, _ := priorOutputs["_impls"].([]cciptestinterfaces.CCIP17Configuration)
	selectors, _ := priorOutputs["_selectors"].([]uint64)
	// cldf is published by protocol_contracts (Phase 2) under the public "cldf"
	// key; absent in some test paths, in which case Phase-3 address persistence
	// is skipped.
	// TODO: migrate this to an address-registration effect so deployed addresses
	// are registered to the datastore deterministically instead of by mutating the
	// shared CLDF accumulator.
	cldf, _ := priorOutputs["cldf"].(*ccldf.CLDF)
	var useLegacy bool
	if pcMap, ok := globalConfig[pccomp.Key].(map[string]any); ok {
		useLegacy, _ = pcMap["use_legacy_configure_lane"].(bool)
	}
	return phase3Inputs{
		jdInfra:                jdInfra,
		blockchains:            blockchains,
		blockchainOutputs:      blockchainOutputs,
		env:                    e,
		topology:               topology,
		obs:                    obs,
		ds:                     ds,
		impls:                  impls,
		selectors:              selectors,
		useLegacyConfigureLane: useLegacy,
		cldf:                   cldf,
	}, nil
}

func ensureAggregatorCredentials(aggregators []*services.AggregatorInput) error {
	for _, agg := range aggregators {
		if agg == nil {
			continue
		}
		creds, cerr := agg.EnsureClientCredentials()
		if cerr != nil {
			return fmt.Errorf("committeeccv: failed to ensure client credentials for aggregator %s: %w", agg.CommitteeName, cerr)
		}
		if agg.Out == nil {
			agg.Out = &services.AggregatorOutput{}
		}
		agg.Out.ClientCredentials = creds
	}
	return nil
}

// runPhase3Core runs the shared CommitteeCCV Phase 3 steps (steps 2–8) against
// a local copy of the deployment environment. It is called by both the standalone
// and CL-node components; the CL-node component performs its own step 1b
// (node launch + NodeIDs population) before calling this function.
func runPhase3Core(
	ctx context.Context,
	inputs phase3Inputs,
	aggregators []*services.AggregatorInput,
	verifiers []*committeeverifier.Input,
	localEnv *deployment.Environment,
) (map[string]any, []devenvruntime.Effect, error) {
	// Step 1c: Deploy committee verifiers (+ resolvers) and mock receivers on chain.
	// These were previously deployed by the Phase-2 kitchen-sink changeset; the split
	// moves them here so Phase 2 deploys only protocol contracts. Must run before lane
	// configuration (Step 5b), which wires the committee verifiers into the lanes.
	if err := deployCommitteeVerifiersAndReceivers(inputs, localEnv); err != nil {
		return nil, nil, err
	}

	// Step 1d: Configure token-pool transfers now that committee verifiers exist. Moved from
	// Phase 2, where the CommitteeVerifier resolver was not yet deployed, so token pools could
	// not be wired to it. Runs before lane config (Step 5b), matching the original ordering.
	// TODO: move to a dedicated token-transfer Phase 3 component.
	if len(inputs.impls) > 0 {
		if err := ccdeploy.ConfigureAllTokenTransfers(inputs.impls, inputs.selectors, localEnv, inputs.topology); err != nil {
			return nil, nil, fmt.Errorf("committeeccv: configure all token transfers: %w", err)
		}
	}

	// Step 2: Launch standalone verifier containers (reads HMAC creds from agg.Out).
	// Route the central monitoring config into each verifier's bootstrap input so it ends up
	// in the generated bootstrap config. LaunchStandaloneVerifiers re-applies bootstrap
	// defaults internally (ApplyBootstrapDefaults preserves Monitoring), so setting it here
	// survives. Each verifier gets its own copy so a future per-service override can't alias others.
	monitoring := inputs.obs.Monitoring
	for _, ver := range verifiers {
		if ver == nil {
			continue
		}
		if ver.Bootstrap == nil {
			ver.Bootstrap = &services.BootstrapInput{}
		}
		m := monitoring
		ver.Bootstrap.Monitoring = &m
	}
	if err := committeeverifier.LaunchStandaloneVerifiers(
		verifiers, aggregators, committeeverifier.CommitteeAggregatorNames(inputs.topology),
		inputs.blockchainOutputs, inputs.jdInfra,
		chainreg.GetRegistry().GetVerifierModifiers(),
	); err != nil {
		return nil, nil, fmt.Errorf("committeeccv: failed to launch standalone verifiers: %w", err)
	}
	if err := committeeverifier.RegisterStandaloneVerifiersWithJD(ctx, verifiers, inputs.jdInfra.OffchainClient); err != nil {
		return nil, nil, fmt.Errorf("committeeccv: failed to register standalone verifiers with JD: %w", err)
	}
	for _, ver := range verifiers {
		if ver != nil && ver.Out != nil && ver.Out.JDNodeID != "" {
			inputs.jdInfra.RegisterNodeAlias(ver.NOPAlias, ver.Out.JDNodeID)
		}
	}

	jobs.SyncEnvNodeIDs(inputs.jdInfra, localEnv)

	// Step 3: Generate shared TLS certificates from aggregator container names.
	var sharedTLSCerts *services.TLSCertPaths
	if len(aggregators) > 0 {
		var allHostnames []string
		for _, agg := range aggregators {
			if agg == nil {
				continue
			}
			nginxName := fmt.Sprintf("%s-%s", agg.InstanceName(), services.AggregatorNginxContainerNameSuffix)
			aggName := fmt.Sprintf("%s-%s", agg.InstanceName(), services.AggregatorContainerNameSuffix)
			allHostnames = append(allHostnames, nginxName, aggName)
		}
		allHostnames = append(allHostnames, "localhost")
		tlsCertDir := filepath.Join(util.CCVConfigDir(), "tls-shared")
		var err error
		sharedTLSCerts, err = services.GenerateTLSCertificates(allHostnames, tlsCertDir)
		if err != nil {
			return nil, nil, fmt.Errorf("committeeccv: failed to generate shared TLS certificates: %w", err)
		}
	}

	// Step 4: Assign shared TLS certificates to each aggregator.
	for _, agg := range aggregators {
		if agg == nil {
			continue
		}
		agg.SharedTLSCerts = sharedTLSCerts
	}

	// Step 5: Enrich topology with verifier signer keys.
	if len(verifiers) > 0 {
		ccdeploy.EnrichTopologyWithVerifiers(inputs.topology, verifiers)
	}

	// Step 5b: Configure lanes. This requires verifiers to be registered in JD (done above)
	// because ApplyVerifierConfig fetches verifier signing keys from JD by node ID.
	if len(inputs.impls) > 0 && len(inputs.blockchains) > 0 {
		var connectErr error
		if inputs.useLegacyConfigureLane {
			connectErr = ccdeploy.ConnectAllChainsLegacy(inputs.impls, inputs.blockchains, inputs.selectors, localEnv, inputs.topology)
		} else {
			connectErr = ccdeploy.ConnectAllChainsCanonical(inputs.impls, inputs.blockchains, inputs.selectors, localEnv, inputs.topology)
		}
		if connectErr != nil {
			return nil, nil, fmt.Errorf("committeeccv: configure lanes: %w", connectErr)
		}
	}

	// Step 6: Generate aggregator committee configuration.
	for _, agg := range aggregators {
		if agg == nil {
			continue
		}
		instanceName := agg.InstanceName()
		committee, ok := inputs.topology.NOPTopology.Committees[agg.CommitteeName]
		if !ok {
			return nil, nil, fmt.Errorf("committeeccv: committee %q not found in topology", agg.CommitteeName)
		}
		cs := ccvchangesets.GenerateAggregatorConfig()
		output, err := cs.Apply(*localEnv, ccvchangesets.GenerateAggregatorConfigInput{
			ServiceIdentifier:  instanceName + "-aggregator",
			CommitteeQualifier: agg.CommitteeName,
			ChainSelectors:     ccvchangesets.CommitteeChainSelectorsFromTopology(committee),
		})
		if err != nil {
			return nil, nil, fmt.Errorf("committeeccv: GenerateAggregatorConfig for %q: %w", instanceName, err)
		}
		aggCfg, err := ccvdeployment.GetAggregatorConfig(output.DataStore.Seal(), instanceName+"-aggregator")
		if err != nil {
			return nil, nil, fmt.Errorf("committeeccv: get aggregator config for %q: %w", instanceName, err)
		}
		agg.GeneratedCommittee = aggCfg
		localEnv.DataStore = output.DataStore.Seal()
	}

	// Step 7: Launch full aggregator containers.
	for _, agg := range aggregators {
		if agg == nil {
			continue
		}
		out, err := services.NewAggregator(agg)
		if err != nil {
			return nil, nil, fmt.Errorf("committeeccv: starting aggregator %q: %w", agg.CommitteeName, err)
		}
		agg.Out = out
	}

	// Step 8: Generate verifier job specs and emit job proposal effects.
	effects, err := buildVerifierJobSpecEffects(localEnv, verifiers, inputs.topology, inputs.obs, sharedTLSCerts, inputs.blockchainOutputs, inputs.ds)
	if err != nil {
		return nil, nil, err
	}

	return map[string]any{
		"aggregators":       aggregators,
		"verifiers":         verifiers,
		"_shared_tls_certs": sharedTLSCerts,
	}, effects, nil
}

// deployCommitteeVerifiersAndReceivers deploys, per chain, the committee
// verifiers (and their resolvers) via the chain-agnostic DeployCommitteeVerifier
// changeset, then deploys the mock receivers that reference those resolvers via
// the optional MockReceiverDeployer hook. Deployed addresses are merged into both
// the shared datastore (inputs.ds) and the working environment (localEnv.DataStore).
func deployCommitteeVerifiersAndReceivers(inputs phase3Inputs, localEnv *deployment.Environment) error {
	if len(inputs.impls) == 0 || len(inputs.blockchains) == 0 {
		return nil
	}

	localEnv.OperationsBundle = operations.NewBundle(
		func() context.Context { return context.Background() },
		localEnv.Logger,
		operations.NewMemoryReporter(),
	)

	// Map chain selector -> impl.
	implBySelector := make(map[uint64]cciptestinterfaces.CCIP17Configuration, len(inputs.impls))
	for i, impl := range inputs.impls {
		if i >= len(inputs.blockchains) {
			break
		}
		networkInfo, err := chainsel.GetChainDetailsByChainIDAndFamily(inputs.blockchains[i].ChainID, impl.ChainFamily())
		if err != nil {
			return fmt.Errorf("committeeccv: chain details for impl %d: %w", i, err)
		}
		implBySelector[networkInfo.ChainSelector] = impl
	}

	// Accumulate the addresses deployed in this phase so they can be appended to
	// the serialized CLDF output. Without this, committee verifiers and mock
	// receivers deploy on-chain but never reach env-out.toml (only the merged,
	// "_"-prefixed datastore carries them, which storePhasedOutput strips).
	var deployedRefs []datastore.AddressRef

	for _, sel := range inputs.selectors {
		impl, ok := implBySelector[sel]
		if !ok {
			continue
		}

		// Reuse the chain impl's deploy config solely to resolve the deployer
		// contract (e.g. CREATE2 factory) deployed during Phase 2.
		chainCfg, err := impl.GetDeployChainContractsCfg(localEnv, sel, inputs.topology)
		if err != nil {
			return fmt.Errorf("committeeccv: get deploy config for chain %d: %w", sel, err)
		}
		if chainCfg.DeployerContract == nil || *chainCfg.DeployerContract == "" {
			return fmt.Errorf("committeeccv: deployer contract not resolved for chain %d", sel)
		}

		committees, err := buildCommitteeVerifierParams(inputs.topology, sel)
		if err != nil {
			return fmt.Errorf("committeeccv: build committee verifier params for chain %d: %w", sel, err)
		}
		if len(committees) == 0 {
			continue
		}

		out, err := ccvchangesets.DeployCommitteeVerifier().Apply(*localEnv, ccvchangesets.DeployCommitteeVerifierInput{
			ChainSelectors: []uint64{sel},
			Committees:     committees,
			DefaultCfg: ccvchangesets.DeployCommitteeVerifierPerChainCfg{
				DeployerContract: *chainCfg.DeployerContract,
			},
		})
		if err != nil {
			return fmt.Errorf("committeeccv: deploy committee verifiers for chain %d: %w", sel, err)
		}
		committeeVerifierDS := out.DataStore.Seal()
		if err := mergePhase3DataStore(inputs.ds, localEnv, committeeVerifierDS); err != nil {
			return fmt.Errorf("committeeccv: merge committee verifier datastore for chain %d: %w", sel, err)
		}
		if deployedRefs, err = appendDataStoreRefs(deployedRefs, committeeVerifierDS); err != nil {
			return fmt.Errorf("committeeccv: collect committee verifier addresses for chain %d: %w", sel, err)
		}

		// TODO: move mock-receiver deployment to a dedicated receivers component.
		// Mock receivers depend on the committee-verifier resolver just deployed.
		//nolint:nestif // Reasonable complexity
		if d, ok := impl.(cciptestinterfaces.MockReceiverDeployer); ok {
			receiverDS, derr := d.DeployMockReceivers(localEnv, sel, inputs.topology)
			if derr != nil {
				return fmt.Errorf("committeeccv: deploy mock receivers for chain %d: %w", sel, derr)
			}
			if receiverDS != nil {
				if err := mergePhase3DataStore(inputs.ds, localEnv, receiverDS); err != nil {
					return fmt.Errorf("committeeccv: merge mock receiver datastore for chain %d: %w", sel, err)
				}
				if deployedRefs, err = appendDataStoreRefs(deployedRefs, receiverDS); err != nil {
					return fmt.Errorf("committeeccv: collect mock receiver addresses for chain %d: %w", sel, err)
				}
			}
		}
	}

	// Append the Phase-3 addresses to the CLDF accumulator so they are serialized
	// to env-out.toml alongside the Phase-2 protocol contracts.
	// TODO: migrate this to an address-registration effect so deployed addresses
	// are registered to the datastore deterministically instead of by mutating the
	// shared CLDF accumulator.
	if inputs.cldf != nil && len(deployedRefs) > 0 {
		encoded, err := json.Marshal(deployedRefs)
		if err != nil {
			return fmt.Errorf("committeeccv: marshal phase-3 addresses: %w", err)
		}
		inputs.cldf.AddAddresses(string(encoded))
	}

	return nil
}

// appendDataStoreRefs fetches every address ref from ds and appends them to dst.
func appendDataStoreRefs(dst []datastore.AddressRef, ds datastore.DataStore) ([]datastore.AddressRef, error) {
	refs, err := ds.Addresses().Fetch()
	if err != nil {
		return dst, err
	}
	return append(dst, refs...), nil
}

// buildCommitteeVerifierParams extracts committee verifier deploy params from the
// topology for one chain. Committees without a chain_config for the selector are
// skipped. Ported from chainlink-ccip's BuildCommitteeVerifierParams; address
// validation is deferred to the chain-family adapter.
func buildCommitteeVerifierParams(
	topology *ccvdeployment.EnvironmentTopology,
	chainSelector uint64,
) ([]ccvadapters.CommitteeVerifierDeployParams, error) {
	if topology == nil || topology.NOPTopology == nil {
		return nil, nil
	}

	chainKey := strconv.FormatUint(chainSelector, 10)

	qualifiers := make([]string, 0, len(topology.NOPTopology.Committees))
	for q := range topology.NOPTopology.Committees {
		qualifiers = append(qualifiers, q)
	}
	sort.Strings(qualifiers)

	params := make([]ccvadapters.CommitteeVerifierDeployParams, 0, len(qualifiers))
	for _, qualifier := range qualifiers {
		committee := topology.NOPTopology.Committees[qualifier]
		chainCfg, ok := committee.ChainConfigs[chainKey]
		if !ok {
			continue
		}
		if committee.VerifierVersion == nil {
			return nil, fmt.Errorf("committee %q has nil VerifierVersion", qualifier)
		}
		params = append(params, ccvadapters.CommitteeVerifierDeployParams{
			Version:          committee.VerifierVersion,
			FeeAggregator:    chainCfg.FeeAggregator,
			AllowlistAdmin:   chainCfg.AllowlistAdmin,
			StorageLocations: committee.StorageLocations,
			Qualifier:        qualifier,
		})
	}

	return params, nil
}

// mergePhase3DataStore merges newDS into the shared mutable datastore and refreshes
// localEnv.DataStore with the combined sealed state so subsequent deploys can
// resolve previously deployed contracts.
func mergePhase3DataStore(ds datastore.MutableDataStore, localEnv *deployment.Environment, newDS datastore.DataStore) error {
	if err := ds.Merge(newDS); err != nil {
		return err
	}
	merged := datastore.NewMemoryDataStore()
	if err := merged.Merge(localEnv.DataStore); err != nil {
		return err
	}
	if err := merged.Merge(newDS); err != nil {
		return err
	}
	localEnv.DataStore = merged.Seal()
	return nil
}

type verifierJobSpec struct {
	Name                    string `toml:"name"`
	ExternalJobID           string `toml:"externalJobID"`
	SchemaVersion           int    `toml:"schemaVersion"`
	Type                    string `toml:"type"`
	CommitteeVerifierConfig string `toml:"committeeVerifierConfig"`
}

func (vjs verifierJobSpec) toBootstrapJobSpec() bootstrap.JobSpec {
	return bootstrap.JobSpec{
		Name:          vjs.Name,
		ExternalJobID: vjs.ExternalJobID,
		SchemaVersion: vjs.SchemaVersion,
		Type:          vjs.Type,
		AppConfig:     vjs.CommitteeVerifierConfig,
	}
}

func validateDisableFinalityCheckers(committeeName string, verifiers []*committeeverifier.Input) (map[string][]string, error) {
	if len(verifiers) == 0 {
		return nil, nil
	}
	result := make(map[string][]string)
	for _, ver := range verifiers {
		if existing, ok := result[ver.ChainFamily]; ok {
			if !slices.Equal(existing, ver.DisableFinalityCheckers) {
				return nil, fmt.Errorf(
					"verifiers in committee %q within the same chain family %s have inconsistent disable_finality_checkers settings",
					committeeName, ver.ChainFamily,
				)
			}
		}
		result[ver.ChainFamily] = ver.DisableFinalityCheckers
	}
	return result, nil
}

func validateVerifierNodeIndices(committeeName string, verifiers []*committeeverifier.Input) error {
	seen := make(map[int]string, len(verifiers))
	for _, ver := range verifiers {
		if existing, dup := seen[ver.NodeIndex]; dup {
			return fmt.Errorf(
				"committee %q: verifiers %q and %q both have node_index=%d — "+
					"node_index must be unique within a committee",
				committeeName, existing, ver.ContainerName, ver.NodeIndex,
			)
		}
		seen[ver.NodeIndex] = ver.ContainerName
	}
	return nil
}

// buildVerifierJobSpecEffects generates verifier job specs via changeset and emits
// JobProposalEffect for each standalone verifier. It also sets GeneratedConfig,
// GeneratedJobSpecs, VerifierID, and TLSCACertFile as side effects on the verifier inputs.
func buildVerifierJobSpecEffects(
	e *deployment.Environment,
	verifiers []*committeeverifier.Input,
	topology *ccvdeployment.EnvironmentTopology,
	obs *observability.Observability,
	sharedTLSCerts *services.TLSCertPaths,
	blockchainOutputs []*ctfblockchain.Output,
	ds datastore.MutableDataStore,
) ([]devenvruntime.Effect, error) {
	if len(verifiers) == 0 {
		return nil, nil
	}

	verifiersByCommittee := make(map[string][]*committeeverifier.Input)
	for _, ver := range verifiers {
		verifiersByCommittee[ver.CommitteeName] = append(verifiersByCommittee[ver.CommitteeName], ver)
	}

	var effects []devenvruntime.Effect
	for committeeName, committeeVerifiers := range verifiersByCommittee {
		disableFinalityCheckersPerFamily, err := validateDisableFinalityCheckers(committeeName, committeeVerifiers)
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

			committee, ok := topology.NOPTopology.Committees[committeeName]
			if !ok {
				return nil, fmt.Errorf("committeeccv: committee %q not found in topology", committeeName)
			}
			cs := ccvchangesets.ApplyVerifierConfig()
			output, err := cs.Apply(*e, ccvchangesets.ApplyVerifierConfigInput{
				CommitteeQualifier:       committeeName,
				DefaultExecutorQualifier: devenvcommon.DefaultExecutorQualifier,
				NOPs:                     ccvchangesets.NOPInputsFromTopology(topology),
				Committee:                ccvchangesets.CommitteeInputFromTopologyPerFamily(committee, family),
				PyroscopeURL:             obs.PyroscopeURL,
				TargetNOPs:               verNOPAliases,
				DisableFinalityCheckers:  disableFinalityCheckersPerFamily[family],
				// Consolidated topology: one verifier job per NOP writing to every aggregator.
				ConsolidateAggregators: true,
			})
			if err != nil {
				return nil, fmt.Errorf("committeeccv: generating verifier configs for committee %s: %w", committeeName, err)
			}
			if err := ds.Merge(output.DataStore.Seal()); err != nil {
				return nil, fmt.Errorf("committeeccv: merging verifier job specs datastore: %w", err)
			}

			aggNames, err := topology.GetAggregatorNamesForCommittee(committeeName)
			if err != nil {
				return nil, err
			}
			if len(aggNames) == 0 {
				return nil, fmt.Errorf("committeeccv: committee %q has no aggregators in topology", committeeName)
			}
			if err := validateVerifierNodeIndices(committeeName, committeeVerifiers); err != nil {
				return nil, err
			}

			for _, ver := range committeeVerifiers {
				if ver.ChainFamily != family {
					continue
				}

				// Consolidated topology: a single verifier job per NOP writing to all aggregators.
				jobSpecID := ccvshared.NewConsolidatedVerifierJobID(ccvshared.NOPAlias(ver.NOPAlias), ccvshared.VerifierJobScope{CommitteeQualifier: committeeName})
				job, err := ccvdeployment.GetJob(output.DataStore.Seal(), ccvshared.NOPAlias(ver.NOPAlias), jobSpecID.ToJobID())
				if err != nil {
					return nil, fmt.Errorf("committeeccv: getting consolidated verifier job spec for %s: %w", ver.ContainerName, err)
				}
				var spec verifierJobSpec
				if err := toml.Unmarshal([]byte(job.Spec), &spec); err != nil {
					return nil, fmt.Errorf("committeeccv: decoding verifier job spec for %s: %w", ver.ContainerName, err)
				}
				bootSpec := spec.toBootstrapJobSpec()
				allJobSpecs := []bootstrap.JobSpec{bootSpec}

				ver.GeneratedJobSpecs = allJobSpecs

				var verCfg commit.Config
				if err := toml.Unmarshal([]byte(bootSpec.AppConfig), &verCfg); err != nil {
					return nil, fmt.Errorf("committeeccv: parsing verifier config from job spec: %w", err)
				}
				configBytes, err := toml.Marshal(verCfg)
				if err != nil {
					return nil, fmt.Errorf("committeeccv: marshaling verifier config: %w", err)
				}
				ver.GeneratedConfig = string(configBytes)
				if ver.Out != nil {
					ver.Out.VerifierID = verCfg.VerifierID
				}
				if sharedTLSCerts != nil && !ver.InsecureAggregatorConnection {
					ver.TLSCACertFile = sharedTLSCerts.CACertFile
				}

				if ver.Mode != services.Standalone {
					continue
				}
				if ver.Out == nil || ver.Out.JDNodeID == "" {
					return nil, fmt.Errorf("committeeccv: verifier %s not registered with JD (missing JDNodeID)", ver.NOPAlias)
				}
				reg, loaderErr := chainreg.GetRegistry().Get(ver.ChainFamily)
				if loaderErr != nil {
					return nil, fmt.Errorf("committeeccv: chain registration for verifier %s: %w", ver.NOPAlias, loaderErr)
				}
				if reg.ChainConfigLoader == nil {
					return nil, fmt.Errorf("committeeccv: chain config loader for family %s not found", ver.ChainFamily)
				}
				blockchainInfos, loaderErr := reg.ChainConfigLoader(blockchainOutputs)
				if loaderErr != nil {
					return nil, fmt.Errorf("committeeccv: loading chain config for verifier %s: %w", ver.NOPAlias, loaderErr)
				}
				baseSpec := allJobSpecs[0]
				jobSpec, specErr := committeeverifier.RebuildVerifierJobSpecWithBlockchainInfos(baseSpec, blockchainInfos)
				if specErr != nil {
					return nil, fmt.Errorf("committeeccv: building job spec for verifier %s: %w", ver.NOPAlias, specErr)
				}
				effects = append(effects, devenvruntime.JobProposalEffect{
					NOPAlias: ver.NOPAlias,
					NodeID:   ver.Out.JDNodeID,
					JobSpec:  jobSpec,
				})
			}
		}
	}

	return effects, nil
}

// Config is the [committeeccv] component config: the aggregator and standalone
// verifier inputs for the committee verification stack. It mirrors the phased
// devenv's [committeeccv] TOML section (Cfg.CommitteeCCVCfg in package ccv).
type Config struct {
	Version    int                         `toml:"version"`
	Aggregator []*services.AggregatorInput `toml:"aggregator"`
	Verifier   []*committeeverifier.Input  `toml:"verifier"`
}

func decodeConfig(raw any) (Config, error) {
	cfg, err := devenvruntime.DecodeConfig[Config](raw, Key)
	if err != nil {
		return Config{}, err
	}
	if err := devenvruntime.CheckConfigVersion(cfg.Version, Version); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
