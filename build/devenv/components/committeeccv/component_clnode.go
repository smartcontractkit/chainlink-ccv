// Package committeeccv contains two registered Phase 3 components:
//   - "committeeccv"       (component.go)  — standalone verifier/aggregator setup
//   - "committeeccv_clnode" (this file)    — CL-node variant; replaces committeeccv when
//     Chainlink nodes host the verifier jobs. Absorbs the former clnode Phase-1
//     config-vehicle component. Delete this file (and its [committeeccv_clnode]
//     config section) when CL nodes leave the devenv.
package committeeccv

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/pelletier/go-toml/v2"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/jobs"
	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/committeeverifier"
	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	ccvshared "github.com/smartcontractkit/chainlink-ccv/deployment/shared"
	ctfblockchain "github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
	ns "github.com/smartcontractkit/chainlink-testing-framework/framework/components/simple_node_set"
)

const (
	CLNodeKey     = "committeeccv_clnode"
	clNodeVersion = 1
)

func init() {
	if err := devenvruntime.Register(CLNodeKey, clnodeFactory); err != nil {
		panic(fmt.Sprintf("committeeccv_clnode component: %v", err))
	}
}

func clnodeFactory(_ map[string]any) (devenvruntime.Component, error) {
	return &clnodeComponent{}, nil
}

type clnodeComponent struct {
	mu     sync.Mutex
	status string
}

func (c *clnodeComponent) setStatus(s string) {
	c.mu.Lock()
	c.status = s
	c.mu.Unlock()
}

// Status implements the devenvruntime.Statuser optional interface so the TUI
// reporter can poll for fine-grained progress during the long Phase 3 setup.
func (c *clnodeComponent) Status() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

func (c *clnodeComponent) ValidateConfig(componentConfig any) error {
	_, err := decodeCLNodeConfig(componentConfig)
	return err
}

// RunPhase3 runs the full CommitteeCCV setup (same steps as the standalone
// component) and additionally launches and registers Chainlink node sets.
// The CL-node launch (step 1b) must happen after HMAC credentials are
// generated (step 1) and before verifier registration (step 2), because:
//   - bakeNodeSecrets writes HMAC creds into node specs before boot
//   - ApplyVerifierConfig fetches CL-mode signing keys from JD by node ID
func (c *clnodeComponent) RunPhase3(
	ctx context.Context,
	globalConfig map[string]any,
	componentConfig any,
	priorOutputs map[string]any,
) (map[string]any, []devenvruntime.Effect, error) {
	cfg, err := decodeCLNodeConfig(componentConfig)
	if err != nil {
		return nil, nil, err
	}
	aggregators, verifiers := cfg.Aggregator, cfg.Verifier
	if len(aggregators) == 0 && len(verifiers) == 0 && len(cfg.NodeSets) == 0 {
		return map[string]any{}, nil, nil
	}
	inputs, err := parsePhase3Inputs(priorOutputs, globalConfig)
	if err != nil {
		return nil, nil, err
	}
	// Work on a local copy of the shared Phase-2 environment.
	localEnv := *inputs.env

	// Step 1: Generate HMAC credentials (must precede bakeNodeSecrets).
	c.setStatus("ensuring aggregator credentials")
	if err := ensureAggregatorCredentials(aggregators); err != nil {
		return nil, nil, err
	}

	// Step 1b: Bake secrets into node specs, then launch and register CL nodes.
	// Must run before step 2 (verifier launch) so JD has the node IDs needed
	// by ApplyVerifierConfig when fetching CL-mode signing keys.
	c.setStatus("launching CL nodes")
	clNodeClients, nodeIDs, err := launchCLNodes(ctx, &cfg, verifiers, aggregators, inputs.topology, inputs.blockchains, inputs.jdInfra)
	if err != nil {
		return nil, nil, fmt.Errorf("committeeccv_clnode: %w", err)
	}
	if len(nodeIDs) > 0 {
		localEnv.NodeIDs = nodeIDs
	}

	outputs, effects, err := runPhase3Core(ctx, inputs, aggregators, verifiers, &localEnv, c.setStatus)
	if err != nil {
		return nil, nil, err
	}
	outputs["_clnode_clients"] = clNodeClients
	return outputs, effects, nil
}

// CLNodeConfig is the [committeeccv_clnode] config section. It embeds the
// committee fields (aggregators, verifiers) and the CL-node fields (node sets,
// funding amounts) so the section is self-contained and can be deleted wholesale
// when CL nodes leave the devenv.
type CLNodeConfig struct {
	Version            int                         `toml:"version"`
	CLNodesFundingETH  float64                     `toml:"cl_nodes_funding_eth"`
	CLNodesFundingLink float64                     `toml:"cl_nodes_funding_link"`
	NodeSets           []*ns.Input                 `toml:"node_sets"`
	Aggregator         []*services.AggregatorInput `toml:"aggregator"`
	Verifier           []*committeeverifier.Input  `toml:"verifier"`
}

func decodeCLNodeConfig(raw any) (CLNodeConfig, error) {
	cfg, err := devenvruntime.DecodeConfig[CLNodeConfig](raw, CLNodeKey)
	if err != nil {
		return CLNodeConfig{}, err
	}
	if err := devenvruntime.CheckConfigVersion(cfg.Version, clNodeVersion); err != nil {
		return CLNodeConfig{}, err
	}
	return cfg, nil
}

// launchCLNodes bakes secrets into node specs, launches the CL node sets, then
// registers and connects each node to JD. Returns a NodeSetClientLookup and the
// JD node IDs for the launched nodes; both are nil/empty when no node sets are
// configured.
func launchCLNodes(
	ctx context.Context,
	cfg *CLNodeConfig,
	verifiers []*committeeverifier.Input,
	aggregators []*services.AggregatorInput,
	topology *ccvdeployment.EnvironmentTopology,
	blockchains []*ctfblockchain.Input,
	jdInfra *jobs.JDInfrastructure,
) (*jobs.NodeSetClientLookup, []string, error) {
	if cfg == nil || len(cfg.NodeSets) == 0 {
		return nil, nil, nil
	}
	if err := bakeNodeSecrets(cfg, verifiers, aggregators, topology); err != nil {
		return nil, nil, fmt.Errorf("baking node secrets: %w", err)
	}
	if err := launchNodeSets(ctx, cfg, blockchains); err != nil {
		return nil, nil, fmt.Errorf("launching CL node sets: %w", err)
	}
	clNopAliases := clModeNOPAliases(topology)
	if len(clNopAliases) == 0 {
		return nil, nil, nil
	}
	clientLookup, err := jobs.NewNodeSetClientLookup(cfg.NodeSets, clNopAliases)
	if err != nil {
		return nil, nil, fmt.Errorf("building CL node client lookup: %w", err)
	}
	if clientLookup == nil {
		return nil, nil, nil
	}
	if err := jobs.RegisterNodesWithJD(ctx, jdInfra, clientLookup, clNopAliases); err != nil {
		return nil, nil, fmt.Errorf("registering CL nodes with JD: %w", err)
	}
	chainIDs := make([]string, len(blockchains))
	for i, bc := range blockchains {
		chainIDs[i] = bc.ChainID
	}
	if err := jobs.ConnectNodesToJD(ctx, jdInfra, clientLookup, chainIDs); err != nil {
		return nil, nil, fmt.Errorf("connecting CL nodes to JD: %w", err)
	}
	// The deployment environment was built in Phase 2 (protocol_contracts) before
	// these CL nodes registered, so its NodeIDs are empty. Return the JD node IDs
	// so the caller can populate its local env copy (FetchNOPSigningKeys needs them).
	return clientLookup, jdInfra.GetNodeIDs(), nil
}

// bakeNodeSecrets sets TestSecretsOverrides on each CL node spec before launch.
// Must be called after HMAC credentials are generated (step 1) and before
// launchNodeSets, because CL node secrets are boot-only.
func bakeNodeSecrets(
	cfg *CLNodeConfig,
	verifiers []*committeeverifier.Input,
	aggregators []*services.AggregatorInput,
	topology *ccvdeployment.EnvironmentTopology,
) error {
	// Build topology aggregator names per committee (matches changeset ordering).
	topoAggNames := make(map[string][]string)
	if topology.NOPTopology != nil {
		for name, committee := range topology.NOPTopology.Committees {
			names := make([]string, len(committee.Aggregators))
			for i, a := range committee.Aggregators {
				names[i] = a.Name
			}
			topoAggNames[name] = names
		}
	}

	aggsByCommittee := make(map[string][]*services.AggregatorInput)
	for _, agg := range aggregators {
		if agg != nil {
			aggsByCommittee[agg.CommitteeName] = append(aggsByCommittee[agg.CommitteeName], agg)
		}
	}

	// Flatten node specs in node-set order; order must match NOP index ordering.
	type nodeSpecEntry struct {
		nodeSetIdx int
		specIdx    int
	}
	var nodeSpecOrder []nodeSpecEntry
	for i, nodeSet := range cfg.NodeSets {
		for j := range nodeSet.NodeSpecs {
			nodeSpecOrder = append(nodeSpecOrder, nodeSpecEntry{i, j})
		}
	}

	aggSecretsPerNode := make(map[int][]clNodeAggregatorSecret)
	for _, ver := range verifiers {
		if ver == nil || ver.Mode != services.CL {
			continue
		}
		index, ok := topology.NOPTopology.GetNOPIndex(ver.NOPAlias)
		if !ok {
			return fmt.Errorf("NOP alias %q not found in topology for verifier %s", ver.NOPAlias, ver.ContainerName)
		}
		if index >= len(nodeSpecOrder) {
			return fmt.Errorf("node index %d for NOPAlias %s exceeds available CL nodes (%d)",
				index, ver.NOPAlias, len(nodeSpecOrder))
		}
		committeeAggs := aggsByCommittee[ver.CommitteeName]
		if len(committeeAggs) == 0 {
			return fmt.Errorf("no aggregators found for committee %q (verifier %s)", ver.CommitteeName, ver.ContainerName)
		}
		committeeTopoNames := topoAggNames[ver.CommitteeName]

		for aggIdx, agg := range committeeAggs {
			aggName := agg.InstanceName()
			if aggIdx < len(committeeTopoNames) {
				aggName = committeeTopoNames[aggIdx]
			}
			apiKeys, err := agg.GetAPIKeys()
			if err != nil {
				return fmt.Errorf("getting API keys for aggregator %s: %w", agg.InstanceName(), err)
			}
			var found bool
			for _, apiClient := range apiKeys {
				if apiClient.ClientID != ver.ContainerName {
					continue
				}
				if len(apiClient.APIKeyPairs) == 0 {
					return fmt.Errorf("no API key pairs for client %s on aggregator %s",
						apiClient.ClientID, agg.InstanceName())
				}
				pair := apiClient.APIKeyPairs[0]
				verifierID := ccvshared.NewVerifierJobID(
					ccvshared.NOPAlias(ver.NOPAlias),
					aggName,
					ccvshared.VerifierJobScope{CommitteeQualifier: ver.CommitteeName},
				).GetVerifierID()
				aggSecretsPerNode[index] = append(aggSecretsPerNode[index], clNodeAggregatorSecret{
					VerifierID: verifierID,
					APIKey:     pair.APIKey,
					APISecret:  pair.Secret,
				})
				found = true
				break
			}
			if !found {
				return fmt.Errorf("API client %q not found on aggregator %s",
					ver.ContainerName, agg.InstanceName())
			}
		}
	}

	for flatIdx, entry := range nodeSpecOrder {
		if len(aggSecretsPerNode[flatIdx]) == 0 {
			continue
		}
		nodeSpec := cfg.NodeSets[entry.nodeSetIdx].NodeSpecs[entry.specIdx]
		secrets := clNodeSecrets{
			CCV: clNodeCCVSecrets{
				AggregatorSecrets: aggSecretsPerNode[flatIdx],
			},
		}
		secretsToml, err := secrets.tomlString()
		if err != nil {
			return fmt.Errorf("marshaling secrets for node %d: %w", flatIdx, err)
		}
		nodeSpec.Node.TestSecretsOverrides = secretsToml
	}
	return nil
}

// clModeNOPAliases returns, in topology order, the aliases of NOPs running in
// CL mode. The order matches the CL node ordering used by NewNodeSetClientLookup.
func clModeNOPAliases(topology *ccvdeployment.EnvironmentTopology) []string {
	if topology == nil || topology.NOPTopology == nil {
		return nil
	}
	var aliases []string
	for _, nop := range topology.NOPTopology.NOPs {
		if nop.GetMode() == ccvshared.NOPModeCL {
			aliases = append(aliases, nop.Alias)
		}
	}
	return aliases
}

// launchNodeSets configures, launches, and funds the CL node sets in cfg.
// TestSecretsOverrides must already be set on each node spec before this is
// called (bakeNodeSecrets handles that), because CL node secrets are boot-only.
func launchNodeSets(ctx context.Context, cfg *CLNodeConfig, blockchains []*ctfblockchain.Input) error {
	if cfg == nil || len(cfg.NodeSets) == 0 {
		return nil
	}
	if len(blockchains) == 0 {
		return fmt.Errorf("committeeccv_clnode: no blockchains available to configure CL nodes")
	}

	impls := make([]cciptestinterfaces.CCIP17Configuration, 0, len(blockchains))
	for _, bc := range blockchains {
		impl, ierr := chainreg.NewProductConfigurationFromNetwork(bc.Type)
		if ierr != nil {
			return fmt.Errorf("committeeccv_clnode: impl for %q: %w", bc.Type, ierr)
		}
		impls = append(impls, impl)
	}

	chainConfigs := []string{commonCLNodesConfig}
	for i, impl := range impls {
		cc, cerr := impl.ConfigureNodes(ctx, blockchains[i])
		if cerr != nil {
			return fmt.Errorf("committeeccv_clnode: ConfigureNodes for %q: %w", blockchains[i].Type, cerr)
		}
		chainConfigs = append(chainConfigs, cc)
	}
	allConfigs := strings.Join(chainConfigs, "\n")
	for _, nodeSet := range cfg.NodeSets {
		for _, nodeSpec := range nodeSet.NodeSpecs {
			nodeSpec.Node.TestConfigOverrides = allConfigs
		}
	}

	for _, nodeSet := range cfg.NodeSets {
		if _, nerr := ns.NewSharedDBNodeSet(nodeSet, nil); nerr != nil {
			return fmt.Errorf("committeeccv_clnode: NewSharedDBNodeSet %q: %w", nodeSet.Name, nerr)
		}
	}

	link := toBigUnits(cfg.CLNodesFundingLink, 1)
	native := toBigUnits(cfg.CLNodesFundingETH, 5)
	for i, impl := range impls {
		if ferr := impl.FundNodes(ctx, cfg.NodeSets, blockchains[i], link, native); ferr != nil {
			return fmt.Errorf("committeeccv_clnode: FundNodes on %q: %w", blockchains[i].Type, ferr)
		}
	}
	return nil
}

func toBigUnits(v float64, def int64) *big.Int {
	if v <= 0 {
		return big.NewInt(def)
	}
	return big.NewInt(int64(v))
}

// commonCLNodesConfig is the base TOML applied to every CL node. It mirrors
// ccv.CommonCLNodesConfig; components cannot import the ccv package (it
// blank-imports every component, which would create a cycle).
const commonCLNodesConfig = `
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

// clNodeSecrets, clNodeCCVSecrets, and clNodeAggregatorSecret are the TOML
// types written to TestSecretsOverrides on each CL node spec. They mirror the
// identically-named types in the ccv package (environment.go); duplicated here
// to avoid the import cycle described above.
type clNodeSecrets struct {
	CCV clNodeCCVSecrets `toml:",omitempty"`
}

func (s *clNodeSecrets) tomlString() (string, error) {
	data, err := toml.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("failed to marshal CCV secrets to TOML: %w", err)
	}
	return string(data), nil
}

type clNodeCCVSecrets struct {
	AggregatorSecrets []clNodeAggregatorSecret `toml:",omitempty"`
}

type clNodeAggregatorSecret struct {
	VerifierID string `toml:",omitempty"`
	APIKey     string `toml:",omitempty"`
	APISecret  string `toml:",omitempty"`
}
