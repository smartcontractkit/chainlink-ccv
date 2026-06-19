// Package deploy contains on-chain contract deployment and lane configuration
// logic for the devenv. It is intentionally isolated from the root ccv package
// so that components can import it without pulling in the full devenv dependency
// graph. Callers import this package directly.
package deploy

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/Masterminds/semver/v3"
	expmaps "golang.org/x/exp/maps"

	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccip/deployment/lanes"
	tokenscore "github.com/smartcontractkit/chainlink-ccip/deployment/tokens"
	changesetscore "github.com/smartcontractkit/chainlink-ccip/deployment/utils/changesets"
	devenvmcms "github.com/smartcontractkit/chainlink-ccip/deployment/utils/mcms"
	ccipAdapters "github.com/smartcontractkit/chainlink-ccip/deployment/v2_0_0/adapters"
	ccipChangesets "github.com/smartcontractkit/chainlink-ccip/deployment/v2_0_0/changesets"
	ccipOffchain "github.com/smartcontractkit/chainlink-ccip/deployment/v2_0_0/offchain"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/committeeverifier"
	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	ccvshared "github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

// convertTopologyToCCIP converts ccvdeployment.EnvironmentTopology to the
// ccipOffchain.EnvironmentTopology required by onchain changesets in chainlink-ccip
// that have not yet migrated to the ccv deployment package. Phase 2 bridge shim.
// TODO: consolidate the two EnvironmentTopology types into one, or remove the
// topology field from the upstream changesets entirely, and delete this function.
func convertTopologyToCCIP(src *ccvdeployment.EnvironmentTopology) *ccipOffchain.EnvironmentTopology {
	if src == nil {
		return nil
	}
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(src); err != nil {
		panic(fmt.Sprintf("convertTopologyToCCIP encode: %v", err))
	}
	var dst ccipOffchain.EnvironmentTopology
	if _, err := toml.Decode(buf.String(), &dst); err != nil {
		panic(fmt.Sprintf("convertTopologyToCCIP decode: %v", err))
	}
	return &dst
}

// mergeIntoSealed creates a new DataStore by merging all provided stores in
// order and returns the sealed result.
func mergeIntoSealed(stores ...datastore.DataStore) (datastore.DataStore, error) {
	tmp := datastore.NewMemoryDataStore()
	for _, s := range stores {
		if err := tmp.Merge(s); err != nil {
			return nil, err
		}
	}
	return tmp.Seal(), nil
}

// DeployContractsForSelector is the shared entry point for deploying CCIP
// contracts on a single chain. It follows the 1.6 pattern: the common code
// calls the tooling API DeployChainContracts changeset; chain impls only
// provide configuration and optional pre/post hooks.
func DeployContractsForSelector(
	ctx context.Context,
	env *deployment.Environment,
	impl cciptestinterfaces.OnChainConfigurable,
	selector uint64,
	topology *ccvdeployment.EnvironmentTopology,
) (datastore.DataStore, error) {
	runningDS := datastore.NewMemoryDataStore()

	env.OperationsBundle = operations.NewBundle(
		func() context.Context { return context.Background() },
		env.Logger,
		operations.NewMemoryReporter(),
	)

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

	// 2. Get chain-specific config (reads pre-deployed addresses from env.DataStore).
	cfg, err := impl.GetDeployChainContractsCfg(env, selector, topology)
	if err != nil {
		return nil, fmt.Errorf("get deploy config for selector %d: %w", selector, err)
	}

	// 3. Call the tooling API changeset.
	ccipTopology := convertTopologyToCCIP(topology)
	registry := ccipAdapters.GetDeployChainContractsRegistry()
	out, err := ccipChangesets.DeployChainContracts(registry, ccipAdapters.GetChainFamilyRegistry()).Apply(*env, changesetscore.WithMCMS[ccipChangesets.DeployChainContractsCfg]{
		Cfg: ccipChangesets.DeployChainContractsCfg{
			Topology:       ccipTopology,
			ChainSelectors: []uint64{selector},
			ChainOverrides: map[uint64]ccipChangesets.DeployChainContractsPerChainCfg{
				selector: cfg,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("deploy chain contracts for selector %d: %w", selector, err)
	}
	if err := runningDS.Merge(out.DataStore.Seal()); err != nil {
		return nil, fmt.Errorf("merge deploy output DS: %w", err)
	}
	merged, err := mergeIntoSealed(env.DataStore, out.DataStore.Seal())
	if err != nil {
		return nil, fmt.Errorf("update env DS with deploy output: %w", err)
	}
	env.DataStore = merged

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

	// 5. Mock receivers (committee + CCTP/Lombard) via the unified
	//    MockReceiverDeployer hook, now that the committee verifiers (step 3)
	//    and CCTP/Lombard token pools (step 4) are in env.DataStore. This
	//    mirrors the phased committeeccv path, which calls the same method.
	if d, ok := impl.(cciptestinterfaces.MockReceiverDeployer); ok { //nolint:nestif // Reasonable complexity
		receiverDS, derr := d.DeployMockReceivers(env, selector, topology)
		if derr != nil {
			return nil, fmt.Errorf("deploy mock receivers for selector %d: %w", selector, derr)
		}
		if receiverDS != nil {
			if err := runningDS.Merge(receiverDS); err != nil {
				return nil, fmt.Errorf("merge mock receiver DS: %w", err)
			}
			merged, err := mergeIntoSealed(env.DataStore, receiverDS)
			if err != nil {
				return nil, fmt.Errorf("update env DS with mock receivers: %w", err)
			}
			env.DataStore = merged
		}
	}

	return runningDS.Seal(), nil
}

// ---------------------------------------------------------------------------
// Canonical path (new): ConfigureChainsForLanesFromTopology
// ---------------------------------------------------------------------------

type chainProfile struct {
	remotes []uint64
	impl    cciptestinterfaces.CCIP17Configuration
}

// ConnectAllChainsCanonical configures lanes incrementally: each iteration adds
// one chain to the mesh, mirroring how production environments grow. The
// underlying ConfigureChainForLanes sequence is fully idempotent, so re-running
// for already-configured contracts is a no-op.
func ConnectAllChainsCanonical(
	impls []cciptestinterfaces.CCIP17Configuration,
	blockchains []*blockchain.Input,
	selectors []uint64,
	e *deployment.Environment,
	topology *ccvdeployment.EnvironmentTopology,
) error {
	if len(blockchains) != len(impls) {
		return fmt.Errorf("connectAllChains: mismatched lengths: %d impls and %d blockchains", len(impls), len(blockchains))
	}
	if len(selectors) == 0 {
		return fmt.Errorf("connectAllChains: selectors must be non-empty")
	}

	profiles := make(map[uint64]chainProfile, len(impls))
	orderedSelectors := make([]uint64, 0, len(impls))
	for i, impl := range impls {
		networkInfo, err := chainsel.GetChainDetailsByChainIDAndFamily(blockchains[i].ChainID, impl.ChainFamily())
		if err != nil {
			return fmt.Errorf("chain %d: %w", i, err)
		}
		sel := networkInfo.ChainSelector
		remotes := make([]uint64, 0, len(selectors))
		for _, s := range selectors {
			if s != sel {
				remotes = append(remotes, s)
			}
		}
		profiles[sel] = chainProfile{
			remotes: remotes,
			impl:    impl,
		}
		orderedSelectors = append(orderedSelectors, sel)
	}
	e.OperationsBundle = operations.NewBundle(
		func() context.Context { return context.Background() },
		e.Logger,
		operations.NewMemoryReporter(),
	)

	cs := ccipChangesets.ConfigureChainsForLanesFromTopology(
		ccipAdapters.GetCommitteeVerifierContractRegistry(),
		ccipAdapters.GetChainFamilyRegistry(),
		changesetscore.GetRegistry(),
	)
	pairs := make(map[string]ccipChangesets.CrossFamilyLanePair)
	key := func(chainA, chainB uint64) string {
		return fmt.Sprintf("%d_%d", chainA, chainB)
	}

	isKeyPresent := func(chainA, chainB uint64) bool {
		return slices.Contains(expmaps.Keys(pairs), key(chainA, chainB)) ||
			slices.Contains(expmaps.Keys(pairs), key(chainB, chainA))
	}
	for sel, profile := range profiles {
		for _, remote := range profile.remotes {
			if isKeyPresent(remote, sel) {
				continue
			}
			cfg, err := profile.impl.GetChainLaneProfile(e, sel)
			if err != nil {
				return fmt.Errorf("get chain lane profile for chain %d: %w", sel, err)
			}
			pairs[key(sel, remote)] = ccipChangesets.CrossFamilyLanePair{
				ChainA:          sel,
				ChainB:          remote,
				ChainAOverrides: &cfg,
				ChainBOverrides: &cfg,
			}
		}
	}

	cfg := ccipChangesets.ConfigureChainsForLanesFromTopologyConfig{
		Topology: convertTopologyToCCIP(topology),
		BuildLanesCrossFamilyConfig: ccipChangesets.BuildLanesCrossFamilyConfig{
			Lanes: expmaps.Values(pairs),
		},
	}
	if err := cs.VerifyPreconditions(*e, cfg); err != nil {
		return fmt.Errorf("(adding chains %v): precondition check failed: %w", expmaps.Values(pairs), err)
	}
	if _, err := cs.Apply(*e, cfg); err != nil {
		return fmt.Errorf("(adding chains %v):  configure chains for lanes: %w", expmaps.Values(pairs), err)
	}

	for _, sel := range orderedSelectors {
		entry := profiles[sel]
		if err := entry.impl.PostConnect(e, sel, entry.remotes); err != nil {
			return fmt.Errorf("post-connect for chain %d: %w", sel, err)
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Legacy path: lanes.ConnectChains
// ---------------------------------------------------------------------------

type chainEntry struct {
	remoteSelectors []uint64
	impl            cciptestinterfaces.CCIP17Configuration
	chainDef        lanes.ChainDefinition
	cvConfig        lanes.CommitteeVerifierRemoteChainInput
}

func ConnectAllChainsLegacy(
	impls []cciptestinterfaces.CCIP17Configuration,
	blockchains []*blockchain.Input,
	selectors []uint64,
	e *deployment.Environment,
	topology *ccvdeployment.EnvironmentTopology,
) error {
	if len(blockchains) != len(impls) {
		return fmt.Errorf("ConnectAllChainsLegacy: mismatched lengths: %d impls and %d blockchains", len(impls), len(blockchains))
	}
	if len(selectors) == 0 {
		return fmt.Errorf("ConnectAllChainsLegacy: selectors must be non-empty")
	}

	entries := make(map[uint64]chainEntry, len(impls))
	orderedSelectors := make([]uint64, 0, len(impls))
	for i, impl := range impls {
		networkInfo, err := chainsel.GetChainDetailsByChainIDAndFamily(blockchains[i].ChainID, impl.ChainFamily())
		if err != nil {
			return fmt.Errorf("chain %d: %w", i, err)
		}
		sel := networkInfo.ChainSelector
		remotes := make([]uint64, 0, len(selectors))
		for _, s := range selectors {
			if s != sel {
				remotes = append(remotes, s)
			}
		}
		chainDef, cvConfig, err := impl.GetConnectionProfile(e, sel)
		if err != nil {
			return fmt.Errorf("get connection profile for chain %d: %w", sel, err)
		}
		entries[sel] = chainEntry{
			remoteSelectors: remotes,
			impl:            impl,
			chainDef:        chainDef,
			cvConfig:        cvConfig,
		}
		orderedSelectors = append(orderedSelectors, sel)
	}

	laneConfigs := make([]lanes.LaneConfig, 0)
	for _, sel := range orderedSelectors {
		entry := entries[sel]
		cvInputs := buildCommitteeVerifierInputs(topology, entry.remoteSelectors, entries)
		for _, rs := range entry.remoteSelectors {
			remote, ok := entries[rs]
			if !ok {
				return fmt.Errorf("missing chain definition for remote selector %d (referenced from chain %d)", rs, sel)
			}
			chainA := entry.chainDef
			chainA.Selector = sel
			chainA.CommitteeVerifierInputs = cvInputs

			chainB := remote.chainDef
			chainB.Selector = rs

			laneConfigs = append(laneConfigs, lanes.LaneConfig{
				ChainA:  chainA,
				ChainB:  chainB,
				Version: semver.MustParse("2.0.0"),
			})
		}
	}

	e.OperationsBundle = operations.NewBundle(
		func() context.Context { return context.Background() },
		e.Logger,
		operations.NewMemoryReporter(),
	)

	populator := ccipChangesets.NewTopologyCommitteePopulator(
		ccipAdapters.GetCommitteeVerifierContractRegistry(),
		convertTopologyToCCIP(topology),
	)

	laneAdapterRegistry := lanes.GetLaneAdapterRegistry()
	mcmsReaderRegistry := changesetscore.GetRegistry()

	connectChainsCS := lanes.ConnectChains(laneAdapterRegistry, mcmsReaderRegistry)
	cfg := lanes.ConnectChainsConfig{
		Lanes:              laneConfigs,
		CommitteePopulator: populator,
	}
	if err := connectChainsCS.VerifyPreconditions(*e, cfg); err != nil {
		return fmt.Errorf("connect chains precondition check failed: %w", err)
	}
	if _, err := connectChainsCS.Apply(*e, cfg); err != nil {
		return fmt.Errorf("configure chains for lanes: %w", err)
	}

	for _, sel := range orderedSelectors {
		entry := entries[sel]
		if err := entry.impl.PostConnect(e, sel, entry.remoteSelectors); err != nil {
			return fmt.Errorf("post-connect for chain %d: %w", sel, err)
		}
	}

	return nil
}

func buildCommitteeVerifierInputs(
	topology *ccvdeployment.EnvironmentTopology,
	remoteSelectors []uint64,
	entries map[uint64]chainEntry,
) []lanes.CommitteeVerifierInput {
	remoteChainConfigs := make(map[uint64]lanes.CommitteeVerifierRemoteChainInput, len(remoteSelectors))
	for _, rs := range remoteSelectors {
		if entry, ok := entries[rs]; ok {
			remoteChainConfigs[rs] = entry.cvConfig
		}
	}

	verifiers := make([]lanes.CommitteeVerifierInput, 0, len(topology.NOPTopology.Committees))
	for qualifier := range topology.NOPTopology.Committees {
		verifiers = append(verifiers, lanes.CommitteeVerifierInput{
			CommitteeQualifier: qualifier,
			RemoteChains:       remoteChainConfigs,
		})
	}

	return verifiers
}

// ---------------------------------------------------------------------------
// Chain-agnostic token & pool deployment
// ---------------------------------------------------------------------------

// DeployTokensAndPools collects TokenExpansion configs from each chain impl
// and deploys tokens and pools via the chain-agnostic TokenExpansion API.
// Each impl provides its chain-specific config (token type, decimals, admins,
// etc.) via GetTokenExpansionConfigs and handles post-deploy work (e.g.
// funding lock-release pools) via PostTokenDeploy.
//
// deltaDS accumulates only the addresses deployed by this function (the
// caller uses it to track per-chain additions). env.DataStore is kept
// up-to-date with the full state so that each TokenExpansion call can
// resolve previously deployed contracts.
func DeployTokensAndPools(
	impl cciptestinterfaces.TokenConfigProvider,
	env *deployment.Environment,
	selector uint64,
	combos []devenvcommon.TokenCombination,
	deltaDS *datastore.MemoryDataStore,
) error {
	configs, err := impl.GetTokenExpansionConfigs(env, selector, combos)
	if err != nil {
		return fmt.Errorf("get token expansion configs for selector %d: %w", selector, err)
	}
	if len(configs) == 0 {
		return nil
	}

	var deployedRefs []datastore.AddressRef

	for _, cfg := range configs {
		poolInput := cfg.DeployTokenPoolInput
		qualifier := ""
		if poolInput != nil {
			qualifier = poolInput.TokenPoolQualifier
		}

		out, err := tokenscore.TokenExpansion().Apply(*env, tokenscore.TokenExpansionInput{
			ChainAdapterVersion: cfg.TokenPoolVersion,
			MCMS:                devenvmcms.Input{},
			TokenExpansionInputPerChain: map[uint64]tokenscore.TokenExpansionInputPerChain{
				selector: cfg,
			},
		})
		if err != nil {
			return fmt.Errorf("failed to deploy %s token and pool: %w", qualifier, err)
		}

		if err := deltaDS.Merge(out.DataStore.Seal()); err != nil {
			return fmt.Errorf("failed to merge delta datastore for %s token: %w", qualifier, err)
		}

		fullDS := datastore.NewMemoryDataStore()
		if err := fullDS.Merge(env.DataStore); err != nil {
			return fmt.Errorf("failed to merge env datastore: %w", err)
		}
		if err := fullDS.Merge(out.DataStore.Seal()); err != nil {
			return fmt.Errorf("failed to merge output datastore: %w", err)
		}
		env.DataStore = fullDS.Seal()

		if poolInput != nil {
			ref, err := env.DataStore.Addresses().Get(
				datastore.NewAddressRefKey(
					selector,
					datastore.ContractType(poolInput.PoolType),
					cfg.TokenPoolVersion,
					poolInput.TokenPoolQualifier,
				),
			)
			if err != nil {
				return fmt.Errorf("failed to get deployed token pool ref for %s: %w", qualifier, err)
			}
			deployedRefs = append(deployedRefs, ref)
		}
	}

	if err := impl.PostTokenDeploy(env, selector, deployedRefs); err != nil {
		return fmt.Errorf("PostTokenDeploy for selector %d: %w", selector, err)
	}

	return nil
}

// ---------------------------------------------------------------------------
// Chain-agnostic token transfer configuration
// ---------------------------------------------------------------------------

// ConfigureAllTokenTransfers collects TokenTransferConfigs from all chain
// impls, groups them by local pool identity, and calls
// ConfigureTokensForTransfers once per group. This replaces the EVM-specific
// BuildTokenTransferConfigs call that previously lived in environment.go.
func ConfigureAllTokenTransfers(
	impls []cciptestinterfaces.CCIP17Configuration,
	selectors []uint64,
	env *deployment.Environment,
	topology *ccvdeployment.EnvironmentTopology,
) error {
	// First merge duplicate configs for the same local pool. Each merged config
	// keeps all remote lanes for that pool; the next phase splits unrelated
	// tokens into separate ConfigureTokensForTransfers calls because upstream
	// keys the Tokens slice by chain selector.
	type poolKey struct {
		chainSelector uint64
		poolID        string
	}
	byPool := make(map[poolKey]tokenscore.TokenTransferConfig)

	for i, impl := range impls {
		tcp, ok := impl.(cciptestinterfaces.TokenConfigProvider)
		if !ok {
			continue
		}
		remoteSelectors := make([]uint64, 0, len(selectors)-1)
		for _, s := range selectors {
			if s != selectors[i] {
				remoteSelectors = append(remoteSelectors, s)
			}
		}

		cfgs, err := tcp.GetTokenTransferConfigs(env, selectors[i], remoteSelectors, topology)
		if err != nil {
			return fmt.Errorf("get token transfer configs for selector %d: %w", selectors[i], err)
		}
		for _, cfg := range cfgs {
			pk := poolKey{
				chainSelector: cfg.ChainSelector,
				poolID:        tokenTransferRefKey(cfg.TokenPoolRef),
			}
			if existing, ok := byPool[pk]; ok {
				maps.Copy(existing.RemoteChains, cfg.RemoteChains)
				byPool[pk] = existing
			} else {
				byPool[pk] = cfg
			}
		}
	}

	if len(byPool) == 0 {
		return nil
	}

	allConfigs := make([]tokenscore.TokenTransferConfig, 0, len(byPool))
	for _, cfg := range byPool {
		allConfigs = append(allConfigs, cfg)
	}

	batches, err := buildTokenTransferBatches(allConfigs)
	if err != nil {
		return err
	}

	tokenAdapterRegistry := tokenscore.GetTokenAdapterRegistry()
	mcmsReaderRegistry := changesetscore.GetRegistry()
	for i, batch := range batches {
		_, err := tokenscore.ConfigureTokensForTransfers(tokenAdapterRegistry, mcmsReaderRegistry).Apply(*env, tokenscore.ConfigureTokensForTransfersConfig{
			Tokens: batch,
		})
		if err != nil {
			return fmt.Errorf("configure tokens for transfers batch %d: %w", i, err)
		}
	}
	return nil
}

func tokenTransferRefKey(ref datastore.AddressRef) string {
	v := ""
	if ref.Version != nil {
		v = ref.Version.String()
	}
	return string(ref.Type) + "+" + v + "+" + ref.Qualifier
}

// canonicalPoolPairKey returns a stable batch key for a pool reference.
//
// It accepts both the current canonical "BASE (POOL_A, POOL_B)" format and
// the older directional "BASE (POOL_A to POOL_B)" / ":local" / ":remote" forms.
// Plain qualifiers without a recognizable pair fall through to tokenTransferRefKey.
func canonicalPoolPairKey(ref datastore.AddressRef) string {
	qualifier := strings.TrimSuffix(strings.TrimSuffix(ref.Qualifier, ":local"), ":remote")
	if pairQualifier, _, ok := strings.Cut(qualifier, "::"); ok {
		qualifier = pairQualifier
	}
	base, rest, ok := strings.Cut(qualifier, " (")
	if !ok || !strings.HasSuffix(rest, ")") {
		return tokenTransferRefKey(ref)
	}
	inner := strings.TrimSuffix(rest, ")")
	a, b, ok := strings.Cut(inner, ", ")
	if !ok {
		a, b, ok = strings.Cut(inner, " to ")
		if !ok {
			return tokenTransferRefKey(ref)
		}
	}
	if a > b {
		a, b = b, a
	}
	return base + "+" + a + "+" + b
}

type tokenTransferNodeKey struct {
	chainSelector uint64
	poolKey       string
}

func tokenTransferConfigNodeKey(cfg tokenscore.TokenTransferConfig) tokenTransferNodeKey {
	return tokenTransferNodeKey{
		chainSelector: cfg.ChainSelector,
		poolKey:       tokenTransferRefKey(cfg.TokenPoolRef),
	}
}

func tokenTransferRemoteNodeKey(chainSelector uint64, ref datastore.AddressRef) tokenTransferNodeKey {
	return tokenTransferNodeKey{
		chainSelector: chainSelector,
		poolKey:       tokenTransferRefKey(ref),
	}
}

func (k tokenTransferNodeKey) String() string {
	return fmt.Sprintf("%d/%s", k.chainSelector, k.poolKey)
}

func buildTokenTransferBatches(configs []tokenscore.TokenTransferConfig) ([][]tokenscore.TokenTransferConfig, error) {
	// Group first so unrelated token pairs never get matched together. Within a
	// group, split only when a ConfigureTokensForTransfers call would contain two
	// configs for the same selector. Each config keeps its full RemoteChains map:
	// the EVM token-pool sequence requires every call for an already-active pool
	// to include all supported remote chains.
	byPair := make(map[string][]tokenscore.TokenTransferConfig)
	for _, cfg := range configs {
		pairKey := canonicalPoolPairKey(cfg.TokenPoolRef)
		byPair[pairKey] = append(byPair[pairKey], cfg)
	}

	groupKeys := make([]string, 0, len(byPair))
	for groupKey := range byPair {
		groupKeys = append(groupKeys, groupKey)
	}
	sort.Strings(groupKeys)

	batches := make([][]tokenscore.TokenTransferConfig, 0, len(groupKeys))
	for _, groupKey := range groupKeys {
		group := append([]tokenscore.TokenTransferConfig(nil), byPair[groupKey]...)
		sort.Slice(group, func(i, j int) bool {
			if group[i].ChainSelector != group[j].ChainSelector {
				return group[i].ChainSelector < group[j].ChainSelector
			}
			return tokenTransferRefKey(group[i].TokenPoolRef) < tokenTransferRefKey(group[j].TokenPoolRef)
		})

		configByNode := make(map[tokenTransferNodeKey]struct{}, len(group))
		for _, cfg := range group {
			from := tokenTransferConfigNodeKey(cfg)
			if _, exists := configByNode[from]; exists {
				return nil, fmt.Errorf("duplicate token transfer config for %s", from)
			}
			configByNode[from] = struct{}{}
		}
		for _, cfg := range group {
			from := tokenTransferConfigNodeKey(cfg)
			for remoteSelector, remoteCfg := range cfg.RemoteChains {
				if remoteCfg.RemotePool == nil {
					return nil, fmt.Errorf("token transfer config %s has nil remote pool for remote selector %d", from, remoteSelector)
				}
				to := tokenTransferRemoteNodeKey(remoteSelector, *remoteCfg.RemotePool)
				if _, exists := configByNode[to]; !exists {
					return nil, fmt.Errorf("token transfer config %s references remote pool %s, but that pool is not present in the same batch group", from, to)
				}
			}
		}

		batches = append(batches, splitTokenTransferBatchBySelector(group)...)
	}
	return batches, nil
}

func splitTokenTransferBatchBySelector(configs []tokenscore.TokenTransferConfig) [][]tokenscore.TokenTransferConfig {
	// isBidirectionallyCompatible checks whether placing cfg into batch would
	// maintain symmetry: for every remote chain already in the batch, the
	// counterpart config must reference cfg's chain back and vice-versa.
	isBidirectionallyCompatible := func(batch []tokenscore.TokenTransferConfig, cfg tokenscore.TokenTransferConfig) bool {
		batchBySelector := make(map[uint64]tokenscore.TokenTransferConfig, len(batch))
		for _, b := range batch {
			batchBySelector[b.ChainSelector] = b
		}

		for remoteSelector := range cfg.RemoteChains {
			counterpart, inBatch := batchBySelector[remoteSelector]
			if !inBatch {
				continue
			}
			if _, ok := counterpart.RemoteChains[cfg.ChainSelector]; !ok {
				return false
			}
		}

		for _, b := range batch {
			if _, refsMe := b.RemoteChains[cfg.ChainSelector]; refsMe {
				if _, ok := cfg.RemoteChains[b.ChainSelector]; !ok {
					return false
				}
			}
		}

		return true
	}

	batches := make([][]tokenscore.TokenTransferConfig, 0, 1)
	seenSelectors := make([]map[uint64]bool, 0, 1)
	for _, cfg := range configs {
		placed := false
		for i := range batches {
			if seenSelectors[i][cfg.ChainSelector] {
				continue
			}
			if !isBidirectionallyCompatible(batches[i], cfg) {
				continue
			}
			batches[i] = append(batches[i], cfg)
			seenSelectors[i][cfg.ChainSelector] = true
			placed = true
			break
		}
		if placed {
			continue
		}
		batches = append(batches, []tokenscore.TokenTransferConfig{cfg})
		seenSelectors = append(seenSelectors, map[uint64]bool{cfg.ChainSelector: true})
	}
	return batches
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
	if cfg.NOPTopology == nil {
		return
	}
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

// EnrichTopologyWithVerifiers enriches an existing topology in-place with signer addresses
// derived from verifier bootstrap keys. Call this after verifiers are launched and their
// Out.BootstrapKeys are populated. The topology pointer is mutated directly so that other
// Phase 4 components reading the same pointer see the updated signer addresses.
func EnrichTopologyWithVerifiers(topology *ccvdeployment.EnvironmentTopology, verifiers []*committeeverifier.Input) {
	enrichEnvironmentTopology(topology, verifiers)
}

// BuildEnvironmentTopology creates a copy of the EnvironmentTopology, enriches it with signer
// addresses and fee aggregator fallbacks, and returns it. This is the single source of truth
// used by both executor and verifier changesets.
func BuildEnvironmentTopology(topology *ccvdeployment.EnvironmentTopology, verifiers []*committeeverifier.Input, e *deployment.Environment) *ccvdeployment.EnvironmentTopology {
	if topology == nil {
		return nil
	}
	envCfg := *topology
	enrichEnvironmentTopology(&envCfg, verifiers)

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
