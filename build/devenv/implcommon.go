package ccv

import (
	"context"
	"fmt"
	"maps"
	"sort"

	"github.com/Masterminds/semver/v3"

	"github.com/smartcontractkit/chainlink-ccip/deployment/finality"

	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccip/deployment/lanes"
	tokenscore "github.com/smartcontractkit/chainlink-ccip/deployment/tokens"
	changesetscore "github.com/smartcontractkit/chainlink-ccip/deployment/utils/changesets"
	devenvmcms "github.com/smartcontractkit/chainlink-ccip/deployment/utils/mcms"
	ccipAdapters "github.com/smartcontractkit/chainlink-ccip/deployment/v2_0_0/adapters"
	ccipChangesets "github.com/smartcontractkit/chainlink-ccip/deployment/v2_0_0/changesets"
	ccipOffchain "github.com/smartcontractkit/chainlink-ccip/deployment/v2_0_0/offchain"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

// ---------------------------------------------------------------------------
// Chain-agnostic contract deployment (matches the 1.6 pattern)
// ---------------------------------------------------------------------------

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
	topology *ccipOffchain.EnvironmentTopology,
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
	registry := ccipAdapters.GetDeployChainContractsRegistry()
	out, err := ccipChangesets.DeployChainContracts(registry).Apply(*env, changesetscore.WithMCMS[ccipChangesets.DeployChainContractsCfg]{
		Cfg: ccipChangesets.DeployChainContractsCfg{
			Topology:                                topology,
			ChainSelectors:                          []uint64{selector},
			IgnoreImportedConfigFromPreviousVersion: true,
			DefaultCfg:                              cfg,
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

	return runningDS.Seal(), nil
}

// ---------------------------------------------------------------------------
// Canonical path (new): ConfigureChainsForLanesFromTopology
// ---------------------------------------------------------------------------

type chainProfile struct {
	remotes []uint64
	impl    cciptestinterfaces.CCIP17Configuration
	profile cciptestinterfaces.ChainLaneProfile
}

// connectAllChains configures lanes incrementally: each iteration adds one
// chain to the mesh, mirroring how production environments grow. The
// underlying ConfigureChainForLanes sequence is fully idempotent, so
// re-running for already-configured contracts is a no-op.
func connectAllChainsCanonical(
	impls []cciptestinterfaces.CCIP17Configuration,
	blockchains []*blockchain.Input,
	selectors []uint64,
	e *deployment.Environment,
	topology *ccipOffchain.EnvironmentTopology,
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
		profile, err := impl.GetChainLaneProfile(e, sel)
		if err != nil {
			return fmt.Errorf("get chain lane profile for chain %d: %w", sel, err)
		}
		profiles[sel] = chainProfile{
			remotes: remotes,
			impl:    impl,
			profile: profile,
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

	for i := 1; i < len(orderedSelectors); i++ {
		newSel := orderedSelectors[i]
		previousSels := orderedSelectors[:i]

		var configs []ccipChangesets.PartialChainConfig

		newChainCfg, err := buildPartialChainConfig(newSel, previousSels, profiles, topology)
		if err != nil {
			return fmt.Errorf("round %d: build config for new chain %d: %w", i, newSel, err)
		}
		configs = append(configs, newChainCfg)

		for _, prevSel := range previousSels {
			prevChainCfg, err := buildPartialChainConfig(prevSel, []uint64{newSel}, profiles, topology)
			if err != nil {
				return fmt.Errorf("round %d: build config for existing chain %d: %w", i, prevSel, err)
			}
			configs = append(configs, prevChainCfg)
		}

		cfg := ccipChangesets.ConfigureChainsForLanesFromTopologyConfig{
			Topology: topology,
			Chains:   configs,
		}
		if err := cs.VerifyPreconditions(*e, cfg); err != nil {
			return fmt.Errorf("round %d (adding chain %d): precondition check failed: %w", i, newSel, err)
		}
		if _, err := cs.Apply(*e, cfg); err != nil {
			return fmt.Errorf("round %d (adding chain %d): configure chains for lanes: %w", i, newSel, err)
		}
	}

	for _, sel := range orderedSelectors {
		entry := profiles[sel]
		if err := entry.impl.PostConnect(e, sel, entry.remotes); err != nil {
			return fmt.Errorf("post-connect for chain %d: %w", sel, err)
		}
	}

	return nil
}

func buildPartialChainConfig(
	localSel uint64,
	remoteSels []uint64,
	profiles map[uint64]chainProfile,
	topology *ccipOffchain.EnvironmentTopology,
) (ccipChangesets.PartialChainConfig, error) {
	localEntry, ok := profiles[localSel]
	if !ok {
		return ccipChangesets.PartialChainConfig{}, fmt.Errorf("no profile for local chain %d", localSel)
	}
	local := localEntry.profile

	remoteChains := make(map[uint64]ccipChangesets.PartialRemoteChainConfig, len(remoteSels))
	for _, rs := range remoteSels {
		remoteEntry, ok := profiles[rs]
		if !ok {
			return ccipChangesets.PartialChainConfig{}, fmt.Errorf("no profile for remote chain %d", rs)
		}
		remote := remoteEntry.profile
		allowTrafficFrom := true
		remoteChains[rs] = ccipChangesets.PartialRemoteChainConfig{
			AllowTrafficFrom:         &allowTrafficFrom,
			DefaultInboundCCVs:       local.DefaultInboundCCVs,
			DefaultOutboundCCVs:      local.DefaultOutboundCCVs,
			DefaultExecutorQualifier: local.DefaultExecutorQualifier,
			FeeQuoterDestChainConfig: remote.FeeQuoterDestChainConfig,
			ExecutorDestChainConfig:  local.ExecutorDestChainConfig,
			AddressBytesLength:       remote.AddressBytesLength,
			BaseExecutionGasCost:     remote.BaseExecutionGasCost,
			TokenReceiverAllowed:     remote.TokenReceiverAllowed,
		}
	}

	qualifiers := make([]string, 0, len(topology.NOPTopology.Committees))
	for qualifier := range topology.NOPTopology.Committees {
		qualifiers = append(qualifiers, qualifier)
	}
	sort.Strings(qualifiers)

	cvConfigs := make([]ccipChangesets.CommitteeVerifierInputConfig, 0, len(qualifiers))
	for _, qualifier := range qualifiers {
		remoteCV := make(map[uint64]ccipChangesets.CommitteeVerifierRemoteChainConfig, len(remoteSels))
		for _, rs := range remoteSels {
			remoteCV[rs] = ccipChangesets.CommitteeVerifierRemoteChainConfig{
				GasForVerification: profiles[rs].profile.GasForVerification,
			}
		}
		cvConfigs = append(cvConfigs, ccipChangesets.CommitteeVerifierInputConfig{
			CommitteeQualifier:    qualifier,
			RemoteChains:          remoteCV,
			AllowedFinalityConfig: finality.Config{BlockDepth: 1, WaitForSafe: true},
		})
	}

	return ccipChangesets.PartialChainConfig{
		ChainSelector:      localSel,
		CommitteeVerifiers: cvConfigs,
		RemoteChains:       remoteChains,
	}, nil
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

func connectAllChainsLegacy(
	impls []cciptestinterfaces.CCIP17Configuration,
	blockchains []*blockchain.Input,
	selectors []uint64,
	e *deployment.Environment,
	topology *ccipOffchain.EnvironmentTopology,
) error {
	if len(blockchains) != len(impls) {
		return fmt.Errorf("connectAllChainsLegacy: mismatched lengths: %d impls and %d blockchains", len(impls), len(blockchains))
	}
	if len(selectors) == 0 {
		return fmt.Errorf("connectAllChainsLegacy: selectors must be non-empty")
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
		topology,
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
	topology *ccipOffchain.EnvironmentTopology,
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
// impls, groups them by pool identity, and calls ConfigureTokensForTransfers
// once per group. This replaces the EVM-specific BuildTokenTransferConfigs
// call that previously lived in environment.go.
func ConfigureAllTokenTransfers(
	impls []cciptestinterfaces.CCIP17Configuration,
	selectors []uint64,
	env *deployment.Environment,
	topology *ccipOffchain.EnvironmentTopology,
) error {
	refKey := func(ref datastore.AddressRef) string {
		v := ""
		if ref.Version != nil {
			v = ref.Version.String()
		}
		return string(ref.Type) + "+" + v + "+" + ref.Qualifier
	}

	// laneKey groups reciprocal configs for the same selector pair by the local
	// pool identity each selector contributes. The selector ordering is stable,
	// so A(local burn)->B(remote lock) and B(local lock)->A(remote burn) land in
	// the same bucket, while the opposite orientation on the same selector pair
	// stays distinct.
	laneKey := func(local datastore.AddressRef, localSelector uint64, remote datastore.AddressRef, remoteSelector uint64) string {
		leftSelector, leftRef := localSelector, local
		rightSelector, rightRef := remoteSelector, remote
		if leftSelector > rightSelector {
			leftSelector, rightSelector = rightSelector, leftSelector
			leftRef, rightRef = rightRef, leftRef
		}
		return fmt.Sprintf("%d:%s<->%d:%s", leftSelector, refKey(leftRef), rightSelector, refKey(rightRef))
	}

	byLane := make(map[string]map[uint64]tokenscore.TokenTransferConfig)

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
			for remoteSelector, remoteCfg := range cfg.RemoteChains {
				if remoteCfg.RemotePool == nil {
					continue
				}

				key := laneKey(cfg.TokenPoolRef, cfg.ChainSelector, *remoteCfg.RemotePool, remoteSelector)
				splitCfg := cfg
				splitCfg.RemoteChains = map[uint64]tokenscore.RemoteChainConfig[*datastore.AddressRef, datastore.AddressRef]{
					remoteSelector: remoteCfg,
				}

				if byLane[key] == nil {
					byLane[key] = make(map[uint64]tokenscore.TokenTransferConfig)
				}

				if existing, ok := byLane[key][cfg.ChainSelector]; ok {
					if refKey(existing.TokenPoolRef) != refKey(splitCfg.TokenPoolRef) {
						return fmt.Errorf(
							"selector %d produced conflicting local pool configs for lane %s: %s/%s vs %s/%s",
							cfg.ChainSelector,
							key,
							existing.TokenPoolRef.Type,
							existing.TokenPoolRef.Qualifier,
							splitCfg.TokenPoolRef.Type,
							splitCfg.TokenPoolRef.Qualifier,
						)
					}
					maps.Copy(existing.RemoteChains, splitCfg.RemoteChains)
					byLane[key][cfg.ChainSelector] = existing
				} else {
					byLane[key][cfg.ChainSelector] = splitCfg
				}
			}
		}
	}

	if len(byLane) == 0 {
		return nil
	}

	tokenAdapterRegistry := tokenscore.GetTokenAdapterRegistry()
	mcmsReaderRegistry := changesetscore.GetRegistry()
	for _, groupedBySelector := range byLane {
		group := make([]tokenscore.TokenTransferConfig, 0, len(groupedBySelector))
		for _, cfg := range groupedBySelector {
			group = append(group, cfg)
		}
		_, err := tokenscore.ConfigureTokensForTransfers(tokenAdapterRegistry, mcmsReaderRegistry).Apply(*env, tokenscore.ConfigureTokensForTransfersConfig{
			Tokens: group,
		})
		if err != nil {
			return fmt.Errorf("configure tokens for transfers: %w", err)
		}
	}
	return nil
}
