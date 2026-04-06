package ccv

import (
	"context"
	"fmt"
	"sort"

	"github.com/Masterminds/semver/v3"

	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccip/deployment/lanes"
	changesetscore "github.com/smartcontractkit/chainlink-ccip/deployment/utils/changesets"
	ccipAdapters "github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/adapters"
	ccipChangesets "github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/changesets"
	ccipOffchain "github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/offchain"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

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
			CommitteeQualifier: qualifier,
			RemoteChains:       remoteCV,
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
	seen := make(map[[2]uint64]struct{})
	for _, sel := range orderedSelectors {
		entry := entries[sel]
		cvInputs := buildCommitteeVerifierInputs(topology, entry.remoteSelectors, entries)
		for _, rs := range entry.remoteSelectors {
			// Normalize selector pairs to avoid duplicate lane configs for (A,B) vs (B,A).
			lo := min(sel, rs)
			hi := max(sel, rs)
			if _, dup := seen[[2]uint64{lo, hi}]; dup {
				continue
			}
			seen[[2]uint64{lo, hi}] = struct{}{}

			remote, ok := entries[rs]
			if !ok {
				return fmt.Errorf("missing chain definition for remote selector %d (referenced from chain %d)", rs, sel)
			}
			chainA := entry.chainDef
			chainA.Selector = sel
			chainA.CommitteeVerifierInputs = cvInputs

			chainB := remote.chainDef
			chainB.Selector = rs
			chainB.CommitteeVerifierInputs = buildCommitteeVerifierInputs(topology, remote.remoteSelectors, entries)

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
