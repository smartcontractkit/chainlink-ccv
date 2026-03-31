package ccv

import (
	"context"
	"fmt"
	"sort"

	chainsel "github.com/smartcontractkit/chain-selectors"

	changesetscore "github.com/smartcontractkit/chainlink-ccip/deployment/utils/changesets"
	ccipAdapters "github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/adapters"
	ccipChangesets "github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/changesets"
	ccipOffchain "github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/offchain"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

type chainProfile struct {
	remotes []uint64
	impl    cciptestinterfaces.CCIP17Configuration
	profile cciptestinterfaces.ChainLaneProfile
}

// connectAllChains configures lanes incrementally: each iteration adds one
// chain to the mesh, mirroring how production environments grow. The
// underlying ConfigureChainForLanes sequence is fully idempotent, so
// re-running for already-configured contracts is a no-op.
func connectAllChains(
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

	remoteChains := make(map[uint64]ccipAdapters.RemoteChainConfig[datastore.AddressRef, datastore.AddressRef], len(remoteSels))
	for _, rs := range remoteSels {
		remoteEntry, ok := profiles[rs]
		if !ok {
			return ccipChangesets.PartialChainConfig{}, fmt.Errorf("no profile for remote chain %d", rs)
		}
		remote := remoteEntry.profile
		allowTrafficFrom := true
		remoteChains[rs] = ccipAdapters.RemoteChainConfig[datastore.AddressRef, datastore.AddressRef]{
			AllowTrafficFrom:         &allowTrafficFrom,
			OnRamps:                  []datastore.AddressRef{remote.OnRamp},
			OffRamp:                  remote.OffRamp,
			DefaultInboundCCVs:       local.DefaultInboundCCVs,
			DefaultOutboundCCVs:      local.DefaultOutboundCCVs,
			DefaultExecutor:          local.DefaultExecutor,
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
		Router:             local.Router,
		OnRamp:             local.OnRamp,
		FeeQuoter:          local.FeeQuoter,
		OffRamp:            local.OffRamp,
		CommitteeVerifiers: cvConfigs,
		RemoteChains:       remoteChains,
	}, nil
}
