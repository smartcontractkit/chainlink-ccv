package ccv

import (
	"context"
	"fmt"

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

// connectAllChains collects a ChainConnectionProfile from each impl, assembles a
// single ConfigureChainsForLanesFromTopologyConfig, applies it once, then runs
// each impl's PostConnect for chain-specific follow-up (e.g. USDC, custom executor).
func connectAllChains(
	ctx context.Context,
	impls []cciptestinterfaces.CCIP17Configuration,
	blockchains []*blockchain.Input,
	selectors []uint64,
	e *deployment.Environment,
	topology *ccipOffchain.EnvironmentTopology,
) error {
	type chainEntry struct {
		selector        uint64
		remoteSelectors []uint64
		impl            cciptestinterfaces.CCIP17Configuration
		profile         cciptestinterfaces.ChainConnectionProfile
	}

	entries := make([]chainEntry, 0, len(impls))
	for i, impl := range impls {
		networkInfo, err := chainsel.GetChainDetailsByChainIDAndFamily(blockchains[i].ChainID, impl.ChainFamily())
		if err != nil {
			return fmt.Errorf("chain %d: %w", i, err)
		}
		remotes := make([]uint64, 0, len(selectors)-1)
		for _, sel := range selectors {
			if sel != networkInfo.ChainSelector {
				remotes = append(remotes, sel)
			}
		}
		profile, err := impl.GetConnectionProfile(ctx, e, networkInfo.ChainSelector, remotes, topology)
		if err != nil {
			return fmt.Errorf("get connection profile for chain %d: %w", networkInfo.ChainSelector, err)
		}
		entries = append(entries, chainEntry{
			selector:        networkInfo.ChainSelector,
			remoteSelectors: remotes,
			impl:            impl,
			profile:         profile,
		})
	}

	profileBySelector := make(map[uint64]cciptestinterfaces.ChainConnectionProfile, len(entries))
	for _, entry := range entries {
		profileBySelector[entry.selector] = entry.profile
	}

	partialChains := make([]ccipChangesets.PartialChainConfig, 0, len(entries))
	for _, entry := range entries {
		remoteChains := make(map[uint64]ccipChangesets.RemoteLaneConfig, len(entry.remoteSelectors))
		for _, rs := range entry.remoteSelectors {
			rp := profileBySelector[rs]
			remoteChains[rs] = ccipChangesets.RemoteLaneConfig{Chain: lanes.ChainDefinition{
				Selector:                          rs,
				FeeQuoterDestChainConfigOverrides: rp.FeeQuoterDestChainConfigOverrides,
				ExecutorDestChainConfig:           rp.ExecutorDestChainConfig,
				AddressBytesLength:                rp.AddressBytesLength,
				BaseExecutionGasCost:              rp.BaseExecutionGasCost,
				DefaultExecutor:                   rp.DefaultExecutor,
				DefaultInboundCCVs:                rp.DefaultInboundCCVs,
				DefaultOutboundCCVs:               rp.DefaultOutboundCCVs,
			}}
		}

		partialChains = append(partialChains, ccipChangesets.PartialChainConfig{
			ChainSelector:                     entry.selector,
			CommitteeVerifiers:                entry.profile.CommitteeVerifiers,
			DefaultInboundCCVs:                entry.profile.DefaultInboundCCVs,
			DefaultOutboundCCVs:               entry.profile.DefaultOutboundCCVs,
			DefaultExecutor:                   entry.profile.DefaultExecutor,
			FeeQuoterDestChainConfigOverrides: entry.profile.FeeQuoterDestChainConfigOverrides,
			ExecutorDestChainConfig:           entry.profile.ExecutorDestChainConfig,
			AddressBytesLength:                entry.profile.AddressBytesLength,
			BaseExecutionGasCost:              entry.profile.BaseExecutionGasCost,
			RemoteChains:                      remoteChains,
		})
	}

	e.OperationsBundle = operations.NewBundle(
		func() context.Context { return context.Background() },
		e.Logger,
		operations.NewMemoryReporter(),
	)

	laneAdapterRegistry := lanes.GetLaneAdapterRegistry()
	mcmsReaderRegistry := changesetscore.GetRegistry()

	_, err := ccipChangesets.ConfigureChainsForLanesFromTopology(
		ccipAdapters.GetCommitteeVerifierContractRegistry(),
		laneAdapterRegistry,
		mcmsReaderRegistry,
	).Apply(*e, ccipChangesets.ConfigureChainsForLanesFromTopologyConfig{
		Topology: topology,
		Chains:   partialChains,
	})
	if err != nil {
		return fmt.Errorf("configure chains for lanes: %w", err)
	}

	for _, entry := range entries {
		if err := entry.impl.PostConnect(ctx, e, entry.selector, entry.remoteSelectors); err != nil {
			return fmt.Errorf("post-connect for chain %d: %w", entry.selector, err)
		}
	}

	return nil
}
