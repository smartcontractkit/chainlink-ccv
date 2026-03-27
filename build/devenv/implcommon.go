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

type chainEntry struct {
	remoteSelectors []uint64
	impl            cciptestinterfaces.CCIP17Configuration
	chainDef        lanes.ChainDefinition
	cvConfig        ccipChangesets.CommitteeVerifierRemoteChainConfig
}

// connectAllChains collects a ChainDefinition from each impl, assembles a
// single ConfigureChainsForLanesFromTopologyConfig, applies it once, then runs
// each impl's PostConnect for chain-specific follow-up (e.g. USDC, custom executor).
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

	entries := make(map[uint64]chainEntry, len(impls))
	// Preserve input ordering for deterministic PostConnect calls.
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

	partialChains := make([]ccipChangesets.PartialChainConfig, 0, len(entries))
	for _, sel := range orderedSelectors {
		entry := entries[sel]
		remoteChains := make(map[uint64]ccipChangesets.RemoteLaneConfig, len(entry.remoteSelectors))
		for _, rs := range entry.remoteSelectors {
			remote, ok := entries[rs]
			if !ok {
				return fmt.Errorf("missing chain definition for remote selector %d (referenced from chain %d)", rs, sel)
			}
			remoteChains[rs] = ccipChangesets.RemoteLaneConfig{Chain: remote.chainDef}
		}

		committeeVerifiers, err := buildCommitteeVerifiers(topology, entry.remoteSelectors, entries)
		if err != nil {
			return fmt.Errorf("build committee verifiers for chain %d: %w", sel, err)
		}

		cd := entry.chainDef
		partialChains = append(partialChains, ccipChangesets.PartialChainConfig{
			ChainSelector:                     sel,
			CommitteeVerifiers:                committeeVerifiers,
			DefaultInboundCCVs:                cd.DefaultInboundCCVs,
			DefaultOutboundCCVs:               cd.DefaultOutboundCCVs,
			DefaultExecutor:                   cd.DefaultExecutor,
			FeeQuoterDestChainConfigOverrides: cd.FeeQuoterDestChainConfigOverrides,
			ExecutorDestChainConfig:           cd.ExecutorDestChainConfig,
			AddressBytesLength:                cd.AddressBytesLength,
			BaseExecutionGasCost:              cd.BaseExecutionGasCost,
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

	for _, sel := range orderedSelectors {
		entry := entries[sel]
		if err := entry.impl.PostConnect(e, sel, entry.remoteSelectors); err != nil {
			return fmt.Errorf("post-connect for chain %d: %w", sel, err)
		}
	}

	return nil
}

// buildCommitteeVerifiers assembles CommitteeVerifierInputConfig entries from
// topology committee qualifiers + per-remote-chain configs looked up from each
// chain's reported CommitteeVerifierRemoteChainConfig.
func buildCommitteeVerifiers(
	topology *ccipOffchain.EnvironmentTopology,
	remoteSelectors []uint64,
	entries map[uint64]chainEntry,
) ([]ccipChangesets.CommitteeVerifierInputConfig, error) {
	remoteChainConfigs := make(map[uint64]ccipChangesets.CommitteeVerifierRemoteChainConfig, len(remoteSelectors))
	for _, rs := range remoteSelectors {
		entry, ok := entries[rs]
		if !ok {
			return nil, fmt.Errorf("missing committee verifier config for remote selector %d", rs)
		}
		remoteChainConfigs[rs] = entry.cvConfig
	}

	verifiers := make([]ccipChangesets.CommitteeVerifierInputConfig, 0, len(topology.NOPTopology.Committees))
	for qualifier := range topology.NOPTopology.Committees {
		verifiers = append(verifiers, ccipChangesets.CommitteeVerifierInputConfig{
			CommitteeQualifier: qualifier,
			RemoteChains:       remoteChainConfigs,
		})
	}

	return verifiers, nil
}
