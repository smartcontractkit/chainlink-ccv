package ccv

import (
	"context"
	"fmt"

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

type chainEntry struct {
	remoteSelectors []uint64
	impl            cciptestinterfaces.CCIP17Configuration
	chainDef        lanes.ChainDefinition
	cvConfig        lanes.CommitteeVerifierRemoteChainInput
}

// connectAllChains collects a ChainDefinition from each impl, assembles
// ConnectChainsConfig with a TopologyCommitteePopulator, applies it once,
// then runs each impl's PostConnect for chain-specific follow-up.
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

// buildCommitteeVerifierInputs assembles CommitteeVerifierInput entries from
// topology committee qualifiers + per-remote-chain configs looked up from each
// chain's reported CommitteeVerifierRemoteChainInput.
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
