package ccv

import (
	"context"
	"fmt"

	changesetscore "github.com/smartcontractkit/chainlink-ccip/deployment/utils/changesets"
	ccipAdapters "github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/adapters"
	ccipChangesets "github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/changesets"
	ccipOffchain "github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/offchain"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

type chainProfile struct {
	remotes []uint64
	impl    cciptestinterfaces.CCIP17Configuration
	profile cciptestinterfaces.ChainLaneProfile
}

// connectAllChains collects a ChainLaneProfile from each impl, assembles
// PartialChainConfig entries for the ConfigureChainsForLanesFromTopology
// changeset, applies it once, then runs each impl's PostConnect.
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

	orderedSelectors, profiles, err := buildConnectionProfilesFromImpls(impls, blockchains, selectors, e)
	if err != nil {
		return fmt.Errorf("connectAllChains: %w", err)
	}

	partialChains, err := buildPartialChainConfigsFromProfiles(topology, orderedSelectors, profiles, ReconfigureLanesParams{})
	if err != nil {
		return fmt.Errorf("connectAllChains: %w", err)
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

	cfg := ccipChangesets.ConfigureChainsForLanesFromTopologyConfig{
		Topology: topology,
		Chains:   partialChains,
	}
	if err := cs.VerifyPreconditions(*e, cfg); err != nil {
		return fmt.Errorf("connectAllChains: precondition check failed: %w", err)
	}
	if _, err := cs.Apply(*e, cfg); err != nil {
		return fmt.Errorf("connectAllChains: configure chains for lanes: %w", err)
	}

	for _, sel := range orderedSelectors {
		entry := profiles[sel]
		if err := entry.impl.PostConnect(e, sel, entry.remotes); err != nil {
			return fmt.Errorf("post-connect for chain %d: %w", sel, err)
		}
	}

	return nil
}
