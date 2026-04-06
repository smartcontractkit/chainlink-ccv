package ccv

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v2_0_0/operations/committee_verifier"
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

// CommitteeRemotePatches maps local chain selector -> remote chain selector -> committee verifier remote patch.
type CommitteeRemotePatches map[uint64]map[uint64]ccipChangesets.CommitteeVerifierRemoteChainConfig

// ReconfigureLanesParams configures reconfigureLanesFromTopology. Zero value is valid: production Router lanes
// (UseTestRouter false), no committee patches. To use TestRouter on a chain, set
// TestRouterByLane[localSelector][remoteSelector] = true; the deployment must include a TestRouter contract
// (DeployChainContractsPerChainCfg.DeployTestRouter) or the changeset apply can fail.
type ReconfigureLanesParams struct {
	CommitteePatches CommitteeRemotePatches
	TestRouterByLane map[uint64]map[uint64]bool
}

// CommitteeRemotePatchesFromAllowlistArgs builds patches for one local chain from operation-style allowlist args.
func CommitteeRemotePatchesFromAllowlistArgs(
	localSelector uint64,
	args []committee_verifier.AllowlistConfigArgs,
) CommitteeRemotePatches {
	if len(args) == 0 {
		return nil
	}
	inner := make(map[uint64]ccipChangesets.CommitteeVerifierRemoteChainConfig, len(args))
	for _, a := range args {
		added := make([]string, len(a.AddedAllowlistedSenders))
		for i, addr := range a.AddedAllowlistedSenders {
			added[i] = addr.Hex()
		}
		removed := make([]string, len(a.RemovedAllowlistedSenders))
		for i, addr := range a.RemovedAllowlistedSenders {
			removed[i] = addr.Hex()
		}
		inner[a.DestChainSelector] = ccipChangesets.CommitteeVerifierRemoteChainConfig{
			AllowlistEnabled:          a.AllowlistEnabled,
			AddedAllowlistedSenders:   added,
			RemovedAllowlistedSenders: removed,
		}
	}
	return CommitteeRemotePatches{localSelector: inner}
}

// ResetMemoryOperationsBundle replaces the environment operations bundle with a fresh in-memory reporter.
func ResetMemoryOperationsBundle(e *deployment.Environment) {
	if e == nil {
		return
	}
	e.OperationsBundle = operations.NewBundle(
		e.GetContext,
		e.Logger,
		operations.NewMemoryReporter(),
	)
}

// reconfigureLanesFromTopology runs ConfigureChainsForLanesFromTopology once with a PartialChainConfig per chain
// (full peer mesh). Selector-to-impl mapping matches connectAllChains: impls[i] with blockchains[i],
// chain selector from chain ID + ChainFamily(), GetChainLaneProfile(env, sel) on that impl.
func reconfigureLanesFromTopology(
	ctx context.Context,
	e *deployment.Environment,
	topology *ccipOffchain.EnvironmentTopology,
	selectors []uint64,
	blockchains []*blockchain.Input,
	impls []cciptestinterfaces.CCIP17Configuration,
	params ReconfigureLanesParams,
) error {
	if e == nil || topology == nil {
		return fmt.Errorf("reconfigure lanes: environment and topology are required")
	}
	if len(selectors) == 0 {
		return fmt.Errorf("reconfigure lanes: selectors is required")
	}
	if len(blockchains) != len(impls) {
		return fmt.Errorf("reconfigure lanes: %d blockchains and %d impls", len(blockchains), len(impls))
	}
	for _, sel := range selectors {
		if !e.BlockChains.Exists(sel) {
			return fmt.Errorf("reconfigure lanes: chain selector %d not in environment", sel)
		}
	}

	orderedSelectors, profiles, err := buildConnectionProfilesFromImpls(impls, blockchains, selectors, e)
	if err != nil {
		return fmt.Errorf("reconfigure lanes: %w", err)
	}
	if err := assertConnectionProfilesCoverSelectors(orderedSelectors, selectors); err != nil {
		return err
	}

	chains, useTestRouter, err := buildPartialChainConfigsFromProfiles(topology, orderedSelectors, profiles, params)
	if err != nil {
		return fmt.Errorf("reconfigure lanes: %w", err)
	}

	ResetMemoryOperationsBundle(e)
	e.OperationsBundle = operations.NewBundle(
		func() context.Context { return ctx },
		e.Logger,
		operations.NewMemoryReporter(),
	)

	out, err := ccipChangesets.ConfigureChainsForLanesFromTopology(
		ccipAdapters.GetCommitteeVerifierContractRegistry(),
		ccipAdapters.GetChainFamilyRegistry(),
		changesetscore.GetRegistry(),
	).Apply(*e, ccipChangesets.ConfigureChainsForLanesFromTopologyConfig{
		Topology:            topology,
		Chains:              chains,
		UseTestRouter:       useTestRouter,
		AllowOnrampOverride: true,
	})
	if err != nil {
		return err
	}
	if out.DataStore != nil {
		mds := datastore.NewMemoryDataStore()
		if err := mds.Merge(e.DataStore); err != nil {
			return fmt.Errorf("reconfigure lanes: merge env datastore: %w", err)
		}
		if err := mds.Merge(out.DataStore.Seal()); err != nil {
			return fmt.Errorf("reconfigure lanes: merge lane changeset datastore: %w", err)
		}
		e.DataStore = mds.Seal()
	}

	for _, sel := range orderedSelectors {
		entry := profiles[sel]
		if err := entry.impl.PostConnect(e, sel, entry.remotes); err != nil {
			return fmt.Errorf("reconfigure lanes: post-connect for chain %d: %w", sel, err)
		}
	}
	return nil
}
