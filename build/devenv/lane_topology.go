package ccv

import (
	"fmt"
	"maps"

	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccip/deployment/lanes"
	ccipChangesets "github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/changesets"
	ccipOffchain "github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/offchain"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

// PeerLaneSnapshot is the reconcile-time view of a remote chain for lane mesh assembly:
// destination chain definition and the committee-verifier defaults that peer reports for remotes.
type PeerLaneSnapshot struct {
	ChainDef        lanes.ChainDefinition
	CommitteeRemote ccipChangesets.CommitteeVerifierRemoteChainConfig
}

// LanePartialConfigOverrides are per-local-chain deltas layered on GetConnectionProfile baselines.
type LanePartialConfigOverrides struct {
	CommitteeRemotePatches map[uint64]ccipChangesets.CommitteeVerifierRemoteChainConfig
	TestRouterByRemote     map[uint64]bool
}

func mapsCloneCV(m map[uint64]ccipChangesets.CommitteeVerifierRemoteChainConfig) map[uint64]ccipChangesets.CommitteeVerifierRemoteChainConfig {
	out := make(map[uint64]ccipChangesets.CommitteeVerifierRemoteChainConfig, len(m))
	maps.Copy(out, m)
	return out
}

func mergeCommitteeVerifierRemoteChainConfigForReconcile(
	base, patch ccipChangesets.CommitteeVerifierRemoteChainConfig,
) ccipChangesets.CommitteeVerifierRemoteChainConfig {
	out := base
	out.AllowlistEnabled = patch.AllowlistEnabled
	if len(patch.AddedAllowlistedSenders) > 0 {
		out.AddedAllowlistedSenders = patch.AddedAllowlistedSenders
	}
	if len(patch.RemovedAllowlistedSenders) > 0 {
		out.RemovedAllowlistedSenders = patch.RemovedAllowlistedSenders
	}
	if patch.GasForVerification != 0 {
		out.GasForVerification = patch.GasForVerification
	}
	if patch.FeeUSDCents != 0 {
		out.FeeUSDCents = patch.FeeUSDCents
	}
	if patch.PayloadSizeBytes != 0 {
		out.PayloadSizeBytes = patch.PayloadSizeBytes
	}
	return out
}

func committeeVerifiersForTopology(
	topology *ccipOffchain.EnvironmentTopology,
	remoteSelectors []uint64,
	remoteCV map[uint64]ccipChangesets.CommitteeVerifierRemoteChainConfig,
) ([]ccipChangesets.CommitteeVerifierInputConfig, error) {
	if topology == nil || topology.NOPTopology == nil {
		return nil, fmt.Errorf("topology with NOPTopology is required")
	}
	remoteChainConfigs := make(map[uint64]ccipChangesets.CommitteeVerifierRemoteChainConfig, len(remoteSelectors))
	for _, rs := range remoteSelectors {
		cfg, ok := remoteCV[rs]
		if !ok {
			return nil, fmt.Errorf("missing committee verifier profile for remote selector %d", rs)
		}
		remoteChainConfigs[rs] = cfg
	}
	verifiers := make([]ccipChangesets.CommitteeVerifierInputConfig, 0, len(topology.NOPTopology.Committees))
	for qualifier := range topology.NOPTopology.Committees {
		verifiers = append(verifiers, ccipChangesets.CommitteeVerifierInputConfig{
			CommitteeQualifier: qualifier,
			RemoteChains:       mapsCloneCV(remoteChainConfigs),
		})
	}
	return verifiers, nil
}

// partialChainConfigForTopologyPeers builds one PartialChainConfig for localSelector using the same
// lane and committee structure as connectAllChains: remote lanes use each peer's ChainDefinition from
// GetConnectionProfile; committee verifiers use each peer's CommitteeVerifierRemoteChainConfig;
// then LanePartialConfigOverrides are merged.
func partialChainConfigForTopologyPeers(
	localSelector uint64,
	remoteSelectors []uint64,
	topology *ccipOffchain.EnvironmentTopology,
	localChain lanes.ChainDefinition,
	remotes map[uint64]PeerLaneSnapshot,
	o LanePartialConfigOverrides,
) (ccipChangesets.PartialChainConfig, error) {
	remoteCV := make(map[uint64]ccipChangesets.CommitteeVerifierRemoteChainConfig, len(remoteSelectors))
	for _, rs := range remoteSelectors {
		snap, ok := remotes[rs]
		if !ok {
			return ccipChangesets.PartialChainConfig{}, fmt.Errorf("missing peer snapshot for remote selector %d", rs)
		}
		remoteCV[rs] = snap.CommitteeRemote
	}
	committeeVerifiers, err := committeeVerifiersForTopology(topology, remoteSelectors, remoteCV)
	if err != nil {
		return ccipChangesets.PartialChainConfig{}, err
	}
	if len(o.CommitteeRemotePatches) > 0 {
		for i := range committeeVerifiers {
			merged := make(map[uint64]ccipChangesets.CommitteeVerifierRemoteChainConfig, len(committeeVerifiers[i].RemoteChains))
			for rs, cfg := range committeeVerifiers[i].RemoteChains {
				merged[rs] = cfg
				if patch, ok := o.CommitteeRemotePatches[rs]; ok {
					merged[rs] = mergeCommitteeVerifierRemoteChainConfigForReconcile(merged[rs], patch)
				}
			}
			committeeVerifiers[i].RemoteChains = merged
		}
	}
	remoteChains := make(map[uint64]ccipChangesets.RemoteLaneConfig, len(remoteSelectors))
	for _, rs := range remoteSelectors {
		snap, ok := remotes[rs]
		if !ok {
			return ccipChangesets.PartialChainConfig{}, fmt.Errorf("missing peer snapshot for remote selector %d", rs)
		}
		tr := false
		if o.TestRouterByRemote != nil {
			tr = o.TestRouterByRemote[rs]
		}
		remoteChains[rs] = ccipChangesets.RemoteLaneConfig{
			Chain:      snap.ChainDef,
			TestRouter: tr,
		}
	}
	cd := localChain
	return ccipChangesets.PartialChainConfig{
		ChainSelector:                     localSelector,
		CommitteeVerifiers:                committeeVerifiers,
		DefaultInboundCCVs:                cd.DefaultInboundCCVs,
		DefaultOutboundCCVs:               cd.DefaultOutboundCCVs,
		DefaultExecutor:                   cd.DefaultExecutor,
		FeeQuoterDestChainConfigOverrides: cd.FeeQuoterDestChainConfigOverrides,
		ExecutorDestChainConfig:           cd.ExecutorDestChainConfig,
		AddressBytesLength:                cd.AddressBytesLength,
		BaseExecutionGasCost:              cd.BaseExecutionGasCost,
		RemoteChains:                      remoteChains,
	}, nil
}

// buildConnectionEntriesFromImpls resolves selectors from blockchains and impls, builds the peer mesh
// remote selector lists from the given selectors slice, and loads GetConnectionProfile per chain.
func buildConnectionEntriesFromImpls(
	impls []cciptestinterfaces.CCIP17Configuration,
	blockchains []*blockchain.Input,
	selectors []uint64,
) ([]uint64, map[uint64]chainEntry, error) {
	if len(blockchains) != len(impls) {
		return nil, nil, fmt.Errorf("connection entries: mismatched lengths: %d impls and %d blockchains", len(impls), len(blockchains))
	}
	entries := make(map[uint64]chainEntry, len(impls))
	orderedSelectors := make([]uint64, 0, len(impls))
	for i, impl := range impls {
		networkInfo, err := chainsel.GetChainDetailsByChainIDAndFamily(blockchains[i].ChainID, impl.ChainFamily())
		if err != nil {
			return nil, nil, fmt.Errorf("chain %d: %w", i, err)
		}
		sel := networkInfo.ChainSelector
		remotes := make([]uint64, 0, len(selectors))
		for _, s := range selectors {
			if s != sel {
				remotes = append(remotes, s)
			}
		}
		chainDef, cvConfig, err := impl.GetConnectionProfile(sel)
		if err != nil {
			return nil, nil, fmt.Errorf("get connection profile for chain %d: %w", sel, err)
		}
		entries[sel] = chainEntry{
			remoteSelectors: remotes,
			impl:            impl,
			chainDef:        chainDef,
			cvConfig:        cvConfig,
		}
		orderedSelectors = append(orderedSelectors, sel)
	}
	return orderedSelectors, entries, nil
}

func assertConnectionEntriesCoverSelectors(
	orderedSelectors []uint64,
	entries map[uint64]chainEntry,
	selectors []uint64,
) error {
	want := make(map[uint64]struct{}, len(selectors))
	for _, s := range selectors {
		want[s] = struct{}{}
	}
	got := make(map[uint64]struct{}, len(orderedSelectors))
	for _, s := range orderedSelectors {
		got[s] = struct{}{}
	}
	if len(want) != len(got) {
		return fmt.Errorf("reconfigure lanes: selectors set does not match configured chains")
	}
	for s := range want {
		if _, ok := got[s]; !ok {
			return fmt.Errorf("reconfigure lanes: selector %d not found in blockchains/impls", s)
		}
	}
	return nil
}

func lanePartialOverridesFromReconfigureParams(params ReconfigureLanesParams, localSel uint64) LanePartialConfigOverrides {
	var o LanePartialConfigOverrides
	if params.CommitteePatches != nil {
		if inner, ok := params.CommitteePatches[localSel]; ok && len(inner) > 0 {
			o.CommitteeRemotePatches = inner
		}
	}
	if params.TestRouterByLane != nil {
		if inner, ok := params.TestRouterByLane[localSel]; ok && len(inner) > 0 {
			o.TestRouterByRemote = inner
		}
	}
	return o
}

// buildPartialChainConfigsFromConnectionGraph builds ConfigureChainsForLanesFromTopology partial configs
// for every chain in orderedSelectors. Zero ReconfigureLanesParams matches fresh deploy (production Router lanes).
func buildPartialChainConfigsFromConnectionGraph(
	topology *ccipOffchain.EnvironmentTopology,
	orderedSelectors []uint64,
	entries map[uint64]chainEntry,
	params ReconfigureLanesParams,
) ([]ccipChangesets.PartialChainConfig, error) {
	chains := make([]ccipChangesets.PartialChainConfig, 0, len(orderedSelectors))
	for _, localSel := range orderedSelectors {
		entry := entries[localSel]
		remotes := make(map[uint64]PeerLaneSnapshot, len(entry.remoteSelectors))
		for _, rs := range entry.remoteSelectors {
			remoteEntry, ok := entries[rs]
			if !ok {
				return nil, fmt.Errorf("missing chain definition for remote selector %d (referenced from chain %d)", rs, localSel)
			}
			remotes[rs] = PeerLaneSnapshot{
				ChainDef:        remoteEntry.chainDef,
				CommitteeRemote: remoteEntry.cvConfig,
			}
		}
		o := lanePartialOverridesFromReconfigureParams(params, localSel)
		pc, err := partialChainConfigForTopologyPeers(
			localSel,
			entry.remoteSelectors,
			topology,
			entry.chainDef,
			remotes,
			o,
		)
		if err != nil {
			return nil, fmt.Errorf("partial chain config for selector %d: %w", localSel, err)
		}
		chains = append(chains, pc)
	}
	return chains, nil
}
