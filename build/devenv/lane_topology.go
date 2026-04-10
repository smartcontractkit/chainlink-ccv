package ccv

import (
	"fmt"
	"maps"
	"sort"

	chainsel "github.com/smartcontractkit/chain-selectors"

	ccipChangesets "github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/changesets"
	ccipOffchain "github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/offchain"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

// LanePartialConfigOverrides are per-local-chain deltas layered on GetChainLaneProfile baselines.
type LanePartialConfigOverrides struct {
	CommitteeRemotePatches map[uint64]ccipChangesets.CommitteeVerifierRemoteChainConfig
	UseTestRouter          bool
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
	profiles map[uint64]chainProfile,
) ([]ccipChangesets.CommitteeVerifierInputConfig, error) {
	if topology == nil || topology.NOPTopology == nil {
		return nil, fmt.Errorf("topology with NOPTopology is required")
	}

	qualifiers := make([]string, 0, len(topology.NOPTopology.Committees))
	for qualifier := range topology.NOPTopology.Committees {
		qualifiers = append(qualifiers, qualifier)
	}
	sort.Strings(qualifiers)

	verifiers := make([]ccipChangesets.CommitteeVerifierInputConfig, 0, len(qualifiers))
	for _, qualifier := range qualifiers {
		remoteCV := make(map[uint64]ccipChangesets.CommitteeVerifierRemoteChainConfig, len(remoteSelectors))
		for _, rs := range remoteSelectors {
			remoteCV[rs] = ccipChangesets.CommitteeVerifierRemoteChainConfig{
				GasForVerification: profiles[rs].profile.GasForVerification,
			}
		}
		verifiers = append(verifiers, ccipChangesets.CommitteeVerifierInputConfig{
			CommitteeQualifier: qualifier,
			RemoteChains:       mapsCloneCV(remoteCV),
		})
	}
	return verifiers, nil
}

// partialChainConfigFromProfile builds one PartialChainConfig for localSelector
// using ChainLaneProfile data. Committee verifiers use each peer's
// GasForVerification; remote chain configs use the remote's FeeQuoterDestChainConfig
// and the local chain's executor/CCV defaults. LanePartialConfigOverrides are merged.
func partialChainConfigFromProfile(
	localSelector uint64,
	remoteSelectors []uint64,
	topology *ccipOffchain.EnvironmentTopology,
	local cciptestinterfaces.ChainLaneProfile,
	profiles map[uint64]chainProfile,
	o LanePartialConfigOverrides,
) (ccipChangesets.PartialChainConfig, error) {
	committeeVerifiers, err := committeeVerifiersForTopology(topology, remoteSelectors, profiles)
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

	remoteChains := make(map[uint64]ccipChangesets.PartialRemoteChainConfig, len(remoteSelectors))
	for _, rs := range remoteSelectors {
		remoteProfile, ok := profiles[rs]
		if !ok {
			return ccipChangesets.PartialChainConfig{}, fmt.Errorf("missing profile for remote selector %d", rs)
		}
		remote := remoteProfile.profile
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

	return ccipChangesets.PartialChainConfig{
		ChainSelector:      localSelector,
		CommitteeVerifiers: committeeVerifiers,
		RemoteChains:       remoteChains,
	}, nil
}

// buildConnectionProfilesFromImpls resolves selectors from blockchains and impls,
// builds the peer mesh remote selector lists, and loads GetChainLaneProfile per chain.
func buildConnectionProfilesFromImpls(
	impls []cciptestinterfaces.CCIP17Configuration,
	blockchains []*blockchain.Input,
	selectors []uint64,
	e *deployment.Environment,
) ([]uint64, map[uint64]chainProfile, error) {
	if len(blockchains) != len(impls) {
		return nil, nil, fmt.Errorf("connection profiles: mismatched lengths: %d impls and %d blockchains", len(impls), len(blockchains))
	}
	profiles := make(map[uint64]chainProfile, len(impls))
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
		profile, err := impl.GetChainLaneProfile(e, sel)
		if err != nil {
			return nil, nil, fmt.Errorf("get chain lane profile for chain %d: %w", sel, err)
		}
		profiles[sel] = chainProfile{
			remotes: remotes,
			impl:    impl,
			profile: profile,
		}
		orderedSelectors = append(orderedSelectors, sel)
	}
	return orderedSelectors, profiles, nil
}

func assertConnectionProfilesCoverSelectors(orderedSelectors, selectors []uint64) error {
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
		if inner, ok := params.TestRouterByLane[localSel]; ok {
			for _, v := range inner {
				if v {
					o.UseTestRouter = true
					break
				}
			}
		}
	}
	return o
}

// buildPartialChainConfigsFromProfiles builds ConfigureChainsForLanesFromTopology
// partial configs for every chain in orderedSelectors. Zero ReconfigureLanesParams
// matches fresh deploy (production Router lanes).
func buildPartialChainConfigsFromProfiles(
	topology *ccipOffchain.EnvironmentTopology,
	orderedSelectors []uint64,
	profiles map[uint64]chainProfile,
	params ReconfigureLanesParams,
) ([]ccipChangesets.PartialChainConfig, bool, error) {
	useTestRouter := false
	chains := make([]ccipChangesets.PartialChainConfig, 0, len(orderedSelectors))
	for _, localSel := range orderedSelectors {
		entry, ok := profiles[localSel]
		if !ok {
			return nil, false, fmt.Errorf("no profile for local chain %d", localSel)
		}
		o := lanePartialOverridesFromReconfigureParams(params, localSel)
		if o.UseTestRouter {
			useTestRouter = true
		}
		pc, err := partialChainConfigFromProfile(
			localSel,
			entry.remotes,
			topology,
			entry.profile,
			profiles,
			o,
		)
		if err != nil {
			return nil, false, fmt.Errorf("partial chain config for selector %d: %w", localSel, err)
		}
		chains = append(chains, pc)
	}
	return chains, useTestRouter, nil
}
