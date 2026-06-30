package adapters

import (
	"fmt"
	"sort"

	"github.com/Masterminds/semver/v3"

	cldfchain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	cldfops "github.com/smartcontractkit/chainlink-deployments-framework/operations"

	evmadapters "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/adapters"
	"github.com/smartcontractkit/chainlink-ccip/deployment/utils"
	ccvadapters "github.com/smartcontractkit/chainlink-ccip/deployment/v2_0_0/adapters"

	ccvdeploymentadapters "github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

const (
	// LaneRemoteOnRampExtra and LaneRemoteOffRampExtra are optional FamilyExtras
	// keys (string hex addresses) carrying the remote chain's OnRamp and OffRamp
	// addresses. The topology-free LaneConfigInput passes only the local chain's
	// ExistingAddresses, so the remote ramps — which the OffRamp source config
	// (allowed remote OnRamps) and the OnRamp dest config (remote OffRamp) cross-
	// reference — are not otherwise available to this adapter. When absent, the
	// underlying ConfigureChainForLanes sequence preserves whatever is already on
	// chain (correct for router promotion and idempotent re-runs; for a brand-new
	// lane these references stay unset until supplied).
	LaneRemoteOnRampExtra  = "remoteOnRamp"
	LaneRemoteOffRampExtra = "remoteOffRamp"
)

// EVMLaneConfigAdapter implements ccvdeploymentadapters.LaneConfigAdapter for EVM
// chains. It wires a single chain into one or more lanes by reusing the existing
// EVM ConfigureChainForLanes sequence: it configures the local OnRamp, OffRamp,
// FeeQuoter, Executor and Router for each remote chain, and references the chosen
// committee verifiers (by qualifier) on the ramps and in the verifier resolver.
//
// It deliberately does NOT manage committee-verifier signature quorums (signers /
// threshold). In the topology-free model those are owned by the dedicated
// committee changesets (AddNOPToCommittee / Increase- / DecreaseThreshold via
// CommitteeVerifierOnchainAdapter.ApplySignatureConfigs). Accordingly every
// CommitteeVerifierRemoteChainConfig it emits carries an empty SignatureConfig,
// which the ConfigureChainForLanes sequence treats as "do not touch signatures".
//
// The underlying sequence is idempotent: re-running reconciles drifted config
// rather than duplicating it.
type EVMLaneConfigAdapter struct{}

var _ ccvdeploymentadapters.LaneConfigAdapter = (*EVMLaneConfigAdapter)(nil)

// family and cvContracts are stateless reusable resolvers/defaults providers from
// the EVM chain-family adapter layer.
var (
	laneChainFamily = &evmadapters.ChainFamilyAdapter{}
	laneCVContracts = &evmadapters.EVMCommitteeVerifierContractAdapter{}
)

var evmConfigureLane = cldfops.NewSequence(
	"evm-configure-lane",
	semver.MustParse("2.0.0"),
	"Chain-agnostic wrapper that resolves topology-free LaneConfigInput into the EVM ConfigureChainForLanes input",
	func(b cldfops.Bundle, chains cldfchain.BlockChains, input ccvdeploymentadapters.LaneConfigInput) (ccvdeploymentadapters.LaneConfigOutput, error) {
		if _, ok := chains.EVMChains()[input.ChainSelector]; !ok {
			return ccvdeploymentadapters.LaneConfigOutput{},
				fmt.Errorf("EVM chain not found for selector %d", input.ChainSelector)
		}

		cfInput, err := toEVMConfigureChainForLanesInput(input)
		if err != nil {
			return ccvdeploymentadapters.LaneConfigOutput{},
				fmt.Errorf("failed to build EVM lane config input for chain %d: %w", input.ChainSelector, err)
		}

		report, err := cldfops.ExecuteSequence(b, laneChainFamily.ConfigureChainForLanes(), chains, cfInput)
		if err != nil {
			return ccvdeploymentadapters.LaneConfigOutput{},
				fmt.Errorf("EVM ConfigureChainForLanes failed for chain %d: %w", input.ChainSelector, err)
		}

		return ccvdeploymentadapters.LaneConfigOutput{
			Addresses: report.Output.Addresses,
			BatchOps:  report.Output.BatchOps,
		}, nil
	},
)

func (a *EVMLaneConfigAdapter) ConfigureLane() *cldfops.Sequence[ccvdeploymentadapters.LaneConfigInput, ccvdeploymentadapters.LaneConfigOutput, cldfchain.BlockChains] {
	return evmConfigureLane
}

// toEVMConfigureChainForLanesInput resolves the local chain's contract addresses
// and per-remote lane settings from the topology-free input into the EVM
// ConfigureChainForLanesInput expected by the underlying sequence.
func toEVMConfigureChainForLanesInput(
	input ccvdeploymentadapters.LaneConfigInput,
) (ccvadapters.ConfigureChainForLanesInput, error) {
	local := input.ChainSelector
	ds := laneLocalDataStore(input.ExistingAddresses)

	router, err := resolveLaneRouter(ds, local, input.UseTestRouter)
	if err != nil {
		return ccvadapters.ConfigureChainForLanesInput{}, err
	}
	onRamp, err := laneChainFamily.GetOnRampAddress(ds, local)
	if err != nil {
		return ccvadapters.ConfigureChainForLanesInput{}, fmt.Errorf("resolve local OnRamp: %w", err)
	}
	offRamp, err := laneChainFamily.GetOffRampAddress(ds, local)
	if err != nil {
		return ccvadapters.ConfigureChainForLanesInput{}, fmt.Errorf("resolve local OffRamp: %w", err)
	}
	feeQuoter, err := laneChainFamily.GetFQAddress(ds, local)
	if err != nil {
		return ccvadapters.ConfigureChainForLanesInput{}, fmt.Errorf("resolve local FeeQuoter: %w", err)
	}

	remoteChains := make(map[uint64]ccvadapters.RemoteChainConfig[[]byte, string], len(input.RemoteChains))
	// committeeVerifiers accumulates one config per referenced CCV qualifier so the
	// sequence can register resolver routing and remote-chain settings for each.
	committeeVerifiers := make(map[string]*ccvadapters.CommitteeVerifierConfig[datastore.AddressRef])

	for remoteSel, rlc := range input.RemoteChains {
		remoteCfg, err := resolveRemoteLaneConfig(ds, local, remoteSel, rlc)
		if err != nil {
			return ccvadapters.ConfigureChainForLanesInput{}, fmt.Errorf("remote chain %d: %w", remoteSel, err)
		}
		remoteChains[remoteSel] = remoteCfg

		// Every committee verifier referenced inbound or outbound for this remote
		// must be configured (resolver routing + remote chain settings).
		for _, qualifier := range dedupeQualifiers(rlc.InboundCCVQualifiers, rlc.OutboundCCVQualifiers) {
			if err := addCommitteeVerifierRemote(committeeVerifiers, ds, local, remoteSel, qualifier); err != nil {
				return ccvadapters.ConfigureChainForLanesInput{}, fmt.Errorf("remote chain %d: %w", remoteSel, err)
			}
		}
	}

	return ccvadapters.ConfigureChainForLanesInput{
		ChainSelector: local,
		// AllowOnrampOverride stays false: switching which router an OnRamp points
		// to (test→prod promotion) is always allowed by the sequence, but replacing
		// an existing OnRamp address for a destination must go through the dedicated
		// migration changeset rather than a lane reconfiguration.
		AllowOnrampOverride: false,
		Router:              router,
		OnRamp:              onRamp,
		FeeQuoter:           feeQuoter,
		OffRamp:             offRamp,
		CommitteeVerifiers:  committeeVerifierConfigs(committeeVerifiers),
		RemoteChains:        remoteChains,
	}, nil
}

// resolveRemoteLaneConfig builds the EVM per-remote lane config, layering caller
// overrides from RemoteLaneConfig on top of the chain-family adapter defaults and
// resolving the executor and committee-verifier (resolver) addresses by qualifier.
func resolveRemoteLaneConfig(
	ds datastore.DataStore,
	local, remote uint64,
	rlc ccvdeploymentadapters.RemoteLaneConfig,
) (ccvadapters.RemoteChainConfig[[]byte, string], error) {
	executorQualifier := rlc.ExecutorQualifier
	if executorQualifier == "" {
		executorQualifier = DefaultQualifier
	}
	executorAddr, err := laneChainFamily.ResolveExecutor(ds, local, executorQualifier)
	if err != nil {
		return ccvadapters.RemoteChainConfig[[]byte, string]{}, fmt.Errorf("resolve executor (qualifier %q): %w", executorQualifier, err)
	}

	inboundCCVs, err := resolveResolverAddresses(ds, local, rlc.InboundCCVQualifiers)
	if err != nil {
		return ccvadapters.RemoteChainConfig[[]byte, string]{}, fmt.Errorf("resolve inbound CCVs: %w", err)
	}
	outboundCCVs, err := resolveResolverAddresses(ds, local, rlc.OutboundCCVQualifiers)
	if err != nil {
		return ccvadapters.RemoteChainConfig[[]byte, string]{}, fmt.Errorf("resolve outbound CCVs: %w", err)
	}

	remoteOnRamps, remoteOffRamp, err := resolveRemoteRamps(ds, remote, rlc.FamilyExtras)
	if err != nil {
		return ccvadapters.RemoteChainConfig[[]byte, string]{}, err
	}

	fqConfig := laneChainFamily.GetDefaultFeeQuoterDestChainConfig(local, remote, laneChainFamily.GetChainFamilySelector())
	fqConfig.ChainFamilySelector = laneChainFamily.GetChainFamilySelector()

	defaults := laneChainFamily.GetDefaultRemoteChainConfig(local, remote)
	allowTrafficFrom := utils.Coalesce(rlc.AllowTrafficFrom, defaults.AllowTrafficFrom)
	tokenReceiverAllowed := utils.Coalesce(rlc.TokenReceiverAllowed, defaults.TokenReceiverAllowed)

	return ccvadapters.RemoteChainConfig[[]byte, string]{
		AllowTrafficFrom:          &allowTrafficFrom,
		OnRamps:                   remoteOnRamps,
		OffRamp:                   remoteOffRamp,
		DefaultExecutor:           executorAddr,
		DefaultInboundCCVs:        inboundCCVs,
		DefaultOutboundCCVs:       outboundCCVs,
		FeeQuoterDestChainConfig:  fqConfig,
		ExecutorDestChainConfig:   defaults.ExecutorDestChainConfig,
		AddressBytesLength:        laneChainFamily.GetAddressBytesLength(),
		BaseExecutionGasCost:      utils.Coalesce(rlc.BaseExecutionGasCost, defaults.BaseExecutionGasCost),
		TokenReceiverAllowed:      &tokenReceiverAllowed,
		MessageNetworkFeeUSDCents: utils.Coalesce(rlc.MessageNetworkFeeUSDCents, defaults.MessageNetworkFeeUSDCents),
		TokenNetworkFeeUSDCents:   utils.Coalesce(rlc.TokenNetworkFeeUSDCents, defaults.TokenNetworkFeeUSDCents),
	}, nil
}

// addCommitteeVerifierRemote ensures committeeVerifiers has an entry for qualifier
// and records remote as one of the chains it serves, using chain-family defaults
// and an empty SignatureConfig (signatures are owned by the committee changesets).
func addCommitteeVerifierRemote(
	committeeVerifiers map[string]*ccvadapters.CommitteeVerifierConfig[datastore.AddressRef],
	ds datastore.DataStore,
	local, remote uint64,
	qualifier string,
) error {
	cfg, ok := committeeVerifiers[qualifier]
	if !ok {
		refs, err := laneCVContracts.ResolveCommitteeVerifierContracts(ds, local, qualifier)
		if err != nil {
			return fmt.Errorf("resolve committee verifier (qualifier %q): %w", qualifier, err)
		}
		cfg = &ccvadapters.CommitteeVerifierConfig[datastore.AddressRef]{
			CommitteeVerifier:     refs,
			RemoteChains:          make(map[uint64]ccvadapters.CommitteeVerifierRemoteChainConfig),
			AllowedFinalityConfig: laneChainFamily.GetDefaultFinalityConfig(),
		}
		committeeVerifiers[qualifier] = cfg
	}

	cvDefaults := laneChainFamily.GetDefaultCommitteeVerifierRemoteChainConfig()
	cfg.RemoteChains[remote] = ccvadapters.CommitteeVerifierRemoteChainConfig{
		AllowlistEnabled:   cvDefaults.AllowlistEnabled,
		FeeUSDCents:        cvDefaults.FeeUSDCents,
		GasForVerification: cvDefaults.GasForVerification,
		PayloadSizeBytes:   cvDefaults.PayloadSizeBytes,
		// SignatureConfig intentionally left empty — see EVMLaneConfigAdapter doc.
	}
	return nil
}

// resolveResolverAddresses maps committee-verifier qualifiers to their verifier
// resolver addresses (the address referenced as a CCV on the ramps), preserving
// order. Duplicate qualifiers collapse to a single address.
func resolveResolverAddresses(ds datastore.DataStore, chainSelector uint64, qualifiers []string) ([]string, error) {
	out := make([]string, 0, len(qualifiers))
	seen := make(map[string]struct{}, len(qualifiers))
	for _, qualifier := range qualifiers {
		if _, dup := seen[qualifier]; dup {
			continue
		}
		seen[qualifier] = struct{}{}
		refs, err := laneCVContracts.GetCommitteeVerifierResolver(ds, chainSelector, qualifier)
		if err != nil {
			return nil, fmt.Errorf("resolver for qualifier %q: %w", qualifier, err)
		}
		for _, ref := range refs {
			out = append(out, ref.Address)
		}
	}
	return out, nil
}

// resolveLaneRouter resolves the production Router or, when useTestRouter is set,
// the TestRouter address for the chain.
func resolveLaneRouter(ds datastore.DataStore, chainSelector uint64, useTestRouter bool) ([]byte, error) {
	if useTestRouter {
		addr, err := laneChainFamily.GetTestRouter(ds, chainSelector)
		if err != nil {
			return nil, fmt.Errorf("resolve local TestRouter: %w", err)
		}
		return addr, nil
	}
	addr, err := laneChainFamily.GetRouterAddress(ds, chainSelector)
	if err != nil {
		return nil, fmt.Errorf("resolve local Router: %w", err)
	}
	return addr, nil
}

// resolveRemoteRamps determines the remote chain's OnRamp/OffRamp addresses used to
// cross-reference the lane (the remote OnRamp on the local OffRamp's allowed-source
// set, and the remote OffRamp on the local OnRamp's dest config). Resolution order:
//  1. An explicit FamilyExtras override (operator-supplied) wins.
//  2. Otherwise resolve from the datastore — LaneConfigInput.ExistingAddresses now
//     carries the remote chain's addresses, matching the legacy topology changeset.
//  3. If neither is available, leave nil so the underlying sequence preserves the
//     current on-chain references.
func resolveRemoteRamps(ds datastore.DataStore, remote uint64, extras map[string]any) ([][]byte, []byte, error) {
	extraOnRamps, extraOffRamp, err := laneRemoteRampsFromExtras(extras)
	if err != nil {
		return nil, nil, err
	}

	onRamps := extraOnRamps
	if len(onRamps) == 0 {
		if addr, rerr := laneChainFamily.GetOnRampAddress(ds, remote); rerr == nil {
			onRamps = [][]byte{addr}
		}
	}

	offRamp := extraOffRamp
	if len(offRamp) == 0 {
		if addr, rerr := laneChainFamily.GetOffRampAddress(ds, remote); rerr == nil {
			offRamp = addr
		}
	}

	return onRamps, offRamp, nil
}

// laneRemoteRampsFromExtras reads the optional remote OnRamp/OffRamp addresses from
// FamilyExtras. Absent keys yield nil. These act as an explicit override over
// datastore resolution (see resolveRemoteRamps). See the LaneRemoteOnRampExtra doc.
func laneRemoteRampsFromExtras(extras map[string]any) (onRamps [][]byte, offRamp []byte, err error) {
	if onRampHex, ok, perr := extraString(extras, LaneRemoteOnRampExtra); perr != nil {
		return nil, nil, perr
	} else if ok {
		addr, perr := parseRequiredNonZeroHexAddress(onRampHex, LaneRemoteOnRampExtra)
		if perr != nil {
			return nil, nil, perr
		}
		onRamps = [][]byte{addr.Bytes()}
	}
	if offRampHex, ok, perr := extraString(extras, LaneRemoteOffRampExtra); perr != nil {
		return nil, nil, perr
	} else if ok {
		addr, perr := parseRequiredNonZeroHexAddress(offRampHex, LaneRemoteOffRampExtra)
		if perr != nil {
			return nil, nil, perr
		}
		offRamp = addr.Bytes()
	}
	return onRamps, offRamp, nil
}

// laneLocalDataStore reconstructs a sealed datastore from the local chain's
// ExistingAddresses so the EVM chain-family resolvers (which take a DataStore) can
// be reused as-is.
func laneLocalDataStore(refs []datastore.AddressRef) datastore.DataStore {
	ms := datastore.NewMemoryDataStore()
	for _, ref := range refs {
		_ = ms.Addresses().Add(ref)
	}
	return ms.Seal()
}

// dedupeQualifiers returns the union of the given qualifier lists in stable
// (sorted) order, dropping empties and duplicates.
func dedupeQualifiers(lists ...[]string) []string {
	seen := make(map[string]struct{})
	for _, list := range lists {
		for _, q := range list {
			if q == "" {
				continue
			}
			seen[q] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for q := range seen {
		out = append(out, q)
	}
	sort.Strings(out)
	return out
}

// committeeVerifierConfigs flattens the per-qualifier map into the slice the
// sequence consumes, ordered by qualifier for determinism.
func committeeVerifierConfigs(byQualifier map[string]*ccvadapters.CommitteeVerifierConfig[datastore.AddressRef]) []ccvadapters.CommitteeVerifierConfig[datastore.AddressRef] {
	qualifiers := make([]string, 0, len(byQualifier))
	for q := range byQualifier {
		qualifiers = append(qualifiers, q)
	}
	sort.Strings(qualifiers)
	out := make([]ccvadapters.CommitteeVerifierConfig[datastore.AddressRef], 0, len(byQualifier))
	for _, q := range qualifiers {
		out = append(out, *byQualifier[q])
	}
	return out
}
