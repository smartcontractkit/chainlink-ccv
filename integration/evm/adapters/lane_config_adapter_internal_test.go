package adapters

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_2_0/operations/router"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/committee_verifier"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/executor"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/fee_quoter"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/offramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/onramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/sequences"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/versioned_verifier_resolver"

	ccvdeploymentadapters "github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

const (
	laneLocalSel  = uint64(5009297550715157269)
	laneRemoteSel = uint64(4949039107694359620)

	laneRouterAddr     = "0x0000000000000000000000000000000000000001"
	laneTestRouterAddr = "0x0000000000000000000000000000000000000002"
	laneOnRampAddr     = "0x0000000000000000000000000000000000000003"
	laneOffRampAddr    = "0x0000000000000000000000000000000000000004"
	laneFeeQuoterAddr  = "0x0000000000000000000000000000000000000005"
	laneExecutorAddr   = "0x0000000000000000000000000000000000000006"
	laneVerifierAddr   = "0x0000000000000000000000000000000000000007"
	laneResolverAddr   = "0x0000000000000000000000000000000000000008"

	laneRemoteOnRampAddr  = "0x0000000000000000000000000000000000000009"
	laneRemoteOffRampAddr = "0x000000000000000000000000000000000000000A"
)

// laneRefs builds the full set of local-chain address refs the lane adapter needs
// to resolve. Individual entries can be dropped to exercise the error branches.
func laneRefs() []datastore.AddressRef {
	return []datastore.AddressRef{
		{ChainSelector: laneLocalSel, Type: datastore.ContractType(router.ContractType), Version: router.Version, Address: laneRouterAddr},
		{ChainSelector: laneLocalSel, Type: datastore.ContractType(router.TestRouterContractType), Version: router.Version, Address: laneTestRouterAddr},
		{ChainSelector: laneLocalSel, Type: datastore.ContractType(onramp.ContractType), Version: onramp.Version, Address: laneOnRampAddr},
		{ChainSelector: laneLocalSel, Type: datastore.ContractType(offramp.ContractType), Version: offramp.Version, Address: laneOffRampAddr},
		{ChainSelector: laneLocalSel, Type: datastore.ContractType(fee_quoter.ContractType), Version: fee_quoter.Version, Address: laneFeeQuoterAddr},
		{ChainSelector: laneLocalSel, Type: datastore.ContractType(sequences.ExecutorProxyType), Version: executor.Version, Qualifier: DefaultQualifier, Address: laneExecutorAddr},
		{ChainSelector: laneLocalSel, Type: datastore.ContractType(committee_verifier.ContractType), Version: committee_verifier.Version, Qualifier: DefaultQualifier, Address: laneVerifierAddr},
		{ChainSelector: laneLocalSel, Type: datastore.ContractType(versioned_verifier_resolver.CommitteeVerifierResolverType), Version: versioned_verifier_resolver.Version, Qualifier: DefaultQualifier, Address: laneResolverAddr},
		// Remote chain ramps — the adapter resolves these for cross-referencing the lane.
		{ChainSelector: laneRemoteSel, Type: datastore.ContractType(onramp.ContractType), Version: onramp.Version, Address: laneRemoteOnRampAddr},
		{ChainSelector: laneRemoteSel, Type: datastore.ContractType(offramp.ContractType), Version: offramp.Version, Address: laneRemoteOffRampAddr},
	}
}

func laneInput(refs []datastore.AddressRef, mutate func(*ccvdeploymentadapters.LaneConfigInput)) ccvdeploymentadapters.LaneConfigInput {
	in := ccvdeploymentadapters.LaneConfigInput{
		ChainSelector:     laneLocalSel,
		ExistingAddresses: refs,
		RemoteChains: map[uint64]ccvdeploymentadapters.RemoteLaneConfig{
			laneRemoteSel: {
				ExecutorQualifier:     DefaultQualifier,
				InboundCCVQualifiers:  []string{DefaultQualifier},
				OutboundCCVQualifiers: []string{DefaultQualifier},
			},
		},
	}
	if mutate != nil {
		mutate(&in)
	}
	return in
}

// TestToEVMConfigureChainForLanesInput_HappyPath proves the topology-free
// LaneConfigInput is resolved into the EVM ConfigureChainForLanesInput: local
// contracts by chain, executor + committee-verifier (resolver) addresses by
// qualifier, with defaults applied — and crucially with an empty SignatureConfig
// so the sequence does not touch the committee verifier's signer quorum.
func TestToEVMConfigureChainForLanesInput_HappyPath(t *testing.T) {
	out, err := toEVMConfigureChainForLanesInput(laneInput(laneRefs(), nil))
	require.NoError(t, err)

	require.Equal(t, common.HexToAddress(laneRouterAddr).Bytes(), out.Router)
	require.Equal(t, common.HexToAddress(laneOnRampAddr).Bytes(), out.OnRamp)
	require.Equal(t, common.HexToAddress(laneOffRampAddr).Bytes(), out.OffRamp)
	require.Equal(t, common.HexToAddress(laneFeeQuoterAddr).Bytes(), out.FeeQuoter)
	require.False(t, out.AllowOnrampOverride)

	rc, ok := out.RemoteChains[laneRemoteSel]
	require.True(t, ok)
	require.Equal(t, laneExecutorAddr, rc.DefaultExecutor)
	require.Equal(t, []string{laneResolverAddr}, rc.DefaultInboundCCVs)
	require.Equal(t, []string{laneResolverAddr}, rc.DefaultOutboundCCVs)
	// Remote ramps are resolved from the datastore (no FamilyExtras needed).
	require.Equal(t, [][]byte{common.HexToAddress(laneRemoteOnRampAddr).Bytes()}, rc.OnRamps)
	require.Equal(t, common.HexToAddress(laneRemoteOffRampAddr).Bytes(), rc.OffRamp)
	require.Equal(t, laneChainFamily.GetChainFamilySelector(), rc.FeeQuoterDestChainConfig.ChainFamilySelector)
	require.Equal(t, laneChainFamily.GetAddressBytesLength(), rc.AddressBytesLength)
	require.NotNil(t, rc.AllowTrafficFrom)

	require.Len(t, out.CommitteeVerifiers, 1)
	cv := out.CommitteeVerifiers[0]
	require.Len(t, cv.CommitteeVerifier, 2) // [verifier, resolver]
	cvRemote, ok := cv.RemoteChains[laneRemoteSel]
	require.True(t, ok)
	require.Empty(t, cvRemote.SignatureConfig.Signers, "lane config must not set signers")
	require.Zero(t, cvRemote.SignatureConfig.Threshold, "lane config must not set threshold")
}

// TestToEVMConfigureChainForLanesInput_UseTestRouter proves the TestRouter is
// selected when UseTestRouter is set.
func TestToEVMConfigureChainForLanesInput_UseTestRouter(t *testing.T) {
	out, err := toEVMConfigureChainForLanesInput(laneInput(laneRefs(), func(in *ccvdeploymentadapters.LaneConfigInput) {
		in.UseTestRouter = true
	}))
	require.NoError(t, err)
	require.Equal(t, common.HexToAddress(laneTestRouterAddr).Bytes(), out.Router)
}

// TestToEVMConfigureChainForLanesInput_Overrides proves caller overrides on the
// RemoteLaneConfig take precedence over the chain-family defaults.
func TestToEVMConfigureChainForLanesInput_Overrides(t *testing.T) {
	allow := false
	gas := uint32(123456)
	out, err := toEVMConfigureChainForLanesInput(laneInput(laneRefs(), func(in *ccvdeploymentadapters.LaneConfigInput) {
		rc := in.RemoteChains[laneRemoteSel]
		rc.AllowTrafficFrom = &allow
		rc.BaseExecutionGasCost = &gas
		in.RemoteChains[laneRemoteSel] = rc
	}))
	require.NoError(t, err)
	rc := out.RemoteChains[laneRemoteSel]
	require.NotNil(t, rc.AllowTrafficFrom)
	require.False(t, *rc.AllowTrafficFrom)
	require.Equal(t, gas, rc.BaseExecutionGasCost)
}

// TestToEVMConfigureChainForLanesInput_RemoteRampsFromExtras proves remote ramp
// addresses supplied via FamilyExtras are threaded into the remote chain config.
func TestToEVMConfigureChainForLanesInput_RemoteRampsFromExtras(t *testing.T) {
	remoteOnRamp := "0x00000000000000000000000000000000000000aa"
	remoteOffRamp := "0x00000000000000000000000000000000000000bb"
	out, err := toEVMConfigureChainForLanesInput(laneInput(laneRefs(), func(in *ccvdeploymentadapters.LaneConfigInput) {
		rc := in.RemoteChains[laneRemoteSel]
		rc.FamilyExtras = map[string]any{
			LaneRemoteOnRampExtra:  remoteOnRamp,
			LaneRemoteOffRampExtra: remoteOffRamp,
		}
		in.RemoteChains[laneRemoteSel] = rc
	}))
	require.NoError(t, err)
	rc := out.RemoteChains[laneRemoteSel]
	require.Equal(t, [][]byte{common.HexToAddress(remoteOnRamp).Bytes()}, rc.OnRamps)
	require.Equal(t, common.HexToAddress(remoteOffRamp).Bytes(), rc.OffRamp)
}

// TestToEVMConfigureChainForLanesInput_Errors covers the resolution error
// branches when required local addresses or qualifiers are absent.
func TestToEVMConfigureChainForLanesInput_Errors(t *testing.T) {
	without := func(skip datastore.ContractType, qualifier string) []datastore.AddressRef {
		out := make([]datastore.AddressRef, 0, len(laneRefs()))
		for _, r := range laneRefs() {
			if r.Type == skip && r.Qualifier == qualifier {
				continue
			}
			out = append(out, r)
		}
		return out
	}

	tests := []struct {
		name       string
		input      ccvdeploymentadapters.LaneConfigInput
		wantErrSub string
	}{
		{
			name:       "missing local Router",
			input:      laneInput(without(datastore.ContractType(router.ContractType), ""), nil),
			wantErrSub: "resolve local Router",
		},
		{
			name: "missing local TestRouter",
			input: laneInput(without(datastore.ContractType(router.TestRouterContractType), ""), func(in *ccvdeploymentadapters.LaneConfigInput) {
				in.UseTestRouter = true
			}),
			wantErrSub: "resolve local TestRouter",
		},
		{
			name:       "missing local OnRamp",
			input:      laneInput(without(datastore.ContractType(onramp.ContractType), ""), nil),
			wantErrSub: "resolve local OnRamp",
		},
		{
			name:       "missing executor",
			input:      laneInput(without(datastore.ContractType(sequences.ExecutorProxyType), DefaultQualifier), nil),
			wantErrSub: "resolve executor",
		},
		{
			name:       "missing committee verifier resolver",
			input:      laneInput(without(datastore.ContractType(versioned_verifier_resolver.CommitteeVerifierResolverType), DefaultQualifier), nil),
			wantErrSub: "resolver for qualifier",
		},
		{
			name: "invalid remote onramp extra",
			input: laneInput(laneRefs(), func(in *ccvdeploymentadapters.LaneConfigInput) {
				rc := in.RemoteChains[laneRemoteSel]
				rc.FamilyExtras = map[string]any{LaneRemoteOnRampExtra: "not-a-hex"}
				in.RemoteChains[laneRemoteSel] = rc
			}),
			wantErrSub: "is not a valid hex address",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := toEVMConfigureChainForLanesInput(tc.input)
			require.ErrorContains(t, err, tc.wantErrSub)
		})
	}
}
