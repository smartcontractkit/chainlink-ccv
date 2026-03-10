package tokenconfig

import (
	"github.com/Masterminds/semver/v3"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/versioned_verifier_resolver"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_5_0/operations/token_admin_registry"
	tokenscore "github.com/smartcontractkit/chainlink-ccip/deployment/tokens"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/deployments"
)

// BuildTokenTransferConfigs returns token transfer configs for all chains implied by selectors,
// based on topology and token combinations. Chain-agnostic: no EVM or other chain impl is used.
func BuildTokenTransferConfigs(topology *deployments.EnvironmentTopology, selectors []uint64) []tokenscore.TokenTransferConfig {
	applicableCombos := common.FilterTokenCombinations(common.AllTokenCombinations(), topology)
	var configs []tokenscore.TokenTransferConfig
	for _, selector := range selectors {
		remoteSelectors := make([]uint64, 0, len(selectors)-1)
		for _, s := range selectors {
			if s != selector {
				remoteSelectors = append(remoteSelectors, s)
			}
		}
		for _, combo := range applicableCombos {
			configs = append(configs,
				buildTokenTransferConfig(selector, remoteSelectors, combo.SourcePoolAddressRef(), combo.DestPoolAddressRef(), combo.SourcePoolCCVQualifiers()),
				buildTokenTransferConfig(selector, remoteSelectors, combo.DestPoolAddressRef(), combo.SourcePoolAddressRef(), combo.DestPoolCCVQualifiers()),
			)
		}
	}
	return configs
}

func buildTokenTransferConfig(
	selector uint64,
	remoteSelectors []uint64,
	localRef datastore.AddressRef,
	remoteRef datastore.AddressRef,
	ccvQualifiers []string,
) tokenscore.TokenTransferConfig {
	tokensRemoteChains := make(map[uint64]tokenscore.RemoteChainConfig[*datastore.AddressRef, datastore.AddressRef])
	for _, rs := range remoteSelectors {
		ccvRefs := make([]datastore.AddressRef, 0, len(ccvQualifiers))
		for _, qualifier := range ccvQualifiers {
			ccvRefs = append(ccvRefs, datastore.AddressRef{
				Type:      datastore.ContractType(versioned_verifier_resolver.CommitteeVerifierResolverType),
				Version:   versioned_verifier_resolver.Version,
				Qualifier: qualifier,
			})
		}

		tokensRemoteChains[rs] = tokenscore.RemoteChainConfig[*datastore.AddressRef, datastore.AddressRef]{
			RemotePool: &remoteRef,
			DefaultFinalityInboundRateLimiterConfig: tokenscore.RateLimiterConfigFloatInput{
				IsEnabled: false,
				Capacity:  0,
				Rate:      0,
			},
			DefaultFinalityOutboundRateLimiterConfig: tokenscore.RateLimiterConfigFloatInput{
				IsEnabled: false,
				Capacity:  0,
				Rate:      0,
			},
			CustomFinalityInboundRateLimiterConfig: tokenscore.RateLimiterConfigFloatInput{
				IsEnabled: false,
				Capacity:  0,
				Rate:      0,
			},
			CustomFinalityOutboundRateLimiterConfig: tokenscore.RateLimiterConfigFloatInput{
				IsEnabled: false,
				Capacity:  0,
				Rate:      0,
			},
			OutboundCCVs: ccvRefs,
			InboundCCVs:  ccvRefs,
		}
	}

	return tokenscore.TokenTransferConfig{
		ChainSelector: selector,
		TokenPoolRef:  localRef,
		RegistryRef: datastore.AddressRef{
			Type:    datastore.ContractType(token_admin_registry.ContractType),
			Version: semver.MustParse(token_admin_registry.Deploy.Version()),
		},
		RemoteChains:     tokensRemoteChains,
		MinFinalityValue: 1,
	}
}
