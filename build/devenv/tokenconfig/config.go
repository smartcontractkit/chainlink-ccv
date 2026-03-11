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

// poolConfigKey uniquely identifies a token pool (for merging configs per chain).
type poolConfigKey struct {
	chainSelector uint64
	poolType      datastore.ContractType
	poolVersion   string
	poolQualifier string
}

// BuildTokenTransferConfigs returns token transfer configs for all chains implied by selectors,
// based on topology and token combinations. Configs for the same (chain, pool) are merged so
// each pool has one config with all remote chains (remote tokens included). Caller should call
// ConfigureTokensForTransfers once per pool-identity group (all chains' configs for that pool type)
// so each setup gets its own mapping slot. Chain-agnostic: no EVM or other chain impl is used.
func BuildTokenTransferConfigs(topology *deployments.EnvironmentTopology, selectors []uint64) []tokenscore.TokenTransferConfig {
	applicableCombos := common.FilterTokenCombinations(common.AllTokenCombinations(), topology)
	merged := make(map[poolConfigKey]tokenscore.TokenTransferConfig)
	for _, selector := range selectors {
		remoteSelectors := make([]uint64, 0, len(selectors)-1)
		for _, s := range selectors {
			if s != selector {
				remoteSelectors = append(remoteSelectors, s)
			}
		}
		for _, combo := range applicableCombos {
			// Both directions so LockRelease<->BurnMint: local LockRelease has remote BurnMint, local BurnMint has remote LockRelease.
			for _, cfg := range []tokenscore.TokenTransferConfig{
				buildTokenTransferConfig(selector, remoteSelectors, combo.SourcePoolAddressRef(), combo.DestPoolAddressRef(), combo.SourcePoolCCVQualifiers()),
				buildTokenTransferConfig(selector, remoteSelectors, combo.DestPoolAddressRef(), combo.SourcePoolAddressRef(), combo.DestPoolCCVQualifiers()),
			} {
				key := poolConfigKey{
					chainSelector: cfg.ChainSelector,
					poolType:      cfg.TokenPoolRef.Type,
					poolVersion:   cfg.TokenPoolRef.Version.String(),
					poolQualifier: cfg.TokenPoolRef.Qualifier,
				}
				existing, ok := merged[key]
				if !ok {
					merged[key] = cfg
					continue
				}
				for rs, rc := range cfg.RemoteChains {
					existing.RemoteChains[rs] = rc
				}
				merged[key] = existing
			}
		}
	}
	configs := make([]tokenscore.TokenTransferConfig, 0, len(merged))
	for _, cfg := range merged {
		configs = append(configs, cfg)
	}
	return configs
}

// PoolIdentityKey returns a key that identifies the pool type (same across chains). Used to group
// configs so ConfigureTokensForTransfers is called once per setup with all counterpart configs.
func PoolIdentityKey(cfg *tokenscore.TokenTransferConfig) string {
	v := ""
	if cfg.TokenPoolRef.Version != nil {
		v = cfg.TokenPoolRef.Version.String()
	}
	return string(cfg.TokenPoolRef.Type) + "\x00" + v + "\x00" + cfg.TokenPoolRef.Qualifier
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
