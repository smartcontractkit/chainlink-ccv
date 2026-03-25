package tokenconfig

import (
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/versioned_verifier_resolver"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_5_0/operations/token_admin_registry"
	"github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/offchain"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

const (
	RoleBurnMint    = "burn-mint"
	RoleLockRelease = "lock-release"
)

// GetTokenPoolOfferings returns EVM token pool offerings for a single chain.
// Each unique pool deployment from AllTokenCombinations becomes one offering
// with its EVM-specific CCV refs, registry ref, role, and compatibility info.
func GetTokenPoolOfferings(selector uint64, topology *offchain.EnvironmentTopology) []cciptestinterfaces.TokenPoolOffering {
	applicableCombos := FilterTokenCombinations(AllTokenCombinations(), topology)

	type offeringKey struct {
		poolType      string
		poolVersion   string
		poolQualifier string
	}
	seen := make(map[offeringKey]struct{})
	var offerings []cciptestinterfaces.TokenPoolOffering

	for _, combo := range applicableCombos {
		for _, side := range []struct {
			ref           datastore.AddressRef
			ccvQualifiers []string
			finality      uint16
		}{
			{combo.SourcePoolAddressRef(), combo.SourcePoolCCVQualifiers(), combo.FinalityConfig()},
			{combo.DestPoolAddressRef(), combo.DestPoolCCVQualifiers(), combo.FinalityConfig()},
		} {
			key := offeringKey{
				poolType:      string(side.ref.Type),
				poolVersion:   side.ref.Version.String(),
				poolQualifier: side.ref.Qualifier,
			}
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}

			role, compat := poolRole(string(side.ref.Type))

			ccvRefs := make([]datastore.AddressRef, 0, len(side.ccvQualifiers))
			for _, qualifier := range side.ccvQualifiers {
				ccvRefs = append(ccvRefs, datastore.AddressRef{
					Type:      datastore.ContractType(versioned_verifier_resolver.CommitteeVerifierResolverType),
					Version:   versioned_verifier_resolver.Version,
					Qualifier: qualifier,
				})
			}

			offerings = append(offerings, cciptestinterfaces.TokenPoolOffering{
				PoolRef:               side.ref,
				RegistryRef:           evmRegistryRef(),
				CCVRefs:               ccvRefs,
				Role:                  role,
				CompatibleRemoteRoles: compat,
				MinFinalityValue:      side.finality,
			})
		}
	}

	return offerings
}

func evmRegistryRef() datastore.AddressRef {
	return datastore.AddressRef{
		Type:    datastore.ContractType(token_admin_registry.ContractType),
		Version: semver.MustParse(token_admin_registry.Deploy.Version()),
	}
}

func poolRole(contractType string) (role string, compatibleRemoteRoles []string) {
	lower := strings.ToLower(contractType)
	switch {
	case strings.Contains(lower, "lockrelease"):
		return RoleLockRelease, []string{RoleBurnMint}
	default:
		return RoleBurnMint, []string{RoleBurnMint, RoleLockRelease}
	}
}
