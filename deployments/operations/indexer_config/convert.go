package indexer_config

import (
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
)

// GeneratedVerifiersToGeneratedConfig converts a map of qualifier to GeneratedVerifier
// into config.GeneratedConfig, using the qualifier as the key.
func GeneratedVerifiersToGeneratedConfig(verifiers map[string]GeneratedVerifier) *config.GeneratedConfig {
	verifierMap := make(map[string]config.GeneratedVerifierConfig, len(verifiers))

	for qualifier, v := range verifiers {
		verifierMap[qualifier] = config.GeneratedVerifierConfig{
			IssuerAddresses: v.IssuerAddresses,
		}
	}

	return &config.GeneratedConfig{
		Verifier: verifierMap,
	}
}
