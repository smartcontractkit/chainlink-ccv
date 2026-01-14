package indexer_config

import (
	"strconv"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
)

// GeneratedVerifiersToGeneratedConfig converts a slice of GeneratedVerifier to config.GeneratedConfig.
func GeneratedVerifiersToGeneratedConfig(verifiers []GeneratedVerifier) *config.GeneratedConfig {
	verifierMap := make(map[string]config.GeneratedVerifierConfig)

	for i, v := range verifiers {
		verifierMap[strconv.Itoa(i)] = config.GeneratedVerifierConfig{
			IssuerAddresses: v.IssuerAddresses,
		}
	}

	return &config.GeneratedConfig{
		Verifier: verifierMap,
	}
}
