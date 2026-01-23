package indexer_config

import (
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
)

// GeneratedVerifiersToGeneratedConfig converts a slice of GeneratedVerifier
// into config.GeneratedConfig.
func GeneratedVerifiersToGeneratedConfig(verifiers []GeneratedVerifier) *config.GeneratedConfig {
	verifierSlice := make([]config.GeneratedVerifierConfig, 0, len(verifiers))

	for _, v := range verifiers {
		verifierSlice = append(verifierSlice, config.GeneratedVerifierConfig{
			Name:            v.Name,
			IssuerAddresses: v.IssuerAddresses,
		})
	}

	return &config.GeneratedConfig{
		Verifier: verifierSlice,
	}
}
