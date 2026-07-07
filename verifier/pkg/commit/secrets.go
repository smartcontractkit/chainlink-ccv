package commit

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
)

// buildHMACConfig validates an API key / secret pair and returns the client config. apiKeyLabel and
// secretLabel name the source (env var names, or file field names) so error messages point the
// operator at the right place regardless of where the credential came from.
func buildHMACConfig(apiKey, secret, apiKeyLabel, secretLabel, aggLabel string) (*hmac.ClientConfig, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("missing %s for aggregator %q", apiKeyLabel, aggLabel)
	}
	if err := hmac.ValidateAPIKey(apiKey); err != nil {
		return nil, fmt.Errorf("invalid %s for aggregator %q: %w", apiKeyLabel, aggLabel, err)
	}
	if secret == "" {
		return nil, fmt.Errorf("missing %s for aggregator %q", secretLabel, aggLabel)
	}
	if err := hmac.ValidateSecret(secret); err != nil {
		return nil, fmt.Errorf("invalid %s for aggregator %q: %w", secretLabel, aggLabel, err)
	}
	return &hmac.ClientConfig{APIKey: apiKey, Secret: secret}, nil
}
