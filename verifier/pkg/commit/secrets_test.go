package commit

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vsecrets"
)

// Valid HMAC credentials: the API key must be a UUID and the secret a >=32-byte hex string.
const (
	validAPIKey = "11111111-1111-1111-1111-111111111111"
)

func validSecret() string { return strings.Repeat("ab", 32) } // 32 bytes hex-encoded

func TestResolveHMACConfig_FileWinsOverEnv(t *testing.T) {
	conn := AggregatorConnection{SecretName: "agg1", Address: "agg1:8080"}

	// Env vars set to a different (also valid) credential; the file must win.
	apiKeyVar, secretKeyVar := conn.AggregatorCredentialEnvVars()
	t.Setenv(apiKeyVar, "22222222-2222-2222-2222-222222222222")
	t.Setenv(secretKeyVar, strings.Repeat("cd", 32))

	secrets := vsecrets.AggregatorSecrets{
		"agg1": {SecretName: "agg1", APIKey: validAPIKey, SecretKey: validSecret()},
	}

	cfg, err := conn.ResolveHMACConfig(secrets)
	require.NoError(t, err)
	require.Equal(t, validAPIKey, cfg.APIKey)
	require.Equal(t, validSecret(), cfg.Secret)
}

func TestResolveHMACConfig_FallsBackToEnvWhenNoFileEntry(t *testing.T) {
	conn := AggregatorConnection{SecretName: "agg1", Address: "agg1:8080"}

	apiKeyVar, secretKeyVar := conn.AggregatorCredentialEnvVars()
	t.Setenv(apiKeyVar, validAPIKey)
	t.Setenv(secretKeyVar, validSecret())

	// A non-nil secrets map that lacks this aggregator, and a nil map, both fall back to env.
	for name, secrets := range map[string]vsecrets.AggregatorSecrets{
		"nil map":              nil,
		"map without this agg": {"other": {SecretName: "other", APIKey: validAPIKey, SecretKey: validSecret()}},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := conn.ResolveHMACConfig(secrets)
			require.NoError(t, err)
			require.Equal(t, validAPIKey, cfg.APIKey)
			require.Equal(t, validSecret(), cfg.Secret)
		})
	}
}

func TestResolveHMACConfig_LegacyDefaultFromFile(t *testing.T) {
	// A connection with no SecretName resolves against the empty-key (legacy default) file entry.
	conn := AggregatorConnection{Address: "agg1:8080"}
	secrets := vsecrets.AggregatorSecrets{
		"": {APIKey: validAPIKey, SecretKey: validSecret()},
	}

	cfg, err := conn.ResolveHMACConfig(secrets)
	require.NoError(t, err)
	require.Equal(t, validAPIKey, cfg.APIKey)
}

func TestResolveHMACConfig_MissingCredentialErrors(t *testing.T) {
	conn := AggregatorConnection{SecretName: "agg1", Address: "agg1:8080"}
	// Ensure env is empty for this aggregator.
	apiKeyVar, secretKeyVar := conn.AggregatorCredentialEnvVars()
	t.Setenv(apiKeyVar, "")
	t.Setenv(secretKeyVar, "")

	_, err := conn.ResolveHMACConfig(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), apiKeyVar) // env-source error names the env var
}

func TestResolveHMACConfig_InvalidFileCredentialErrors(t *testing.T) {
	conn := AggregatorConnection{SecretName: "agg1", Address: "agg1:8080"}
	secrets := vsecrets.AggregatorSecrets{
		"agg1": {SecretName: "agg1", APIKey: "not-a-uuid", SecretKey: validSecret()},
	}

	_, err := conn.ResolveHMACConfig(secrets)
	require.Error(t, err)
	require.Contains(t, err.Error(), "api_key") // file-source error names the file field
}
