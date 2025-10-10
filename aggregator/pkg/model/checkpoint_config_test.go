package model

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAPIKeyConfig(t *testing.T) {
	t.Run("validate_api_key_with_valid_config", func(t *testing.T) {
		config := &APIKeyConfig{
			Clients: map[string]*APIClient{
				"test-api-key": {
					ClientID:    "test-client",
					Description: "Test client",
					Enabled:     true,
				},
			},
		}

		err := config.ValidateAPIKey("test-api-key")
		require.NoError(t, err, "valid API key should pass validation")
	})

	t.Run("validate_api_key_with_disabled_client", func(t *testing.T) {
		config := &APIKeyConfig{
			Clients: map[string]*APIClient{
				"disabled-key": {
					ClientID:    "disabled-client",
					Description: "Disabled client",
					Enabled:     false, // Disabled
				},
			},
		}

		err := config.ValidateAPIKey("disabled-key")
		require.Error(t, err, "disabled API key should fail validation")
		require.Contains(t, err.Error(), "invalid or disabled api key")
	})

	t.Run("validate_api_key_with_unknown_key", func(t *testing.T) {
		config := &APIKeyConfig{
			Clients: map[string]*APIClient{},
		}

		err := config.ValidateAPIKey("unknown-key")
		require.Error(t, err, "unknown API key should fail validation")
		require.Contains(t, err.Error(), "invalid or disabled api key")
	})

	t.Run("get_client_by_api_key", func(t *testing.T) {
		config := &APIKeyConfig{
			Clients: map[string]*APIClient{
				"valid-key": {
					ClientID:    "client-123",
					Description: "Valid client",
					Enabled:     true,
				},
			},
		}

		client, exists := config.GetClientByAPIKey("valid-key")
		require.True(t, exists, "should find valid API key")
		require.Equal(t, "client-123", client.ClientID, "should return correct client ID")
	})

	t.Run("aggregator_config_validation", func(t *testing.T) {
		config := &AggregatorConfig{
			APIKeys: APIKeyConfig{
				Clients: map[string]*APIClient{
					"valid-key": {
						ClientID:    "client-1",
						Description: "Test client",
						Enabled:     true,
					},
					"": { // Invalid empty key
						ClientID: "client-2",
						Enabled:  true,
					},
				},
			},
		}

		err := config.Validate()
		require.Error(t, err, "should fail validation with empty API key")
		require.Contains(t, err.Error(), "api key cannot be empty")
	})

	t.Run("set_defaults", func(t *testing.T) {
		config := &AggregatorConfig{
			APIKeys: APIKeyConfig{
				// No defaults set
			},
			Checkpoints: CheckpointConfig{
				// No defaults set
			},
		}

		config.SetDefaults()

		require.Equal(t, 1000, config.Checkpoints.MaxCheckpointsPerRequest)
		require.NotNil(t, config.APIKeys.Clients)
	})
}
