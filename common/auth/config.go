package auth

import (
	"errors"
	"strings"
)

// APIClient represents a configured client for API access.
type APIClient struct {
	ClientID    string            `toml:"clientId"`
	Description string            `toml:"description,omitempty"`
	Enabled     bool              `toml:"enabled"`
	Secrets     map[string]string `toml:"secrets,omitempty"`
	Groups      []string          `toml:"groups,omitempty"`
}

// APIKeyConfig represents the configuration for API key management.
type APIKeyConfig struct {
	// Clients maps API keys to client configurations
	Clients map[string]*APIClient `toml:"clients"`
}

// GetClientByAPIKey returns the client configuration for a given API key.
func (c *APIKeyConfig) GetClientByAPIKey(apiKey string) (*APIClient, bool) {
	client, exists := c.Clients[apiKey]
	if !exists || !client.Enabled {
		return nil, false
	}
	return client, true
}

// ValidateAPIKey validates an API key against the configuration.
func (c *APIKeyConfig) ValidateAPIKey(apiKey string) error {
	if strings.TrimSpace(apiKey) == "" {
		return errors.New("api key cannot be empty")
	}

	client, exists := c.GetClientByAPIKey(apiKey)
	if !exists {
		return errors.New("invalid or disabled api key")
	}

	if client.ClientID == "" {
		return errors.New("client id cannot be empty")
	}

	return nil
}
