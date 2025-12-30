package auth

// APIKeyPair provides access to API key credentials.
type APIKeyPair interface {
	// GetAPIKey returns the API key identifier.
	GetAPIKey() string
	// GetSecret returns the secret used for signing.
	GetSecret() string
}

// ClientConfig provides access to client configuration.
type ClientConfig interface {
	// GetClientID returns the unique client identifier.
	GetClientID() string
	// GetGroups returns the list of groups the client belongs to.
	GetGroups() []string
	// IsEnabled returns whether the client is enabled.
	IsEnabled() bool
}

// ClientProvider provides methods to lookup clients by API key or client ID.
type ClientProvider interface {
	// GetClientByAPIKey looks up a client by their API key.
	GetClientByAPIKey(apiKey string) (ClientConfig, APIKeyPair, bool)
	// GetClientByClientID looks up a client by their client ID.
	GetClientByClientID(clientID string) (ClientConfig, bool)
}
