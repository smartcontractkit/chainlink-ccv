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

// HMACFailureRecorder is an interface for recording HMAC verification outcomes.
// When implemented by a ClientProvider, the HMAC middleware uses it to track consecutive
// signature failures and may disable clients after a threshold.
type HMACFailureRecorder interface {
	// RecordHMACVerificationFailure records a signature failure; returns true if the client was disabled.
	RecordHMACVerificationFailure(clientID string) (clientWasDisabled bool)
	// RecordHMACVerificationSuccess resets the consecutive failure count for the client.
	RecordHMACVerificationSuccess(clientID string)
}
