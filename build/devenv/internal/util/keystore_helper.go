package util

const (
	// DefaultKeystoreName is the name used for keystore storage in the database.
	DefaultKeystoreName = "verifier-keystore"
	// DefaultKeystorePassword is a devenv-only password for the keystore.
	// In production, this should be provided via secure configuration.
	DefaultKeystorePassword = "devenv-keystore-password-not-for-production"
)
