package bootstrap

// DefaultCSAKeyName is the keystore key name for the JD CSA authentication key.
// It is exported so that external tools (e.g. devenv) can look up the key by name.
const DefaultCSAKeyName = "bootstrap_default_csa_key"

// Deprecated key names retained only for the backwards-compat initialization block.
// Remove once all callers declare their required keys explicitly via WithKey.
const (
	defaultECDSASigningKeyName = "bootstrap_default_ecdsa_signing_key"
	defaultEdDSASigningKeyName = "bootstrap_default_eddsa_signing_key"
)
