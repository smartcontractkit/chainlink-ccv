package bootstrap

import "github.com/smartcontractkit/chainlink-ccv/bootstrap/info"

// DefaultCSAKeyName is the keystore key name for the JD CSA authentication key.
// It is exported so that external tools (e.g. devenv) can look up the key by name.
const DefaultCSAKeyName = info.DefaultCSAKeyName

// GetKeysEndpoint is the bootstrap info-server endpoint for named public keys.
const GetKeysEndpoint = info.GetKeysEndpoint
