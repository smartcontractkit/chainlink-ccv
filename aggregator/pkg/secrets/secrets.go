// Package secrets defines the aggregator secrets file: an optional, operator-provided TOML file
// carrying the aggregator's own credentials — the application storage DB URL, the redis password used
// by rate limiting, and the per-client inbound HMAC api_key/secret_key pairs.
//
// Secrets resolve backwards-compatibly: an absent file is never an error and falls back entirely to
// environment variables, and when a value is present in both the file and an env var the file wins.
// For client credentials this is resolved per client: if the file supplies any
// pairs for a client_id, that set is authoritative and the env-derived pairs for that client are
// ignored.
package secrets

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

// Environment variables and the default path for the aggregator secrets file.
const (
	// StorageURLEnvVar is the legacy environment variable for the application storage DB URL, used as
	// the fallback when the secrets file does not supply [storage].url.
	StorageURLEnvVar = "AGGREGATOR_STORAGE_CONNECTION_URL"

	// RedisPasswordEnvVar is the legacy environment variable for the rate limiter's redis password,
	// used as the fallback when the secrets file does not supply [redis].password.
	RedisPasswordEnvVar = "AGGREGATOR_REDIS_PASSWORD" //nolint:gosec // G101: env var name, not a credential

	// SecretsPathEnvVar is the env var naming the secrets file path; it follows the repo's
	// <APP>_SECRETS_PATH convention and pairs with AGGREGATOR_CONFIG_PATH.
	SecretsPathEnvVar = "AGGREGATOR_SECRETS_PATH" //nolint:gosec // G101: env var name, not a credential

	// DefaultSecretsPath is the namespaced default location of the secrets.toml file.
	DefaultSecretsPath = "/etc/aggregator/secrets.toml" //nolint:gosec // G101: file path, not a credential
)

// File is the on-disk schema of the aggregator secrets file. It carries only credential-bearing
// values.
type File struct {
	Storage StorageSecrets `toml:"storage"`
	Redis   RedisSecrets   `toml:"redis"`
	Clients []ClientSecret `toml:"clients"`
}

// StorageSecrets holds the aggregator's application storage DB URL (formerly
// AGGREGATOR_STORAGE_CONNECTION_URL).
type StorageSecrets struct {
	// URL is the application storage database connection URL.
	URL string `toml:"url"`
}

// RedisSecrets holds the redis password used by the rate limiter (formerly AGGREGATOR_REDIS_PASSWORD).
// The non-secret redis configuration (address, db) are deliberately not here.
type RedisSecrets struct {
	// Password is the redis password used by the rate limiter.
	Password string `toml:"password"`
}

// ClientSecret is one client's inbound HMAC credential as declared in the [[clients]] array of tables.
// A client_id may appear more than once to declare multiple pairs (e.g. during key rotation); the
// aggregator accepts any of a client's pairs.
type ClientSecret struct {
	// ClientID identifies the client these credentials belong to; joins to clients.clientId in the config.
	ClientID string `toml:"client_id"`
	// APIKey is the client's inbound HMAC API key.
	APIKey string `toml:"api_key"`
	// SecretKey is the client's inbound HMAC secret key.
	SecretKey string `toml:"secret_key"`
}

// ClientCredential is one resolved (api_key, secret_key) pair for a client.
type ClientCredential struct {
	APIKey    string
	SecretKey string
}

// ClientSecrets is the resolved per-client credential set, indexed by client_id. A nil map means the
// file supplied no client credentials, in which case each client falls back entirely to its env vars.
type ClientSecrets map[string][]ClientCredential

// Secrets is the parsed, validated aggregator secrets, ready to hand to the read sites. An absent file
// yields a zero value whose accessors all fall back to environment variables.
type Secrets struct {
	// storageURL is the DB URL from the file; empty when the file omits it (env is then used).
	storageURL string
	// redisPassword is the redis password from the file; empty when omitted (env is then used).
	redisPassword string
	// clients is nil when the file supplied no [[clients]] (env is then used for every client).
	clients ClientSecrets
}

// newClientSecrets groups the given entries by client_id, enforcing that a present file is
// well-formed: every entry must carry a non-empty client_id, api_key, and secret_key, and no api_key
// may appear twice (an api_key is the auth lookup key, so a collision is genuinely ambiguous). A
// repeated client_id is allowed. Returns a nil map (not an error) when entries is
// empty.
func newClientSecrets(entries []ClientSecret) (ClientSecrets, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	seenAPIKey := make(map[string]int, len(entries))
	result := make(ClientSecrets)
	for i, e := range entries {
		clientID := strings.TrimSpace(e.ClientID)
		if clientID == "" {
			return nil, fmt.Errorf("clients entry #%d: client_id is required", i)
		}
		if strings.TrimSpace(e.APIKey) == "" {
			return nil, fmt.Errorf("clients entry #%d (client_id %q): api_key is required", i, clientID)
		}
		if strings.TrimSpace(e.SecretKey) == "" {
			return nil, fmt.Errorf("clients entry #%d (client_id %q): secret_key is required", i, clientID)
		}
		if prev, dup := seenAPIKey[e.APIKey]; dup {
			return nil, fmt.Errorf("duplicate api_key in clients entries #%d and #%d (client_id %q)", prev, i, clientID)
		}
		seenAPIKey[e.APIKey] = i
		result[clientID] = append(result[clientID], ClientCredential{APIKey: e.APIKey, SecretKey: e.SecretKey})
	}
	return result, nil
}

// decodeError turns a TOML decode failure into an error safe to log. BurntSushi's ParseError.Error()
// (and its Message/input fields) can echo a snippet of the offending source line, which for a sensitive file
// may be a credential value.
func decodeError(path string, err error) error {
	if pe, ok := errors.AsType[toml.ParseError](err); ok {
		return fmt.Errorf("failed to decode aggregator secrets file %q: TOML parse error at line %d, column %d (last key %q)",
			path, pe.Position.Line, pe.Position.Col, pe.LastKey)
	}
	return fmt.Errorf("failed to decode aggregator secrets file %q: malformed or invalid TOML (details omitted to avoid logging secret values)", path)
}

// ResolveSecretsPath returns the secrets file path from envVar, or defaultPath when unset.
func ResolveSecretsPath(envVar, defaultPath string) string {
	if p := os.Getenv(envVar); p != "" {
		return p
	}
	return defaultPath
}

// LoadFromEnv resolves the secrets path from envVar (falling back to defaultPath) and loads it.
func LoadFromEnv(envVar, defaultPath string) (*Secrets, error) {
	return Load(ResolveSecretsPath(envVar, defaultPath))
}

// Load reads and validates the aggregator secrets file at path.
//
// An absent file is never an error: it returns an empty *Secrets so callers uniformly fall back to
// environment variables. A present file is decoded strictly —
// malformed TOML, unknown/misspelled keys, a half-filled [[clients]] entry, or a duplicate api_key are
// hard errors, so a real secrets file is never silently half-ignored. Credential-value validation
// (api_key/secret_key format) and DB URL correctness are deferred to their use sites, so those errors
// read identically whether the value came from the file or the environment.
func Load(path string) (*Secrets, error) {
	tomlBytes, err := os.ReadFile(path) //nolint:gosec // G304: path is operator-provided (env var / default), trusted.
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// Absent file: env-only, backwards-compatible path.
			return &Secrets{}, nil
		}
		return nil, fmt.Errorf("failed to read aggregator secrets file %q: %w", path, err)
	}

	var file File
	md, err := toml.Decode(string(tomlBytes), &file)
	if err != nil {
		return nil, decodeError(path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		return nil, fmt.Errorf("aggregator secrets file %q has unknown keys: %+v", path, undecoded)
	}

	clients, err := newClientSecrets(file.Clients)
	if err != nil {
		return nil, fmt.Errorf("invalid aggregator secrets file %q: %w", path, err)
	}

	return &Secrets{storageURL: file.Storage.URL, redisPassword: file.Redis.Password, clients: clients}, nil
}

// StorageURL returns the application storage DB URL: the secrets file value when present, otherwise
// the AGGREGATOR_STORAGE_CONNECTION_URL environment variable. The file wins. An
// empty result means no storage URL is configured.
func (s *Secrets) StorageURL() string {
	if s != nil && s.storageURL != "" {
		return s.storageURL
	}
	return os.Getenv(StorageURLEnvVar)
}

// RedisPassword returns the rate limiter's redis password: the secrets file value when present,
// otherwise the AGGREGATOR_REDIS_PASSWORD environment variable. The file wins. An empty result means
// no password (redis auth disabled), preserving the existing behavior.
func (s *Secrets) RedisPassword() string {
	if s != nil && s.redisPassword != "" {
		return s.redisPassword
	}
	return os.Getenv(RedisPasswordEnvVar)
}

// ClientSecrets returns the per-client credentials from the file, or nil when the file supplied none
// (in which case every client's credentials resolve from env vars).
func (s *Secrets) ClientSecrets() ClientSecrets {
	if s == nil {
		return nil
	}
	return s.clients
}
