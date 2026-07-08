// Package vsecrets defines the verifier secrets file: an optional, operator-provided TOML
// file carrying the verifier apps' own credentials — the application storage DB URL and, for the
// committee verifier, per-aggregator HMAC credentials. It is a leaf package (depending only on the
// TOML decoder) so the verifier apps, the commit package, and the devenv harness can all share one
// schema definition without pulling in heavier dependencies.
//
// Secrets resolve backwards-compatibly: an absent file is never an error and falls back entirely to
// environment variables, and when a value is present in both the file and an env var the file wins.
package vsecrets

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

// Environment variables and default paths for the verifier secrets file. Each verifier app resolves
// its own path env var, falling back to a namespaced default under /etc. The names follow the repo's
// <APP>_SECRETS_PATH convention (BOOTSTRAPPER_SECRETS_PATH, INDEXER_SECRETS_PATH).
const (
	// DatabaseURLEnvVar is the legacy environment variable for the application storage DB URL, used
	// as the fallback when the secrets file does not supply [db].url.
	DatabaseURLEnvVar = "CL_DATABASE_URL"

	CommitteeVerifierSecretsPathEnv     = "COMMITTEE_VERIFIER_SECRETS_PATH"
	DefaultCommitteeVerifierSecretsPath = "/etc/committee-verifier/secrets.toml"

	TokenVerifierSecretsPathEnv     = "TOKEN_VERIFIER_SECRETS_PATH"      //nolint:gosec // G101: env var name, not a credential
	DefaultTokenVerifierSecretsPath = "/etc/token-verifier/secrets.toml" //nolint:gosec // G101: file path, not a credential
)

// SecretsFile is the on-disk schema of the verifier secrets file. It carries only credential-bearing
// values: the application storage DB URL and, for the committee verifier, per-aggregator HMAC
// credentials. Non-secret DB tuning knobs stay as environment variables and are intentionally absent
// here. The token verifier populates only [db].
type SecretsFile struct {
	DB          DBSecrets          `toml:"db"`
	Aggregators []AggregatorSecret `toml:"aggregators"`
}

// DBSecrets holds the application storage database URL. This is the verifier's own storage DB
// (CL_DATABASE_URL), distinct from the bootstrapper's keystore-ORM [db].
type DBSecrets struct {
	URL string `toml:"url"`
}

// AggregatorSecret is one aggregator's HMAC credential as declared in the [[aggregators]] array of
// tables. SecretName is the join key back to the committee verifier's config
// (AggregatorConnection.SecretName); an omitted SecretName is the legacy single-aggregator default,
// matching the un-suffixed VERIFIER_AGGREGATOR_API_KEY / _SECRET_KEY env vars.
//
// This is deliberately a minimal, credential-only struct: the secrets file carries credentials,
// never connection settings such as address or TLS.
type AggregatorSecret struct {
	SecretName string `toml:"secret_name"`
	APIKey     string `toml:"api_key"`
	SecretKey  string `toml:"secret_key"`
}

// AggregatorSecrets is the resolved set of aggregator HMAC credentials, indexed by raw SecretName
// (the empty string key is the legacy default). Unlike the env-var scheme it is keyed by the verbatim
// name, so lookups are collision-free. A nil map means the file supplied no aggregator credentials,
// in which case resolution falls back entirely to env vars.
type AggregatorSecrets map[string]AggregatorSecret

// NewAggregatorSecrets indexes the given entries by SecretName, enforcing that the file is
// unambiguous: duplicate secret_names (including more than one omitted/default entry) are a hard
// error rather than a silent last-wins. Returns a nil map (not an error) when entries is empty, so a
// secrets file with no [[aggregators]] section resolves purely from env vars.
func NewAggregatorSecrets(entries []AggregatorSecret) (AggregatorSecrets, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	secrets := make(AggregatorSecrets, len(entries))
	for _, e := range entries {
		key := strings.TrimSpace(e.SecretName)
		if _, dup := secrets[key]; dup {
			if key == "" {
				return nil, fmt.Errorf("more than one aggregator entry omits secret_name (only one legacy default is allowed)")
			}
			return nil, fmt.Errorf("duplicate aggregator secret_name %q", key)
		}
		secrets[key] = AggregatorSecret{SecretName: key, APIKey: e.APIKey, SecretKey: e.SecretKey}
	}
	return secrets, nil
}

// VerifierSecrets is the parsed, validated verifier secrets, ready to hand to the read sites. It is
// always non-nil when returned from Load; an absent file yields a zero value whose lookups all miss,
// so resolution falls back to environment variables (the backwards-compatible path).
type VerifierSecrets struct {
	// dbURL is the DB URL from the file; empty when the file omits it (env is then used).
	dbURL string
	// aggregators is nil when the file supplied no [[aggregators]] (env is then used).
	aggregators AggregatorSecrets
}

// ResolveSecretsPath returns the secrets file path from envVar, or defaultPath when unset.
func ResolveSecretsPath(envVar, defaultPath string) string {
	if p := os.Getenv(envVar); p != "" {
		return p
	}
	return defaultPath
}

// LoadFromEnv resolves the secrets path from envVar (falling back to defaultPath) and loads it. This
// is the convenience each verifier app uses so the env-var/default resolution lives in one place.
func LoadFromEnv(envVar, defaultPath string) (*VerifierSecrets, error) {
	return Load(ResolveSecretsPath(envVar, defaultPath))
}

// Load reads and validates the verifier secrets file at path.
//
// An absent file is never an error: it returns an empty *VerifierSecrets so callers uniformly fall
// back to environment variables (the backwards-compatible default). A present file is decoded
// strictly — malformed TOML, unknown/misspelled keys, duplicate aggregator secret_names, or more
// than one omitted-secret_name entry are hard errors, so a real secrets file is never silently
// half-ignored. Credential-value validation (api_key/secret_key format) and DB URL correctness are
// deferred to their use sites, so those errors read identically whether the value came from the file
// or the environment.
func Load(path string) (*VerifierSecrets, error) {
	tomlBytes, err := os.ReadFile(path) //nolint:gosec // G304: path is operator-provided (env var / default), trusted.
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// Absent file: env-only, backwards-compatible path.
			return &VerifierSecrets{}, nil
		}
		return nil, fmt.Errorf("failed to read verifier secrets file %q: %w", path, err)
	}

	var file SecretsFile
	md, err := toml.Decode(string(tomlBytes), &file)
	if err != nil {
		return nil, fmt.Errorf("failed to decode verifier secrets file %q: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		return nil, fmt.Errorf("verifier secrets file %q has unknown keys: %+v", path, undecoded)
	}

	aggregators, err := NewAggregatorSecrets(file.Aggregators)
	if err != nil {
		return nil, fmt.Errorf("invalid verifier secrets file %q: %w", path, err)
	}

	return &VerifierSecrets{dbURL: file.DB.URL, aggregators: aggregators}, nil
}

// DatabaseURL returns the application storage DB URL: the secrets file value when present, otherwise
// the CL_DATABASE_URL environment variable (backwards-compatible). The file wins. An empty result
// means no DB is configured, preserving the existing "DB optional" behavior.
func (s *VerifierSecrets) DatabaseURL() string {
	if s != nil && s.dbURL != "" {
		return s.dbURL
	}
	return os.Getenv(DatabaseURLEnvVar)
}

// AggregatorSecrets returns the per-aggregator HMAC credentials from the file, or nil when the file
// supplied none (in which case aggregator resolution falls back to env vars).
func (s *VerifierSecrets) AggregatorSecrets() AggregatorSecrets {
	if s == nil {
		return nil
	}
	return s.aggregators
}
