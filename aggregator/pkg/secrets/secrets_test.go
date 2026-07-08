package secrets

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func writeSecretsFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secrets.toml")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

func TestLoad_AbsentFileIsEnvOnly(t *testing.T) {
	// An absent file is not an error; every value falls back to its env var and clients are nil.
	t.Setenv(StorageURLEnvVar, "postgres://env-host/agg")
	t.Setenv(RedisPasswordEnvVar, "env-redis-pw")

	s, err := Load(filepath.Join(t.TempDir(), "does-not-exist.toml"))
	require.NoError(t, err)
	require.Equal(t, "postgres://env-host/agg", s.StorageURL())
	require.Equal(t, "env-redis-pw", s.RedisPassword())
	require.Nil(t, s.ClientSecrets())
}

func TestLoad_PresentFile(t *testing.T) {
	// With no env set, the file supplies the storage URL, redis password, and client credentials.
	t.Setenv(StorageURLEnvVar, "")
	t.Setenv(RedisPasswordEnvVar, "")

	path := writeSecretsFile(t, `
[storage]
url = "postgres://file-host/agg"

[redis]
password = "file-redis-pw"

[[clients]]
client_id  = "verifier-1"
api_key    = "key-a"
secret_key = "secret-a"

[[clients]]
client_id  = "verifier-2"
api_key    = "key-b"
secret_key = "secret-b"
`)

	s, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, "postgres://file-host/agg", s.StorageURL())
	require.Equal(t, "file-redis-pw", s.RedisPassword())

	clients := s.ClientSecrets()
	require.Len(t, clients, 2)
	require.Equal(t, []ClientCredential{{APIKey: "key-a", SecretKey: "secret-a"}}, clients["verifier-1"])
	require.Equal(t, []ClientCredential{{APIKey: "key-b", SecretKey: "secret-b"}}, clients["verifier-2"])
}

func TestLoad_FileWinsOverEnv(t *testing.T) {
	// When both env and file supply a value, the file wins.
	t.Setenv(StorageURLEnvVar, "postgres://env-host/agg")
	t.Setenv(RedisPasswordEnvVar, "env-redis-pw")

	path := writeSecretsFile(t, `
[storage]
url = "postgres://file-host/agg"

[redis]
password = "file-redis-pw"
`)

	s, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, "postgres://file-host/agg", s.StorageURL())
	require.Equal(t, "file-redis-pw", s.RedisPassword())
}

func TestLoad_ValuesFallBackToEnvWhenFileOmitsThem(t *testing.T) {
	// A file with clients but no [storage]/[redis] leaves those to the env vars.
	t.Setenv(StorageURLEnvVar, "postgres://env-host/agg")
	t.Setenv(RedisPasswordEnvVar, "env-redis-pw")

	path := writeSecretsFile(t, `
[[clients]]
client_id  = "verifier-1"
api_key    = "key-a"
secret_key = "secret-a"
`)

	s, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, "postgres://env-host/agg", s.StorageURL())
	require.Equal(t, "env-redis-pw", s.RedisPassword())
	require.Len(t, s.ClientSecrets(), 1)
}

func TestLoad_RotationRepeatsClientID(t *testing.T) {
	// A repeated client_id is allowed and declares multiple accepted pairs (key rotation).
	path := writeSecretsFile(t, `
[[clients]]
client_id  = "verifier-1"
api_key    = "key-primary"
secret_key = "secret-primary"

[[clients]]
client_id  = "verifier-1"
api_key    = "key-rotating"
secret_key = "secret-rotating"
`)

	s, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, []ClientCredential{
		{APIKey: "key-primary", SecretKey: "secret-primary"},
		{APIKey: "key-rotating", SecretKey: "secret-rotating"},
	}, s.ClientSecrets()["verifier-1"])
}

func TestLoad_StrictRejectsUnknownKey(t *testing.T) {
	// A misspelled key (api_ky) must fail loudly rather than silently leave the credential empty.
	path := writeSecretsFile(t, `
[[clients]]
client_id  = "verifier-1"
api_ky     = "typo"
secret_key = "secret-a"
`)

	_, err := Load(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown keys")
}

func TestLoad_RejectsMalformedTOML(t *testing.T) {
	path := writeSecretsFile(t, `[storage] this is not valid toml`)

	_, err := Load(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "decode")
}

func TestLoad_RejectsDuplicateAPIKeyWithoutLeakingValue(t *testing.T) {
	path := writeSecretsFile(t, `
[[clients]]
client_id  = "verifier-1"
api_key    = "shared-key"
secret_key = "secret-a"

[[clients]]
client_id  = "verifier-2"
api_key    = "shared-key"
secret_key = "secret-b"
`)

	_, err := Load(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "duplicate api_key")
	// The error references ordinals and client_id, never the credential value itself.
	require.NotContains(t, err.Error(), "shared-key")
}

func TestLoad_RejectsMissingFields(t *testing.T) {
	tests := map[string]string{
		"missing client_id": `
[[clients]]
api_key    = "key-a"
secret_key = "secret-a"
`,
		"missing api_key": `
[[clients]]
client_id  = "verifier-1"
secret_key = "secret-a"
`,
		"missing secret_key": `
[[clients]]
client_id  = "verifier-1"
api_key    = "key-a"
`,
	}
	for name, contents := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Load(writeSecretsFile(t, contents))
			require.Error(t, err)
			require.Contains(t, err.Error(), "is required")
		})
	}
}

func TestResolveSecretsPath(t *testing.T) {
	t.Run("env set", func(t *testing.T) {
		t.Setenv(SecretsPathEnvVar, "/custom/secrets.toml")
		require.Equal(t, "/custom/secrets.toml", ResolveSecretsPath(SecretsPathEnvVar, DefaultSecretsPath))
	})
	t.Run("env unset uses default", func(t *testing.T) {
		t.Setenv(SecretsPathEnvVar, "")
		require.Equal(t, DefaultSecretsPath, ResolveSecretsPath(SecretsPathEnvVar, DefaultSecretsPath))
	})
}

func TestAccessors_NilReceiver(t *testing.T) {
	// A nil *Secrets is the env-only path (defensive; callers normally pass a non-nil value).
	t.Setenv(StorageURLEnvVar, "postgres://env-host/agg")
	t.Setenv(RedisPasswordEnvVar, "env-redis-pw")
	var s *Secrets
	require.Equal(t, "postgres://env-host/agg", s.StorageURL())
	require.Equal(t, "env-redis-pw", s.RedisPassword())
	require.Nil(t, s.ClientSecrets())
}
