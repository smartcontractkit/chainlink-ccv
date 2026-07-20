package vsecrets

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
	// An absent file is not an error; DB URL falls back to CL_DATABASE_URL and aggregators are nil.
	t.Setenv(DatabaseURLEnvVar, "postgres://env-host/db")

	secrets, err := Load(filepath.Join(t.TempDir(), "does-not-exist.toml"))
	require.NoError(t, err)
	require.Equal(t, "postgres://env-host/db", secrets.DatabaseURL())
	require.Nil(t, secrets.AggregatorSecrets())
}

func TestLoad_PresentFile(t *testing.T) {
	// With no env var set, the file supplies both the DB URL and the aggregator credentials.
	t.Setenv(DatabaseURLEnvVar, "")

	path := writeSecretsFile(t, `
[db]
url = "postgres://file-host/db"

[[aggregators]]
secret_name = "arbitrum_mainnet"
api_key = "key-a"
secret_key = "secret-a"

[[aggregators]]
secret_name = "base_mainnet"
api_key = "key-b"
secret_key = "secret-b"
`)

	secrets, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, "postgres://file-host/db", secrets.DatabaseURL())

	aggs := secrets.AggregatorSecrets()
	require.Len(t, aggs, 2)
	require.Equal(t, AggregatorSecret{SecretName: "arbitrum_mainnet", APIKey: "key-a", SecretKey: "secret-a"}, aggs["arbitrum_mainnet"])
	require.Equal(t, AggregatorSecret{SecretName: "base_mainnet", APIKey: "key-b", SecretKey: "secret-b"}, aggs["base_mainnet"])
}

func TestLoad_FileWinsOverEnv(t *testing.T) {
	// When both the env var and the file supply the DB URL, the file wins.
	t.Setenv(DatabaseURLEnvVar, "postgres://env-host/db")

	path := writeSecretsFile(t, `
[db]
url = "postgres://file-host/db"
`)

	secrets, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, "postgres://file-host/db", secrets.DatabaseURL())
}

func TestLoad_DBFallsBackToEnvWhenFileOmitsIt(t *testing.T) {
	// A file with aggregators but no [db] leaves the DB URL to the env var.
	t.Setenv(DatabaseURLEnvVar, "postgres://env-host/db")

	path := writeSecretsFile(t, `
[[aggregators]]
secret_name = "arbitrum_mainnet"
api_key = "key-a"
secret_key = "secret-a"
`)

	secrets, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, "postgres://env-host/db", secrets.DatabaseURL())
	require.Len(t, secrets.AggregatorSecrets(), 1)
}

func TestLoad_LegacyDefaultAggregator(t *testing.T) {
	// An entry with an omitted secret_name is the legacy default, indexed under the empty key.
	path := writeSecretsFile(t, `
[[aggregators]]
api_key = "key-default"
secret_key = "secret-default"
`)

	secrets, err := Load(path)
	require.NoError(t, err)
	aggs := secrets.AggregatorSecrets()
	require.Len(t, aggs, 1)
	require.Equal(t, AggregatorSecret{SecretName: "", APIKey: "key-default", SecretKey: "secret-default"}, aggs[""])
}

func TestLoad_StrictRejectsUnknownKey(t *testing.T) {
	// A misspelled key (api_ky) must fail loudly rather than silently leave the credential empty.
	path := writeSecretsFile(t, `
[[aggregators]]
secret_name = "arbitrum_mainnet"
api_ky = "typo"
secret_key = "secret-a"
`)

	_, err := Load(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown keys")
}

func TestLoad_RejectsMalformedTOML(t *testing.T) {
	path := writeSecretsFile(t, `[db] this is not valid toml`)

	_, err := Load(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "decode")
}

func TestLoad_RejectsDuplicateSecretName(t *testing.T) {
	path := writeSecretsFile(t, `
[[aggregators]]
secret_name = "dup"
api_key = "key-a"
secret_key = "secret-a"

[[aggregators]]
secret_name = "dup"
api_key = "key-b"
secret_key = "secret-b"
`)

	_, err := Load(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "duplicate aggregator secret_name")
}

func TestLoad_RejectsMultipleDefaults(t *testing.T) {
	path := writeSecretsFile(t, `
[[aggregators]]
api_key = "key-a"
secret_key = "secret-a"

[[aggregators]]
api_key = "key-b"
secret_key = "secret-b"
`)

	_, err := Load(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "omits secret_name")
}

func TestNewAggregatorSecrets_EmptyIsNil(t *testing.T) {
	aggs, err := NewAggregatorSecrets(nil)
	require.NoError(t, err)
	require.Nil(t, aggs)
}

func TestNewAggregatorSecrets_TrimsSecretName(t *testing.T) {
	// secret_name is trimmed on both index and lookup, so surrounding whitespace does not create a
	// phantom distinct key.
	aggs, err := NewAggregatorSecrets([]AggregatorSecret{{SecretName: "  agg  ", APIKey: "k", SecretKey: "s"}})
	require.NoError(t, err)
	require.Len(t, aggs, 1)
	_, ok := aggs["agg"]
	require.True(t, ok)
}

func TestResolveSecretsPath(t *testing.T) {
	t.Run("env set", func(t *testing.T) {
		t.Setenv(CommitteeVerifierSecretsPathEnv, "/custom/secrets.toml")
		require.Equal(t, "/custom/secrets.toml", ResolveSecretsPath(CommitteeVerifierSecretsPathEnv, "/default.toml"))
	})
	t.Run("env unset uses default", func(t *testing.T) {
		t.Setenv(CommitteeVerifierSecretsPathEnv, "")
		require.Equal(t, "/default.toml", ResolveSecretsPath(CommitteeVerifierSecretsPathEnv, "/default.toml"))
	})
}

func TestDatabaseURL_NilReceiver(t *testing.T) {
	// A nil *VerifierSecrets is the env-only path (defensive; callers normally pass a non-nil value).
	t.Setenv(DatabaseURLEnvVar, "postgres://env-host/db")
	var s *VerifierSecrets
	require.Equal(t, "postgres://env-host/db", s.DatabaseURL())
	require.Nil(t, s.AggregatorSecrets())
}
