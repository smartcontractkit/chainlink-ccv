package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validConfigTOML is a minimal config that passes Validate, with the postgres URI
// left empty the way the deployed configs leave it (LoadConfig fills it from
// secrets.toml at runtime).
const validConfigTOML = `
[Monitoring]
LogLevel = "info"

[[Discoveries]]
Address = "aggregator:50051"
PollInterval = 500
Timeout = 5000
NtpServer = "time.google.com"

[Scheduler]
TickerInterval = 50
VerificationVisibilityWindow = 86400
BaseDelay = 100
MaxDelay = 30_000

[[Verifier]]
Type = "aggregator"
Name = "default-verifier"
Address = "aggregator:50051"
BatchSize = 100
MaxBatchWaitTime = 50

[Storage]
Strategy = "single"

[Storage.Single]
Type = "postgres"

[Storage.Single.Postgres]
URI = ""
MaxOpenConnections = 20
MaxIdleConnections = 5
`

const validGeneratedTOML = `
[[Verifier]]
Name = "default-verifier"
IssuerAddresses = ["0x1111111111111111111111111111111111111111"]
`

// writeConfigPair writes the main config (with GeneratedConfigPath pointing at the
// generated file) and the generated config into one temp dir, and returns the main
// config path.
func writeConfigPair(t *testing.T, mainTOML, generatedTOML string) string {
	t.Helper()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "generated.toml"), []byte(generatedTOML), 0o600))

	mainPath := filepath.Join(dir, "indexer.toml")
	withPath := `GeneratedConfigPath = "generated.toml"` + "\n" + mainTOML
	require.NoError(t, os.WriteFile(mainPath, []byte(withPath), 0o600))

	return mainPath
}

func TestValidateConfigFile(t *testing.T) {
	t.Parallel()

	t.Run("clean config passes without secrets", func(t *testing.T) {
		t.Parallel()

		path := writeConfigPair(t, validConfigTOML, validGeneratedTOML)

		unmatched, err := ValidateConfigFile(path)
		require.NoError(t, err)
		assert.Empty(t, unmatched)
	})

	t.Run("no generated config path is fine", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "indexer.toml")
		require.NoError(t, os.WriteFile(path, []byte(validConfigTOML), 0o600))

		unmatched, err := ValidateConfigFile(path)
		require.NoError(t, err)
		assert.Empty(t, unmatched)
	})

	t.Run("unmatched generated entries are reported without failing", func(t *testing.T) {
		t.Parallel()

		path := writeConfigPair(t, validConfigTOML, `
[[Verifier]]
Name = "some-other-verifier"
IssuerAddresses = ["0x1111111111111111111111111111111111111111"]
`)

		unmatched, err := ValidateConfigFile(path)
		require.NoError(t, err, "LoadConfig only logs unmatched names, so this must not fail")
		assert.Equal(t, []string{"some-other-verifier"}, unmatched)
	})

	t.Run("unknown key in the main config is reported as drift", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "indexer.toml")
		require.NoError(t, os.WriteFile(path, []byte(validConfigTOML+"\nbogusTopLevel = 1\n"), 0o600))

		_, err := ValidateConfigFile(path)
		require.ErrorContains(t, err, "unknown keys")
		require.ErrorContains(t, err, "bogusTopLevel")
	})

	t.Run("unknown key in the generated config is reported as drift", func(t *testing.T) {
		t.Parallel()

		path := writeConfigPair(t, validConfigTOML, `
[[Verifier]]
Name = "default-verifier"
IssuerAddresses = ["0x1111111111111111111111111111111111111111"]
BogusField = true
`)

		_, err := ValidateConfigFile(path)
		require.ErrorContains(t, err, "generated.toml")
		require.ErrorContains(t, err, "BogusField")
	})

	t.Run("bare-integer duration is a type-mismatch decode error", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "indexer.toml")
		// common.Duration fields require quoted strings; a bare int would otherwise
		// be read as nanoseconds.
		require.NoError(t, os.WriteFile(path, []byte(validConfigTOML+"\n[Resilience]\nRequestTimeout = 5\n"), 0o600))

		_, err := ValidateConfigFile(path)
		require.ErrorContains(t, err, "must be a quoted string")
	})

	t.Run("missing generated config file errors", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		path := filepath.Join(dir, "indexer.toml")
		require.NoError(t, os.WriteFile(path,
			[]byte(`GeneratedConfigPath = "does-not-exist.toml"`+"\n"+validConfigTOML), 0o600))

		_, err := ValidateConfigFile(path)
		require.ErrorContains(t, err, "does-not-exist.toml")
	})

	t.Run("decodes cleanly but fails semantic validation", func(t *testing.T) {
		t.Parallel()

		// Timeout must exceed PollInterval. Everything else is valid so that the
		// discovery check is the one that fails.
		path := filepath.Join(t.TempDir(), "indexer.toml")
		broken := `
[Monitoring]
LogLevel = "info"

[[Discoveries]]
Address = "aggregator:50051"
PollInterval = 5000
Timeout = 500
NtpServer = "time.google.com"

[Scheduler]
TickerInterval = 50
VerificationVisibilityWindow = 86400
BaseDelay = 100
MaxDelay = 30_000

[Storage]
Strategy = "single"

[Storage.Single]
Type = "postgres"

[Storage.Single.Postgres]
MaxOpenConnections = 20
`
		require.NoError(t, os.WriteFile(path, []byte(broken), 0o600))

		_, err := ValidateConfigFile(path)
		require.ErrorContains(t, err, "validation")
		require.ErrorContains(t, err, "timeout must be greater than poll interval")
	})

	t.Run("missing main config file errors", func(t *testing.T) {
		t.Parallel()

		_, err := ValidateConfigFile(filepath.Join(t.TempDir(), "nope.toml"))
		require.Error(t, err)
	})
}
