package admin

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

func TestLoadConfig(t *testing.T) {
	t.Run("parses with loopback default", func(t *testing.T) {
		cfg, err := LoadConfig(writeConfig(t, ""))
		require.NoError(t, err)
		require.Equal(t, DefaultListenAddress, cfg.ListenAddress)
	})

	t.Run("missing file is an error", func(t *testing.T) {
		_, err := LoadConfig(filepath.Join(t.TempDir(), "nope.toml"))
		require.ErrorContains(t, err, "does not exist")
	})

	t.Run("unknown keys are rejected", func(t *testing.T) {
		_, err := LoadConfig(writeConfig(t, "bogus_key = 1\n"))
		require.ErrorContains(t, err, "unknown keys")
	})

	t.Run("bad listen address is rejected", func(t *testing.T) {
		_, err := LoadConfig(writeConfig(t, `listen_address = "no-port"`+"\n"))
		require.ErrorContains(t, err, "listen_address")
	})

	t.Run("optional fields parse", func(t *testing.T) {
		cfg, err := LoadConfig(writeConfig(t, `
aggregator_address = "aggregator-1:50051"
trace_url = "https://traces.example.com"
`))
		require.NoError(t, err)
		require.Equal(t, "aggregator-1:50051", cfg.AggregatorAddress)
		require.Equal(t, "https://traces.example.com", cfg.TraceURL)
	})

	t.Run("non-loopback listen defers the identity check to startup", func(t *testing.T) {
		// The rule needs the verifier secrets (basic auth), so LoadConfig accepts
		// the file and ValidateAccessPolicy enforces it at server startup.
		cfg, err := LoadConfig(writeConfig(t, `listen_address = "0.0.0.0:8105"`+"\n"))
		require.NoError(t, err)
		require.ErrorContains(t, ValidateAccessPolicy(cfg, nil), "identity source")
		require.NoError(t, ValidateAccessPolicy(cfg, &BasicAuth{Username: "u", Password: "p"}))

		cfg, err = LoadConfig(writeConfig(t, `listen_address = "0.0.0.0:8105"
[access]
actor_header = "X-Remote-User"
`))
		require.NoError(t, err)
		require.Equal(t, "X-Remote-User", cfg.Access.ActorHeader)
		require.NoError(t, ValidateAccessPolicy(cfg, nil))
	})
}
