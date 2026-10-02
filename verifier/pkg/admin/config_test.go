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

const validNode = `
[[nodes]]
name = "verifier-1"
secrets_path = "/etc/nodes/verifier-1/secrets.toml"
`

func TestLoadConfig(t *testing.T) {
	t.Run("parses with loopback default", func(t *testing.T) {
		cfg, err := LoadConfig(writeConfig(t, validNode))
		require.NoError(t, err)
		require.Equal(t, DefaultListenAddress, cfg.ListenAddress)
		require.Len(t, cfg.Nodes, 1)
	})

	t.Run("missing file is an error", func(t *testing.T) {
		_, err := LoadConfig(filepath.Join(t.TempDir(), "nope.toml"))
		require.ErrorContains(t, err, "does not exist")
	})

	t.Run("unknown keys are rejected", func(t *testing.T) {
		_, err := LoadConfig(writeConfig(t, validNode+"\nbogus_key = 1\n"))
		require.ErrorContains(t, err, "unknown keys")
	})

	t.Run("requires at least one node", func(t *testing.T) {
		_, err := LoadConfig(writeConfig(t, ""))
		require.ErrorContains(t, err, "at least one")
	})

	t.Run("duplicate node names are rejected", func(t *testing.T) {
		_, err := LoadConfig(writeConfig(t, validNode+validNode))
		require.ErrorContains(t, err, "duplicate node name")
	})

	t.Run("non-loopback listen requires an actor header", func(t *testing.T) {
		_, err := LoadConfig(writeConfig(t, `listen_address = "0.0.0.0:8105"`+validNode))
		require.ErrorContains(t, err, "actor_header")

		cfg, err := LoadConfig(writeConfig(t, `listen_address = "0.0.0.0:8105"
[access]
actor_header = "X-Remote-User"
`+validNode))
		require.NoError(t, err)
		require.Equal(t, "X-Remote-User", cfg.Access.ActorHeader)
	})
}
