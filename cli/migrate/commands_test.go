package migrate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeCredsFile(t *testing.T, dir, contents string) string {
	t.Helper()
	path := filepath.Join(dir, "api-creds.txt")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

func TestReadAPICredentials(t *testing.T) {
	t.Parallel()

	t.Run("email and password, CRLF tolerated", func(t *testing.T) {
		t.Parallel()
		path := writeCredsFile(t, t.TempDir(), "admin@example.com\r\nnode-password\r\n")
		email, password, err := readAPICredentials(path)
		require.NoError(t, err)
		assert.Equal(t, "admin@example.com", email)
		assert.Equal(t, "node-password", password)
	})

	t.Run("a password may contain spaces", func(t *testing.T) {
		t.Parallel()
		path := writeCredsFile(t, t.TempDir(), "admin@example.com\npass word\n")
		_, password, err := readAPICredentials(path)
		require.NoError(t, err)
		assert.Equal(t, "pass word", password)
	})

	t.Run("missing password line", func(t *testing.T) {
		t.Parallel()
		path := writeCredsFile(t, t.TempDir(), "admin@example.com\n")
		_, _, err := readAPICredentials(path)
		require.ErrorContains(t, err, "line 2")
	})

	t.Run("empty password", func(t *testing.T) {
		t.Parallel()
		path := writeCredsFile(t, t.TempDir(), "admin@example.com\n\n")
		_, _, err := readAPICredentials(path)
		require.ErrorContains(t, err, "empty password")
	})
}
