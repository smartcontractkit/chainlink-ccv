package evmconfig

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadSecretsFile(t *testing.T) {
	got, err := LoadSecretsFile("")
	require.NoError(t, err)
	require.Equal(t, &Secrets{}, got)

	path := filepath.Join(t.TempDir(), "secrets.toml")
	require.NoError(t, os.WriteFile(path, []byte(`
[db]
url = "postgres://localhost/evm"
`), 0o600))
	got, err = LoadSecretsFile(path)
	require.NoError(t, err)
	require.Equal(t, "postgres://localhost/evm", got.DB.URL)

	require.NoError(t, os.WriteFile(path, []byte("[db]\n"), 0o600))
	_, err = LoadSecretsFile(path)
	require.ErrorContains(t, err, "field 'url' is required")

	require.NoError(t, os.WriteFile(path, []byte("[dbb]\nurl = \"x\"\n"), 0o600))
	_, err = LoadSecretsFile(path)
	require.ErrorContains(t, err, "unknown fields")
}
