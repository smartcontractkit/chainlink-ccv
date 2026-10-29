package services

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vsecrets"
)

func TestGenerateVerifierSecretsAndAdminConsoleConfig(t *testing.T) {
	dir := t.TempDir()

	secretsBytes, err := GenerateVerifierSecrets("postgresql://user:pass@db:5432/verifier", []vsecrets.AggregatorSecret{
		{SecretName: "agg-1", APIKey: "k1", SecretKey: "s1"},
	})
	require.NoError(t, err)

	secretsPath := filepath.Join(dir, "secrets.toml")
	require.NoError(t, os.WriteFile(secretsPath, secretsBytes, 0o600))

	secrets, err := vsecrets.Load(secretsPath)
	require.NoError(t, err)
	require.Equal(t, "postgresql://user:pass@db:5432/verifier", secrets.DatabaseURL())
	require.NotNil(t, secrets.AdminUIAuth())
	require.Equal(t, DefaultAdminUIUsername, secrets.AdminUIAuth().Username)
	require.Equal(t, DefaultAdminUIPassword, secrets.AdminUIAuth().Password)

	cfgBytes, err := GenerateAdminConsoleConfig()
	require.NoError(t, err)

	var cfg adminConsoleConfig
	md, err := toml.Decode(string(cfgBytes), &cfg)
	require.NoError(t, err)
	require.Empty(t, md.Undecoded())
	require.Equal(t, DefaultAdminConsoleListenAddr, cfg.ListenAddress)
}
