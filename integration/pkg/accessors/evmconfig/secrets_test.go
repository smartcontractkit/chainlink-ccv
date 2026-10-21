package evmconfig

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"
)

func TestSecretsDecodeAndValidate(t *testing.T) {
	var s Secrets
	md, err := toml.Decode(`
[db]
url = "postgres://localhost/evm"

[[chains."1".nodes]]
name = "a"
http_url = "https://a"
ws_url = "wss://a"
`, &s)
	require.NoError(t, err)
	require.Empty(t, md.Undecoded())
	require.NoError(t, s.Validate())
	require.Equal(t, "wss://a", s.Chains["1"].Nodes[0].WSUrl)
	require.Equal(t, "postgres://localhost/evm", s.DB.URL)
}

func TestSecretsValidateErrors(t *testing.T) {
	tests := map[string]struct {
		secrets Secrets
		want    string
	}{
		"no nodes":       {Secrets{Chains: map[string]ChainSecrets{"1": {}}}, "at least one node is required"},
		"missing name":   {Secrets{Chains: map[string]ChainSecrets{"1": {Nodes: []NodeSecrets{{HTTPUrl: "h"}}}}}, "field 'name' is required"},
		"missing url":    {Secrets{Chains: map[string]ChainSecrets{"1": {Nodes: []NodeSecrets{{Name: "a"}}}}}, "field 'http_url' is required"},
		"missing db url": {Secrets{DB: &DBConfig{}}, "field 'url' is required"},
		"duplicate":      {Secrets{Chains: map[string]ChainSecrets{"1": {Nodes: []NodeSecrets{{Name: "a", HTTPUrl: "h"}, {Name: "a", HTTPUrl: "h"}}}}}, `duplicate node name "a"`},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			require.ErrorContains(t, tc.secrets.Validate(), tc.want)
		})
	}
	require.NoError(t, (&Secrets{}).Validate())
}

func TestConfigValidate(t *testing.T) {
	ok := Config{Chains: map[string]ChainConfig{"1": {Nodes: []Node{{HTTPUrl: "h", Order: 100}}}}}
	require.NoError(t, ok.Validate())

	tests := map[string]struct {
		cfg  Config
		want string
	}{
		"no nodes":      {Config{Chains: map[string]ChainConfig{"1": {}}}, "at least one node is required"},
		"missing url":   {Config{Chains: map[string]ChainConfig{"1": {Nodes: []Node{{Name: "a"}}}}}, "field 'http_url' is required"},
		"order range":   {Config{Chains: map[string]ChainConfig{"1": {Nodes: []Node{{HTTPUrl: "h", Order: 101}}}}}, "field 'order' must be between"},
		"negative size": {Config{Chains: map[string]ChainConfig{"1": {Nodes: []Node{{HTTPUrl: "h"}}, SourceReaderHeaderFetchBatchSize: -1}}}, "must not be negative"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			require.ErrorContains(t, tc.cfg.Validate(), tc.want)
		})
	}
}

func TestLoadSecretsFile(t *testing.T) {
	got, err := LoadSecretsFile("")
	require.NoError(t, err)
	require.Equal(t, &Secrets{}, got)

	path := filepath.Join(t.TempDir(), "secrets.toml")
	require.NoError(t, os.WriteFile(path, []byte("[db]\nurl = \"postgres://localhost/evm\"\n"), 0o600))
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
