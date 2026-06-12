package configuration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

func TestLoadGeneratedConfigString(t *testing.T) {
	tests := []struct {
		name        string
		configStr   string
		expectError bool
		errorMsg    string
		validate    func(t *testing.T, cfg *model.GeneratedConfig)
	}{
		{
			name:        "empty config parses successfully",
			configStr:   "",
			expectError: false,
			validate: func(t *testing.T, cfg *model.GeneratedConfig) {
				assert.Nil(t, cfg.Committee)
			},
		},
		{
			name: "valid committee config parses successfully",
			configStr: `
[committee]
[committee.quorumConfigs.1]
sourceVerifierAddress = "0x1234567890abcdef1234567890abcdef12345678"
threshold = 1
[[committee.quorumConfigs.1.signers]]
address = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[committee.destinationVerifiers]
"2" = "0xabcdef1234567890abcdef1234567890abcdef12"
`,
			expectError: false,
			validate: func(t *testing.T, cfg *model.GeneratedConfig) {
				require.NotNil(t, cfg.Committee)
				assert.Len(t, cfg.Committee.QuorumConfigs, 1)
				assert.Len(t, cfg.Committee.DestinationVerifiers, 1)
			},
		},
		{
			name:        "invalid TOML returns error",
			configStr:   "[[invalid",
			expectError: true,
			errorMsg:    "failed to parse generated config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := LoadGeneratedConfigString(tt.configStr)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, cfg)
				if tt.validate != nil {
					tt.validate(t, cfg)
				}
			}
		})
	}
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestValidateConfigFile(t *testing.T) {
	t.Run("clean config with merged generated config passes", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "generated.toml", `
[committee]
[committee.destinationVerifiers]
"2" = "0xabcdef1234567890abcdef1234567890abcdef12"
`)
		main := writeFile(t, dir, "aggregator.toml", `
pyroscope_url = "http://pyroscope:4040"
generatedConfigPath = "generated.toml"
[server]
address = ":50051"
[storage]
type = "postgres"
connMaxLifetime = "1h"
`)
		require.NoError(t, ValidateConfigFile(main))
	})

	t.Run("unknown key in main config is reported as drift", func(t *testing.T) {
		dir := t.TempDir()
		main := writeFile(t, dir, "aggregator.toml", `
[storage]
type = "postgres"
connMaxIdleTimeTYPO = "5m"
`)
		err := ValidateConfigFile(main)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "aggregator.toml")
		assert.Contains(t, err.Error(), "storage.connMaxIdleTimeTYPO")
	})

	t.Run("bare-int duration is a type-mismatch decode error", func(t *testing.T) {
		// Reproduces the original deploy failure: common.Duration rejects bare ints.
		dir := t.TempDir()
		main := writeFile(t, dir, "aggregator.toml", `
[storage]
connMaxLifetime = 0
`)
		err := ValidateConfigFile(main)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decode error")
	})

	t.Run("unknown key in generated config is reported", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "generated.toml", `
[committee]
bogusKey = true
`)
		main := writeFile(t, dir, "aggregator.toml", `
generatedConfigPath = "generated.toml"
`)
		err := ValidateConfigFile(main)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "generated.toml")
		assert.Contains(t, err.Error(), "committee.bogusKey")
	})

	t.Run("missing generated config file errors", func(t *testing.T) {
		dir := t.TempDir()
		main := writeFile(t, dir, "aggregator.toml", `
generatedConfigPath = "does-not-exist.toml"
`)
		err := ValidateConfigFile(main)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does-not-exist.toml")
	})

	t.Run("missing main config file errors", func(t *testing.T) {
		err := ValidateConfigFile(filepath.Join(t.TempDir(), "nope.toml"))
		require.Error(t, err)
	})
}
