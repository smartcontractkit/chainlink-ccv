package configuration

import (
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
