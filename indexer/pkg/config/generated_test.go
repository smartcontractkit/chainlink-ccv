package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadGeneratedConfigFromBytes(t *testing.T) {
	tests := []struct {
		name        string
		data        string
		expectError bool
		errorMsg    string
		validate    func(t *testing.T, cfg *GeneratedConfig)
	}{
		{
			name:        "empty config parses successfully",
			data:        "",
			expectError: false,
			validate: func(t *testing.T, cfg *GeneratedConfig) {
				assert.Nil(t, cfg.Verifier)
			},
		},
		{
			name: "valid verifier config parses successfully",
			data: `
[Verifier.0]
IssuerAddresses = ["0x1234567890abcdef1234567890abcdef12345678"]

[Verifier.1]
IssuerAddresses = ["0xabcdef1234567890abcdef1234567890abcdef12", "0x9876543210fedcba9876543210fedcba98765432"]
`,
			expectError: false,
			validate: func(t *testing.T, cfg *GeneratedConfig) {
				require.NotNil(t, cfg.Verifier)
				assert.Len(t, cfg.Verifier, 2)
				assert.Len(t, cfg.Verifier["0"].IssuerAddresses, 1)
				assert.Len(t, cfg.Verifier["1"].IssuerAddresses, 2)
			},
		},
		{
			name:        "invalid TOML returns error",
			data:        "[[invalid",
			expectError: true,
			errorMsg:    "failed to parse TOML generated config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := LoadGeneratedConfigFromBytes([]byte(tt.data))

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

func TestMergeGeneratedConfig(t *testing.T) {
	tests := []struct {
		name        string
		mainConfig  *Config
		generated   *GeneratedConfig
		expectError bool
		errorMsg    string
		validate    func(t *testing.T, cfg *Config)
	}{
		{
			name:        "nil generated config does not modify main config",
			mainConfig:  &Config{Verifiers: []VerifierConfig{{}}},
			generated:   nil,
			expectError: false,
			validate: func(t *testing.T, cfg *Config) {
				assert.Empty(t, cfg.Verifiers[0].IssuerAddresses)
			},
		},
		{
			name:       "generated addresses are added to empty main config",
			mainConfig: &Config{Verifiers: []VerifierConfig{{}}},
			generated: &GeneratedConfig{
				Verifier: map[string]GeneratedVerifierConfig{
					"0": {IssuerAddresses: []string{"0xaaa", "0xbbb"}},
				},
			},
			expectError: false,
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, []string{"0xaaa", "0xbbb"}, cfg.Verifiers[0].IssuerAddresses)
			},
		},
		{
			name: "generated addresses are merged with existing addresses",
			mainConfig: &Config{
				Verifiers: []VerifierConfig{
					{IssuerAddresses: []string{"0xexisting1", "0xexisting2"}},
				},
			},
			generated: &GeneratedConfig{
				Verifier: map[string]GeneratedVerifierConfig{
					"0": {IssuerAddresses: []string{"0xgenerated1", "0xgenerated2"}},
				},
			},
			expectError: false,
			validate: func(t *testing.T, cfg *Config) {
				assert.Len(t, cfg.Verifiers[0].IssuerAddresses, 4)
				assert.Contains(t, cfg.Verifiers[0].IssuerAddresses, "0xexisting1")
				assert.Contains(t, cfg.Verifiers[0].IssuerAddresses, "0xexisting2")
				assert.Contains(t, cfg.Verifiers[0].IssuerAddresses, "0xgenerated1")
				assert.Contains(t, cfg.Verifiers[0].IssuerAddresses, "0xgenerated2")
			},
		},
		{
			name: "duplicate addresses are deduplicated case-insensitively",
			mainConfig: &Config{
				Verifiers: []VerifierConfig{
					{IssuerAddresses: []string{"0xAAA", "0xBBB"}},
				},
			},
			generated: &GeneratedConfig{
				Verifier: map[string]GeneratedVerifierConfig{
					"0": {IssuerAddresses: []string{"0xaaa", "0xccc"}},
				},
			},
			expectError: false,
			validate: func(t *testing.T, cfg *Config) {
				assert.Len(t, cfg.Verifiers[0].IssuerAddresses, 3)
				assert.Equal(t, "0xAAA", cfg.Verifiers[0].IssuerAddresses[0])
				assert.Equal(t, "0xBBB", cfg.Verifiers[0].IssuerAddresses[1])
				assert.Equal(t, "0xccc", cfg.Verifiers[0].IssuerAddresses[2])
			},
		},
		{
			name: "original address casing is preserved on deduplication",
			mainConfig: &Config{
				Verifiers: []VerifierConfig{
					{IssuerAddresses: []string{"0xAbCdEf"}},
				},
			},
			generated: &GeneratedConfig{
				Verifier: map[string]GeneratedVerifierConfig{
					"0": {IssuerAddresses: []string{"0xABCDEF"}},
				},
			},
			expectError: false,
			validate: func(t *testing.T, cfg *Config) {
				assert.Len(t, cfg.Verifiers[0].IssuerAddresses, 1)
				assert.Equal(t, "0xAbCdEf", cfg.Verifiers[0].IssuerAddresses[0])
			},
		},
		{
			name:       "invalid verifier index returns error",
			mainConfig: &Config{Verifiers: []VerifierConfig{{}}},
			generated: &GeneratedConfig{
				Verifier: map[string]GeneratedVerifierConfig{
					"invalid": {IssuerAddresses: []string{"0xaaa"}},
				},
			},
			expectError: true,
			errorMsg:    "invalid verifier index in generated config",
		},
		{
			name:       "out of range verifier index returns error",
			mainConfig: &Config{Verifiers: []VerifierConfig{{}}},
			generated: &GeneratedConfig{
				Verifier: map[string]GeneratedVerifierConfig{
					"5": {IssuerAddresses: []string{"0xaaa"}},
				},
			},
			expectError: true,
			errorMsg:    "verifier index 5 in generated config is out of range",
		},
		{
			name:       "negative verifier index returns error",
			mainConfig: &Config{Verifiers: []VerifierConfig{{}}},
			generated: &GeneratedConfig{
				Verifier: map[string]GeneratedVerifierConfig{
					"-1": {IssuerAddresses: []string{"0xaaa"}},
				},
			},
			expectError: true,
			errorMsg:    "verifier index -1 in generated config is out of range",
		},
		{
			name: "multiple verifiers can be merged",
			mainConfig: &Config{
				Verifiers: []VerifierConfig{
					{IssuerAddresses: []string{"0xv0"}},
					{IssuerAddresses: []string{"0xv1"}},
					{},
				},
			},
			generated: &GeneratedConfig{
				Verifier: map[string]GeneratedVerifierConfig{
					"0": {IssuerAddresses: []string{"0xv0-gen"}},
					"2": {IssuerAddresses: []string{"0xv2-gen"}},
				},
			},
			expectError: false,
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, []string{"0xv0", "0xv0-gen"}, cfg.Verifiers[0].IssuerAddresses)
				assert.Equal(t, []string{"0xv1"}, cfg.Verifiers[1].IssuerAddresses)
				assert.Equal(t, []string{"0xv2-gen"}, cfg.Verifiers[2].IssuerAddresses)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := MergeGeneratedConfig(tt.mainConfig, tt.generated)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, tt.mainConfig)
				}
			}
		})
	}
}

func TestMergeAddresses(t *testing.T) {
	tests := []struct {
		name       string
		existing   []string
		additional []string
		expected   []string
	}{
		{
			name:       "empty slices return empty result",
			existing:   nil,
			additional: nil,
			expected:   []string{},
		},
		{
			name:       "only existing addresses",
			existing:   []string{"0xaaa", "0xbbb"},
			additional: nil,
			expected:   []string{"0xaaa", "0xbbb"},
		},
		{
			name:       "only additional addresses",
			existing:   nil,
			additional: []string{"0xccc", "0xddd"},
			expected:   []string{"0xccc", "0xddd"},
		},
		{
			name:       "no duplicates merges all",
			existing:   []string{"0xaaa", "0xbbb"},
			additional: []string{"0xccc", "0xddd"},
			expected:   []string{"0xaaa", "0xbbb", "0xccc", "0xddd"},
		},
		{
			name:       "duplicates are removed case-insensitively",
			existing:   []string{"0xAAA", "0xBBB"},
			additional: []string{"0xaaa", "0xCCC"},
			expected:   []string{"0xAAA", "0xBBB", "0xCCC"},
		},
		{
			name:       "first occurrence casing is preserved",
			existing:   []string{"0xAbCdEf"},
			additional: []string{"0xABCDEF", "0xabcdef"},
			expected:   []string{"0xAbCdEf"},
		},
		{
			name:       "duplicates within existing are removed",
			existing:   []string{"0xaaa", "0xAAA", "0xbbb"},
			additional: nil,
			expected:   []string{"0xaaa", "0xbbb"},
		},
		{
			name:       "duplicates within additional are removed",
			existing:   nil,
			additional: []string{"0xaaa", "0xAAA", "0xbbb"},
			expected:   []string{"0xaaa", "0xbbb"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mergeAddresses(tt.existing, tt.additional)
			assert.Equal(t, tt.expected, result)
		})
	}
}
