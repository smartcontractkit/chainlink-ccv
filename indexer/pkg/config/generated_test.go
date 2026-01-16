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
			name: "valid verifier config parses successfully with qualifier keys",
			data: `
[Verifier.default]
IssuerAddresses = ["0x1234567890abcdef1234567890abcdef12345678"]

[Verifier.CCTP]
IssuerAddresses = ["0xabcdef1234567890abcdef1234567890abcdef12", "0x9876543210fedcba9876543210fedcba98765432"]
`,
			expectError: false,
			validate: func(t *testing.T, cfg *GeneratedConfig) {
				require.NotNil(t, cfg.Verifier)
				assert.Len(t, cfg.Verifier, 2)
				assert.Len(t, cfg.Verifier["default"].IssuerAddresses, 1)
				assert.Len(t, cfg.Verifier["CCTP"].IssuerAddresses, 2)
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
		name              string
		mainConfig        *Config
		generated         *GeneratedConfig
		expectedUnmatched []string
		validate          func(t *testing.T, cfg *Config)
	}{
		{
			name:              "nil generated config does not modify main config",
			mainConfig:        &Config{Verifiers: []VerifierConfig{{IssuerAddressesQualifier: "default"}}},
			generated:         nil,
			expectedUnmatched: nil,
			validate: func(t *testing.T, cfg *Config) {
				assert.Empty(t, cfg.Verifiers[0].IssuerAddresses)
			},
		},
		{
			name:       "generated addresses are added to verifier with matching qualifier",
			mainConfig: &Config{Verifiers: []VerifierConfig{{IssuerAddressesQualifier: "default"}}},
			generated: &GeneratedConfig{
				Verifier: map[string]GeneratedVerifierConfig{
					"default": {IssuerAddresses: []string{"0xaaa", "0xbbb"}},
				},
			},
			expectedUnmatched: nil,
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, []string{"0xaaa", "0xbbb"}, cfg.Verifiers[0].IssuerAddresses)
			},
		},
		{
			name: "generated addresses are merged with existing addresses",
			mainConfig: &Config{
				Verifiers: []VerifierConfig{
					{IssuerAddressesQualifier: "default", IssuerAddresses: []string{"0xexisting1", "0xexisting2"}},
				},
			},
			generated: &GeneratedConfig{
				Verifier: map[string]GeneratedVerifierConfig{
					"default": {IssuerAddresses: []string{"0xgenerated1", "0xgenerated2"}},
				},
			},
			expectedUnmatched: nil,
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
					{IssuerAddressesQualifier: "default", IssuerAddresses: []string{"0xAAA", "0xBBB"}},
				},
			},
			generated: &GeneratedConfig{
				Verifier: map[string]GeneratedVerifierConfig{
					"default": {IssuerAddresses: []string{"0xaaa", "0xccc"}},
				},
			},
			expectedUnmatched: nil,
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
					{IssuerAddressesQualifier: "default", IssuerAddresses: []string{"0xAbCdEf"}},
				},
			},
			generated: &GeneratedConfig{
				Verifier: map[string]GeneratedVerifierConfig{
					"default": {IssuerAddresses: []string{"0xABCDEF"}},
				},
			},
			expectedUnmatched: nil,
			validate: func(t *testing.T, cfg *Config) {
				assert.Len(t, cfg.Verifiers[0].IssuerAddresses, 1)
				assert.Equal(t, "0xAbCdEf", cfg.Verifiers[0].IssuerAddresses[0])
			},
		},
		{
			name: "verifier without qualifier is not modified and generated qualifier is unmatched",
			mainConfig: &Config{Verifiers: []VerifierConfig{
				{IssuerAddresses: []string{"0xoriginal"}},
			}},
			generated: &GeneratedConfig{
				Verifier: map[string]GeneratedVerifierConfig{
					"default": {IssuerAddresses: []string{"0xaaa"}},
				},
			},
			expectedUnmatched: []string{"default"},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, []string{"0xoriginal"}, cfg.Verifiers[0].IssuerAddresses)
			},
		},
		{
			name: "unmatched qualifier in generated config is returned",
			mainConfig: &Config{Verifiers: []VerifierConfig{
				{IssuerAddressesQualifier: "default", IssuerAddresses: []string{"0xoriginal"}},
			}},
			generated: &GeneratedConfig{
				Verifier: map[string]GeneratedVerifierConfig{
					"unknown": {IssuerAddresses: []string{"0xaaa"}},
				},
			},
			expectedUnmatched: []string{"unknown"},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, []string{"0xoriginal"}, cfg.Verifiers[0].IssuerAddresses)
			},
		},
		{
			name: "multiple verifiers can be merged by qualifier",
			mainConfig: &Config{
				Verifiers: []VerifierConfig{
					{IssuerAddressesQualifier: "default", IssuerAddresses: []string{"0xv0"}},
					{IssuerAddressesQualifier: "secondary", IssuerAddresses: []string{"0xv1"}},
					{IssuerAddressesQualifier: "CCTP"},
				},
			},
			generated: &GeneratedConfig{
				Verifier: map[string]GeneratedVerifierConfig{
					"default": {IssuerAddresses: []string{"0xv0-gen"}},
					"CCTP":    {IssuerAddresses: []string{"0xv2-gen"}},
				},
			},
			expectedUnmatched: nil,
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, []string{"0xv0", "0xv0-gen"}, cfg.Verifiers[0].IssuerAddresses)
				assert.Equal(t, []string{"0xv1"}, cfg.Verifiers[1].IssuerAddresses)
				assert.Equal(t, []string{"0xv2-gen"}, cfg.Verifiers[2].IssuerAddresses)
			},
		},
		{
			name: "multiple unmatched qualifiers are all returned",
			mainConfig: &Config{Verifiers: []VerifierConfig{
				{IssuerAddressesQualifier: "default"},
			}},
			generated: &GeneratedConfig{
				Verifier: map[string]GeneratedVerifierConfig{
					"default": {IssuerAddresses: []string{"0xaaa"}},
					"unknown": {IssuerAddresses: []string{"0xbbb"}},
					"missing": {IssuerAddresses: []string{"0xccc"}},
				},
			},
			expectedUnmatched: []string{"unknown", "missing"},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, []string{"0xaaa"}, cfg.Verifiers[0].IssuerAddresses)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unmatched := MergeGeneratedConfig(tt.mainConfig, tt.generated)
			assert.ElementsMatch(t, tt.expectedUnmatched, unmatched)
			if tt.validate != nil {
				tt.validate(t, tt.mainConfig)
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
