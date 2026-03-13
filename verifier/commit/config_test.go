package commit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_Validate_Success(t *testing.T) {
	tests := []struct {
		name   string
		config Config
	}{
		{
			name: "single chain",
			config: Config{
				OnRampAddresses: map[string]string{
					"1": "0xOnRamp1",
				},
				CommitteeVerifierAddresses: map[string]string{
					"1": "0xCommittee1",
				},
				RMNRemoteAddresses: map[string]string{
					"1": "0xRMNRemote1",
				},
			},
		},
		{
			name: "multiple chains",
			config: Config{
				OnRampAddresses: map[string]string{
					"1": "0xOnRamp1",
					"2": "0xOnRamp2",
				},
				CommitteeVerifierAddresses: map[string]string{
					"1": "0xCommittee1",
					"2": "0xCommittee2",
				},
				RMNRemoteAddresses: map[string]string{
					"1": "0xRMNRemote1",
					"2": "0xRMNRemote2",
				},
			},
		},
		{
			name: "empty maps",
			config: Config{
				OnRampAddresses:            map[string]string{},
				CommitteeVerifierAddresses: map[string]string{},
				RMNRemoteAddresses:         map[string]string{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			require.NoError(t, err)
		})
	}
}

func TestConfig_Validate_Errors(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		errSubstr string
	}{
		{
			name: "onramp and committee length mismatch",
			config: Config{
				OnRampAddresses: map[string]string{
					"1": "0xOnRamp1",
					"2": "0xOnRamp2",
				},
				CommitteeVerifierAddresses: map[string]string{
					"1": "0xCommittee1",
				},
				RMNRemoteAddresses: map[string]string{
					"1": "0xRMNRemote1",
					"2": "0xRMNRemote2",
				},
			},
			errSubstr: "mismatched lengths",
		},
		{
			name: "onramp and RMN Remote length mismatch",
			config: Config{
				OnRampAddresses: map[string]string{
					"1": "0xOnRamp1",
					"2": "0xOnRamp2",
				},
				CommitteeVerifierAddresses: map[string]string{
					"1": "0xCommittee1",
					"2": "0xCommittee2",
				},
				RMNRemoteAddresses: map[string]string{
					"1": "0xRMNRemote1",
				},
			},
			errSubstr: "mismatched lengths",
		},
		{
			name: "all three maps length mismatch",
			config: Config{
				OnRampAddresses: map[string]string{
					"1": "0xOnRamp1",
					"2": "0xOnRamp2",
					"3": "0xOnRamp3",
				},
				CommitteeVerifierAddresses: map[string]string{
					"1": "0xCommittee1",
				},
				RMNRemoteAddresses: map[string]string{
					"1": "0xRMNRemote1",
					"2": "0xRMNRemote2",
				},
			},
			errSubstr: "mismatched lengths",
		},
		{
			name: "onramp key absent from committee verifier addresses",
			config: Config{
				OnRampAddresses: map[string]string{
					"1": "0xOnRamp1",
				},
				CommitteeVerifierAddresses: map[string]string{
					"2": "0xCommittee2",
				},
				RMNRemoteAddresses: map[string]string{
					"1": "0xRMNRemote1",
				},
			},
			errSubstr: "not in committee verifier addresses",
		},
		{
			name: "onramp key absent from RMN Remote addresses",
			config: Config{
				OnRampAddresses: map[string]string{
					"1": "0xOnRamp1",
				},
				CommitteeVerifierAddresses: map[string]string{
					"1": "0xCommittee1",
				},
				RMNRemoteAddresses: map[string]string{
					"2": "0xRMNRemote2",
				},
			},
			errSubstr: "not in RMN Remote addresses",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errSubstr)
		})
	}
}
