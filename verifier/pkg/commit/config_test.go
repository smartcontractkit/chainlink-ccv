package commit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
)

func TestConfig_Validate_Success(t *testing.T) {
	tests := []struct {
		name   string
		config Config
	}{
		{
			name: "single chain",
			config: Config{
				CommitteeVerifierAddresses: map[string]string{
					"1": "0xCommittee1",
				},
				CommitteeConfig: chainaccess.CommitteeConfig{
					OnRampAddresses: map[string]string{
						"1": "0xOnRamp1",
					},
					RMNRemoteAddresses: map[string]string{
						"1": "0xRMNRemote1",
					},
				},
			},
		},
		{
			name: "multiple chains",
			config: Config{
				CommitteeVerifierAddresses: map[string]string{
					"1": "0xCommittee1",
					"2": "0xCommittee2",
				},
				CommitteeConfig: chainaccess.CommitteeConfig{
					OnRampAddresses: map[string]string{
						"1": "0xOnRamp1",
						"2": "0xOnRamp2",
					},
					RMNRemoteAddresses: map[string]string{
						"1": "0xRMNRemote1",
						"2": "0xRMNRemote2",
					},
				},
			},
		},
		{
			name: "empty maps",
			config: Config{
				CommitteeVerifierAddresses: map[string]string{},
				CommitteeConfig: chainaccess.CommitteeConfig{
					OnRampAddresses:    map[string]string{},
					RMNRemoteAddresses: map[string]string{},
				},
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
				CommitteeVerifierAddresses: map[string]string{
					"1": "0xCommittee1",
				},
				CommitteeConfig: chainaccess.CommitteeConfig{
					OnRampAddresses: map[string]string{
						"1": "0xOnRamp1",
						"2": "0xOnRamp2",
					},
					RMNRemoteAddresses: map[string]string{
						"1": "0xRMNRemote1",
						"2": "0xRMNRemote2",
					},
				},
			},
			errSubstr: "mismatched lengths",
		},
		{
			name: "onramp and RMN Remote length mismatch",
			config: Config{
				CommitteeVerifierAddresses: map[string]string{
					"1": "0xCommittee1",
					"2": "0xCommittee2",
				},
				CommitteeConfig: chainaccess.CommitteeConfig{
					OnRampAddresses: map[string]string{
						"1": "0xOnRamp1",
						"2": "0xOnRamp2",
					},
					RMNRemoteAddresses: map[string]string{
						"1": "0xRMNRemote1",
					},
				},
			},
			errSubstr: "mismatched lengths",
		},
		{
			name: "all three maps length mismatch",
			config: Config{
				CommitteeVerifierAddresses: map[string]string{
					"1": "0xCommittee1",
				},
				CommitteeConfig: chainaccess.CommitteeConfig{
					OnRampAddresses: map[string]string{
						"1": "0xOnRamp1",
						"2": "0xOnRamp2",
						"3": "0xOnRamp3",
					},
					RMNRemoteAddresses: map[string]string{
						"1": "0xRMNRemote1",
						"2": "0xRMNRemote2",
					},
				},
			},
			errSubstr: "mismatched lengths",
		},
		{
			name: "onramp key absent from committee verifier addresses",
			config: Config{
				CommitteeVerifierAddresses: map[string]string{
					"2": "0xCommittee2",
				},
				CommitteeConfig: chainaccess.CommitteeConfig{
					OnRampAddresses: map[string]string{
						"1": "0xOnRamp1",
					},
					RMNRemoteAddresses: map[string]string{
						"1": "0xRMNRemote1",
					},
				},
			},
			errSubstr: "not in committee verifier addresses",
		},
		{
			name: "onramp key absent from RMN Remote addresses",
			config: Config{
				CommitteeVerifierAddresses: map[string]string{
					"1": "0xCommittee1",
				},
				CommitteeConfig: chainaccess.CommitteeConfig{
					OnRampAddresses: map[string]string{
						"1": "0xOnRamp1",
					},
					RMNRemoteAddresses: map[string]string{
						"2": "0xRMNRemote2",
					},
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
