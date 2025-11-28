package commit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
)

// TestValidateMessageErrors tests message validation error conditions.
func TestValidateMessageErrors(t *testing.T) {
	tests := []struct {
		task            *verifier.VerificationTask
		name            string
		expectErr       string
		verifier        protocol.UnknownAddress
		defaultExecutor protocol.UnknownAddress
	}{
		{
			name:            "nil_task",
			task:            nil,
			verifier:        protocol.UnknownAddress{},
			defaultExecutor: protocol.UnknownAddress{},
			expectErr:       "verification task is nil",
		},
		{
			name: "unsupported_version",
			task: &verifier.VerificationTask{
				Message: protocol.Message{
					Version: 99, // Unsupported version
				},
			},
			verifier:        protocol.UnknownAddress{},
			defaultExecutor: protocol.UnknownAddress{},
			expectErr:       "unsupported message version",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMessage(tt.task)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectErr)
		})
	}
}
