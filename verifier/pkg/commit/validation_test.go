package commit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
)

// TestValidateVerificationTask tests validation error conditions.
func TestValidateVerificationTask(t *testing.T) {
	validBlobs := []protocol.ReceiptWithBlob{{}}

	tests := []struct {
		name      string
		task      *verifier.VerificationTask
		expectErr string
	}{
		{
			name:      "nil_task",
			task:      nil,
			expectErr: "verification task is nil",
		},
		{
			name: "unsupported_version",
			task: &verifier.VerificationTask{
				Message: protocol.Message{
					Version: 99,
				},
			},
			expectErr: "unsupported message version",
		},
		{
			name: "empty_sender",
			task: &verifier.VerificationTask{
				Message: protocol.Message{
					Version: protocol.MessageVersion,
					Sender:  nil,
				},
			},
			expectErr: "sender cannot be empty",
		},
		{
			name: "empty_receiver",
			task: &verifier.VerificationTask{
				Message: protocol.Message{
					Version:  protocol.MessageVersion,
					Sender:   []byte{1},
					Receiver: nil,
				},
			},
			expectErr: "receiver cannot be empty",
		},
		{
			name: "empty_verifier_blobs",
			task: &verifier.VerificationTask{
				Message: protocol.Message{
					Version:  protocol.MessageVersion,
					Sender:   []byte{1},
					Receiver: []byte{2},
				},
				ReceiptBlobs: []protocol.ReceiptWithBlob{},
			},
			expectErr: "receipt blobs list is empty",
		},
		{
			name: "nil_verifier_blobs",
			task: &verifier.VerificationTask{
				Message: protocol.Message{
					Version:  protocol.MessageVersion,
					Sender:   []byte{1},
					Receiver: []byte{2},
				},
				ReceiptBlobs: nil,
			},
			expectErr: "receipt blobs list is empty",
		},
		{
			name: "valid_task",
			task: &verifier.VerificationTask{
				Message: protocol.Message{
					Version:  protocol.MessageVersion,
					Sender:   []byte{1},
					Receiver: []byte{2},
				},
				ReceiptBlobs: validBlobs,
			},
			expectErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateVerificationTask(tt.task)
			if tt.expectErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectErr)
			}
		})
	}
}
