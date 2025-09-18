package commit

import (
	"bytes"
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/types"

	types2 "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

// ValidateMessage validates a verification task message using the new format.
func ValidateMessage(verificationTask *types.VerificationTask, verifierOnRampAddress types2.UnknownAddress) error {
	if verificationTask == nil {
		return fmt.Errorf("verification task is nil")
	}

	message := verificationTask.Message
	if message.Version != types2.MessageVersion {
		return fmt.Errorf("unsupported message version: %d", message.Version)
	}

	messageID, err := message.MessageID()
	if err != nil {
		return fmt.Errorf("failed to compute message ID: %w", err)
	}
	if bytes.Equal(messageID[:], make([]byte, 32)) {
		return fmt.Errorf("message ID is empty")
	}

	// Check if the verifier onramp address is found as issuer in any receipt blob

	return nil
}
