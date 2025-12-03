package commit

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
)

// ValidateMessage validates a verification task message using the new format.
func ValidateMessage(verificationTask *verifier.VerificationTask) error {
	if verificationTask == nil {
		return fmt.Errorf("verification task is nil")
	}

	message := verificationTask.Message
	// TODO: this check seems redundant - its already done in Verifier.ValidateMessage.
	if message.Version != protocol.MessageVersion {
		return fmt.Errorf("unsupported message version: %d", message.Version)
	}

	// Receipt blobs list must not be empty
	if len(verificationTask.ReceiptBlobs) == 0 {
		return fmt.Errorf("receipt blobs list is empty, at least one receipt blob is required")
	}

	return nil
}
