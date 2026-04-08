package commit

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
)

// ValidateVerificationTask validates a verification task, including its message and blobs.
func ValidateVerificationTask(verificationTask *verifier.VerificationTask) error {
	if verificationTask == nil {
		return fmt.Errorf("verification task is nil")
	}

	message := verificationTask.Message
	if message.Version != protocol.MessageVersion {
		return fmt.Errorf("unsupported message version: %d", message.Version)
	}

	if message.Sender.IsZeroOrEmpty() {
		return fmt.Errorf("sender cannot be empty or zero")
	}

	if message.Receiver.IsZeroOrEmpty() {
		return fmt.Errorf("receiver cannot be empty or zero")
	}

	if len(verificationTask.ReceiptBlobs) == 0 {
		return fmt.Errorf("receipt blobs list is empty, at least one receipt blob is required")
	}

	return nil
}
