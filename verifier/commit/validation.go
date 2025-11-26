package commit

import (
	"bytes"
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
)

// ValidateMessage validates a verification task message using the new format.
func ValidateMessage(
	verificationTask *verifier.VerificationTask,
	verifierOnRampAddress protocol.UnknownAddress,
	defaultExecutorOnRampAddress protocol.UnknownAddress,
) error {
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

	// Check if the verifier onramp address or the default executor onramp address is found as issuer in any receipt blob
	found := false
	for _, receipt := range verificationTask.ReceiptBlobs {
		isVerifierOnRamp := bytes.Equal(receipt.Issuer.Bytes(), verifierOnRampAddress.Bytes())
		isDefaultExecutorOnRamp := bytes.Equal(receipt.Issuer.Bytes(), defaultExecutorOnRampAddress.Bytes())
		if isVerifierOnRamp || isDefaultExecutorOnRamp {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf(
			"verifier onramp address %s or default executor onramp address %s not found as issuer in any receipt blob",
			verifierOnRampAddress.String(),
			defaultExecutorOnRampAddress.String(),
		)
	}

	return nil
}
