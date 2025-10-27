package verifier

import (
	"context"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// CreateCCVData creates CCVData from verification task and signature using the new format.
func CreateCCVData(verificationTask *VerificationTask, signature, verifierBlob []byte, sourceVerifierAddress protocol.UnknownAddress) (*protocol.CCVData, error) {
	message := verificationTask.Message
	messageID, err := message.MessageID()
	if err != nil {
		return nil, fmt.Errorf("failed to compute message ID: %w", err)
	}
	return &protocol.CCVData{
		MessageID:             messageID,
		Nonce:                 message.Nonce,
		SourceChainSelector:   message.SourceChainSelector,
		DestChainSelector:     message.DestChainSelector,
		SourceVerifierAddress: sourceVerifierAddress,
		DestVerifierAddress:   protocol.UnknownAddress{}, // Will be set by the caller if needed
		CCVData:               signature,
		BlobData:              verifierBlob,           // Additional verifier-specific data
		Timestamp:             time.Now().UnixMicro(), // Unix timestamp in microseconds
		Message:               message,
		ReceiptBlobs:          verificationTask.ReceiptBlobs, // Include all receipt blobs for executors
	}, nil
}

// TODO: Unused, delete?
// sendVerificationError sends a verification error to the error channel.
func sendVerificationError(ctx context.Context, task VerificationTask, err error, verificationErrorCh chan<- VerificationError, lggr logger.Logger) {
	verificationError := VerificationError{
		Task:      task,
		Error:     err,
		Timestamp: time.Now(),
	}

	select {
	case verificationErrorCh <- verificationError:
		lggr.Errorw("Verification error sent to error channel", "error", err)
	case <-ctx.Done():
		lggr.Debugw("Context cancelled while sending verification error", "error", err)
	}
}

// FindVerifierIndexBySourceAddress finds the index of the source verifier address in the ReceiptBlobs array.
func findVerifierIndexBySourceAddress(verificationTask *VerificationTask, sourceVerifierAddress protocol.UnknownAddress) (int, error) {
	for i, receipt := range verificationTask.ReceiptBlobs {
		if receipt.Issuer.String() == sourceVerifierAddress.String() {
			return i, nil
		}
	}

	return -1, fmt.Errorf("source verifier address %s not found in ReceiptBlobs", sourceVerifierAddress.String())
}
