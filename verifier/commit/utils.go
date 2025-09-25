package commit

import (
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
)

// CreateCCVData creates CCVData from verification task and signature using the new format.
func CreateCCVData(verificationTask *verifier.VerificationTask, signature, verifierBlob []byte, sourceVerifierAddress protocol.UnknownAddress) (*protocol.CCVData, error) {
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
