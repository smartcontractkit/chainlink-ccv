package commit

import (
	"bytes"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/hashing"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/types"

	protocol "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

// CalculateSignatureHash calculates signature hashing using canonical binary encoding:
// keccak256(messageHash || ccvArgs).
// This matches the onchain validation in CommitOffRamp.sol:42:
// _validateSignatures(keccak256(bytes.concat(messageHash, ccvArgs)), rs, ss);.
func CalculateSignatureHash(messageHash protocol.Bytes32, ccvArgs []byte) ([32]byte, error) {
	var buf bytes.Buffer
	buf.Write(messageHash[:])
	buf.Write(ccvArgs)
	return hashing.Keccak256(buf.Bytes()), nil
}

// CreateCCVData creates CCVData from verification task, signature, and blob using the new format.
func CreateCCVData(verificationTask *types.VerificationTask, signature, verifierBlob []byte, sourceVerifierAddress protocol.UnknownAddress) (*protocol.CCVData, error) {
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
