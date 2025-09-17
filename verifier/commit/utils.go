package commit

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/types"

	protocol "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

// Keccak256 computes the Keccak256 hash of the input.
func Keccak256(data []byte) [32]byte {
	hash := crypto.Keccak256(data)
	var result [32]byte
	copy(result[:], hash)
	return result
}

// CalculateSignatureHash calculates signature hash using canonical binary encoding:
// keccak256(messageHash || keccak256(verifierBlob)).
func CalculateSignatureHash(messageHash protocol.Bytes32, verifierBlob []byte) ([32]byte, error) {
	verifierBlobHash := Keccak256(verifierBlob)

	// Canonical encoding: simply concatenate the two 32-byte hashes
	var buf bytes.Buffer
	buf.Write(messageHash[:])
	buf.Write(verifierBlobHash[:])

	return Keccak256(buf.Bytes()), nil
}

// EncodeSignatures encodes r and s arrays into signature format using canonical binary encoding.
func EncodeSignatures(rs, ss [][32]byte) ([]byte, error) {
	rsLen := len(rs)
	if rsLen != len(ss) {
		return nil, fmt.Errorf("rs and ss arrays must have the same length")
	}

	var buf bytes.Buffer

	// Encode array length as uint16 (big-endian)
	if rsLen > math.MaxUint16 {
		return nil, fmt.Errorf("rs and ss arrays exceeds maximum length")
	}
	arrayLen := uint16(rsLen)
	if err := binary.Write(&buf, binary.BigEndian, arrayLen); err != nil {
		return nil, err
	}

	// Encode rs array
	for _, r := range rs {
		buf.Write(r[:])
	}

	// Encode ss array
	for _, s := range ss {
		buf.Write(s[:])
	}

	return buf.Bytes(), nil
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
