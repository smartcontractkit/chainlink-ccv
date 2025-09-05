package commit

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
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

// VerifierBlobData represents the data stored in a verifier blob.
type VerifierBlobData struct {
	Version uint8  `json:"version"`
	Nonce   uint64 `json:"nonce"`
	// Future extensions can add more fields here
}

// EncodeVerifierBlob encodes verifier blob data using length-prefixed canonical encoding.
func EncodeVerifierBlob(nonce uint64) ([]byte, error) {
	blob := VerifierBlobData{
		Version: 1,
		Nonce:   nonce,
	}

	// Encode the blob content
	var content bytes.Buffer
	if err := content.WriteByte(blob.Version); err != nil {
		return nil, err
	}
	if err := binary.Write(&content, binary.BigEndian, blob.Nonce); err != nil {
		return nil, err
	}

	// Create length-prefixed blob: length(2 bytes) + content
	var buf bytes.Buffer
	contentBytes := content.Bytes()
	// #nosec G115 - safe because contentBytes is created here
	if err := binary.Write(&buf, binary.BigEndian, uint16(len(contentBytes))); err != nil {
		return nil, err
	}
	buf.Write(contentBytes)

	return buf.Bytes(), nil
}

// DecodeReceiptBlob decodes verifier blob data using length-prefixed canonical encoding.
func DecodeReceiptBlob(receiptBlob []byte) (uint64, error) {
	blob, err := DecodeVerifierBlobData(receiptBlob)
	if err != nil {
		return 0, err
	}
	return blob.Nonce, nil
}

// DecodeVerifierBlobData decodes complete verifier blob data using length-prefixed format.
func DecodeVerifierBlobData(receiptBlob []byte) (*VerifierBlobData, error) {
	if len(receiptBlob) < 2 {
		return nil, fmt.Errorf("receipt blob too short: %d bytes, expected at least 2", len(receiptBlob))
	}

	reader := bytes.NewReader(receiptBlob)

	// Read content length
	var contentLength uint16
	err := binary.Read(reader, binary.BigEndian, &contentLength)
	if err != nil {
		return nil, fmt.Errorf("failed to read content length: %w", err)
	}

	// Check if we have enough data for the content
	if reader.Len() < int(contentLength) {
		return nil, fmt.Errorf("insufficient data: expected %d bytes, have %d", contentLength, reader.Len())
	}

	// Read content
	content := make([]byte, contentLength)
	if _, err := io.ReadFull(reader, content); err != nil {
		return nil, fmt.Errorf("failed to read blob content: %w", err)
	}

	// Decode content
	contentReader := bytes.NewReader(content)
	blob := &VerifierBlobData{}

	// Read version
	version, err := contentReader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read version: %w", err)
	}
	blob.Version = version

	if version != 1 {
		return nil, fmt.Errorf("unsupported verifier blob version: %d", version)
	}

	// Read nonce
	err = binary.Read(contentReader, binary.BigEndian, &blob.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to read nonce: %w", err)
	}

	// Future versions can read additional fields here based on version

	return blob, nil
}

// EncodeSignatures encodes r and s arrays into signature format using canonical binary encoding.
func EncodeSignatures(rs, ss [][32]byte) ([]byte, error) {
	if len(rs) != len(ss) {
		return nil, fmt.Errorf("rs and ss arrays must have the same length")
	}

	var buf bytes.Buffer

	// Encode array length as uint16 (big-endian)
	// #nosec G115 - safe because ecdsa sigs
	arrayLen := uint16(len(rs))
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
		SequenceNumber:        message.SequenceNumber,
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
