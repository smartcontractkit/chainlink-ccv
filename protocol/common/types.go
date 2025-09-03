package common

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	cciptypes "github.com/smartcontractkit/chainlink-common/pkg/types/ccipocr3"
)

// Constants for CCIP v1.7
const (
	MaxNumTokens   = 1
	MaxDataSize    = 1024 // 1kb
	MessageVersion = 1    // Current message format version
)

// UnknownAddress represents an address on an unknown chain.
type UnknownAddress []byte

// NewUnknownAddressFromHex creates an UnknownAddress from a hex string
func NewUnknownAddressFromHex(s string) (UnknownAddress, error) {
	if s == "" {
		return UnknownAddress{}, nil
	}

	// Remove 0x prefix if present
	if len(s) >= 2 && s[:2] == "0x" {
		s = s[2:]
	}

	bytes, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %w", err)
	}

	return UnknownAddress(bytes), nil
}

// String returns the hex representation of the address
func (a UnknownAddress) String() string {
	if len(a) == 0 {
		return ""
	}
	return "0x" + hex.EncodeToString(a)
}

// Bytes returns the raw bytes of the address
func (a UnknownAddress) Bytes() []byte {
	return []byte(a)
}

// TokenTransfer represents a chain-agnostic token transfer with canonical encoding
type TokenTransfer struct {
	Version                  uint8    `json:"version"`
	Amount                   *big.Int `json:"amount"`
	SourceTokenAddressLength uint8    `json:"source_token_address_length"`
	SourceTokenAddress       []byte   `json:"source_token_address"`
	DestTokenAddressLength   uint8    `json:"dest_token_address_length"`
	DestTokenAddress         []byte   `json:"dest_token_address"`
	TokenReceiverLength      uint8    `json:"token_receiver_length"`
	TokenReceiver            []byte   `json:"token_receiver"`
	ExtraDataLength          uint8    `json:"extra_data_length"`
	ExtraData                []byte   `json:"extra_data"`
}

// Encode returns the canonical encoding of this token transfer
func (tt *TokenTransfer) Encode() []byte {
	var buf bytes.Buffer

	// Version (1 byte)
	buf.WriteByte(tt.Version)

	// Amount (32 bytes, big-endian)
	amountBytes := make([]byte, 32)
	if tt.Amount != nil {
		tt.Amount.FillBytes(amountBytes)
	}
	buf.Write(amountBytes)

	// Source token address
	buf.WriteByte(tt.SourceTokenAddressLength)
	buf.Write(tt.SourceTokenAddress)

	// Dest token address
	buf.WriteByte(tt.DestTokenAddressLength)
	buf.Write(tt.DestTokenAddress)

	// Token receiver
	buf.WriteByte(tt.TokenReceiverLength)
	buf.Write(tt.TokenReceiver)

	// Extra data
	buf.WriteByte(tt.ExtraDataLength)
	buf.Write(tt.ExtraData)

	return buf.Bytes()
}

// DecodeTokenTransfer decodes a TokenTransfer from bytes
func DecodeTokenTransfer(data []byte) (*TokenTransfer, error) {
	if len(data) < 34 { // minimum size: version(1) + amount(32) + length(1)
		return nil, fmt.Errorf("data too short for token transfer")
	}

	reader := bytes.NewReader(data)
	tt := &TokenTransfer{}

	// Read version
	version, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read version: %w", err)
	}
	tt.Version = version

	// Read amount (32 bytes)
	amountBytes := make([]byte, 32)
	if _, err := io.ReadFull(reader, amountBytes); err != nil {
		return nil, fmt.Errorf("failed to read amount: %w", err)
	}
	tt.Amount = new(big.Int).SetBytes(amountBytes)

	// Read source token address
	sourceLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read source token address length: %w", err)
	}
	tt.SourceTokenAddressLength = sourceLen
	tt.SourceTokenAddress = make([]byte, sourceLen)
	if _, err := io.ReadFull(reader, tt.SourceTokenAddress); err != nil {
		return nil, fmt.Errorf("failed to read source token address: %w", err)
	}

	// Read dest token address
	destLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read dest token address length: %w", err)
	}
	tt.DestTokenAddressLength = destLen
	tt.DestTokenAddress = make([]byte, destLen)
	if _, err := io.ReadFull(reader, tt.DestTokenAddress); err != nil {
		return nil, fmt.Errorf("failed to read dest token address: %w", err)
	}

	// Read token receiver
	receiverLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read token receiver length: %w", err)
	}
	tt.TokenReceiverLength = receiverLen
	tt.TokenReceiver = make([]byte, receiverLen)
	if _, err := io.ReadFull(reader, tt.TokenReceiver); err != nil {
		return nil, fmt.Errorf("failed to read token receiver: %w", err)
	}

	// Read extra data
	extraLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read extra data length: %w", err)
	}
	tt.ExtraDataLength = extraLen
	tt.ExtraData = make([]byte, extraLen)
	if _, err := io.ReadFull(reader, tt.ExtraData); err != nil {
		return nil, fmt.Errorf("failed to read extra data: %w", err)
	}

	// Ensure all data was consumed
	if reader.Len() != 0 {
		return nil, fmt.Errorf("trailing bytes after decoding")
	}

	return tt, nil
}

// Message represents the chain-agnostic CCIP message format
type Message struct {
	// Protocol header
	Version              uint8                   `json:"version"`
	SourceChainSelector  cciptypes.ChainSelector `json:"source_chain_selector"`
	DestChainSelector    cciptypes.ChainSelector `json:"dest_chain_selector"`
	SequenceNumber       cciptypes.SeqNum        `json:"sequence_number"`
	OnRampAddressLength  uint8                   `json:"on_ramp_address_length"`
	OnRampAddress        []byte                  `json:"on_ramp_address"`
	OffRampAddressLength uint8                   `json:"off_ramp_address_length"`
	OffRampAddress       []byte                  `json:"off_ramp_address"`

	// User provided data
	Finality            uint16 `json:"finality"`
	SenderLength        uint8  `json:"sender_length"`
	Sender              []byte `json:"sender"`
	ReceiverLength      uint8  `json:"receiver_length"`
	Receiver            []byte `json:"receiver"`
	DestBlobLength      uint16 `json:"dest_blob_length"`
	DestBlob            []byte `json:"dest_blob"`
	TokenTransferLength uint16 `json:"token_transfer_length"`
	TokenTransfer       []byte `json:"token_transfer"`
	DataLength          uint16 `json:"data_length"`
	Data                []byte `json:"data"`
}

// Encode returns the canonical encoding of this message
func (m *Message) Encode() []byte {
	var buf bytes.Buffer

	// Protocol header
	buf.WriteByte(m.Version)

	// Chain selectors and sequence number (8 bytes each, big-endian)
	binary.Write(&buf, binary.BigEndian, uint64(m.SourceChainSelector))
	binary.Write(&buf, binary.BigEndian, uint64(m.DestChainSelector))
	binary.Write(&buf, binary.BigEndian, uint64(m.SequenceNumber))

	// On-ramp address
	buf.WriteByte(m.OnRampAddressLength)
	buf.Write(m.OnRampAddress)

	// Off-ramp address
	buf.WriteByte(m.OffRampAddressLength)
	buf.Write(m.OffRampAddress)

	// User provided data
	binary.Write(&buf, binary.BigEndian, m.Finality)

	// Sender
	buf.WriteByte(m.SenderLength)
	buf.Write(m.Sender)

	// Receiver
	buf.WriteByte(m.ReceiverLength)
	buf.Write(m.Receiver)

	// Dest blob
	binary.Write(&buf, binary.BigEndian, m.DestBlobLength)
	buf.Write(m.DestBlob)

	// Token transfer
	binary.Write(&buf, binary.BigEndian, m.TokenTransferLength)
	buf.Write(m.TokenTransfer)

	// Data
	binary.Write(&buf, binary.BigEndian, m.DataLength)
	buf.Write(m.Data)

	return buf.Bytes()
}

// DecodeMessage decodes a Message from bytes
func DecodeMessage(data []byte) (*Message, error) {
	if len(data) < 27 { // minimum size for required fields
		return nil, fmt.Errorf("data too short for message")
	}

	reader := bytes.NewReader(data)
	msg := &Message{}

	// Read version
	version, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read version: %w", err)
	}
	msg.Version = version

	// Read chain selectors and sequence number
	var sourceChain, destChain, seqNum uint64
	if err := binary.Read(reader, binary.BigEndian, &sourceChain); err != nil {
		return nil, fmt.Errorf("failed to read source chain selector: %w", err)
	}
	if err := binary.Read(reader, binary.BigEndian, &destChain); err != nil {
		return nil, fmt.Errorf("failed to read dest chain selector: %w", err)
	}
	if err := binary.Read(reader, binary.BigEndian, &seqNum); err != nil {
		return nil, fmt.Errorf("failed to read sequence number: %w", err)
	}

	msg.SourceChainSelector = cciptypes.ChainSelector(sourceChain)
	msg.DestChainSelector = cciptypes.ChainSelector(destChain)
	msg.SequenceNumber = cciptypes.SeqNum(seqNum)

	// Read on-ramp address
	onRampLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read on-ramp address length: %w", err)
	}
	msg.OnRampAddressLength = onRampLen
	msg.OnRampAddress = make([]byte, onRampLen)
	if _, err := io.ReadFull(reader, msg.OnRampAddress); err != nil {
		return nil, fmt.Errorf("failed to read on-ramp address: %w", err)
	}

	// Read off-ramp address
	offRampLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read off-ramp address length: %w", err)
	}
	msg.OffRampAddressLength = offRampLen
	msg.OffRampAddress = make([]byte, offRampLen)
	if _, err := io.ReadFull(reader, msg.OffRampAddress); err != nil {
		return nil, fmt.Errorf("failed to read off-ramp address: %w", err)
	}

	// Read finality
	if err := binary.Read(reader, binary.BigEndian, &msg.Finality); err != nil {
		return nil, fmt.Errorf("failed to read finality: %w", err)
	}

	// Read sender
	senderLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read sender length: %w", err)
	}
	msg.SenderLength = senderLen
	msg.Sender = make([]byte, senderLen)
	if _, err := io.ReadFull(reader, msg.Sender); err != nil {
		return nil, fmt.Errorf("failed to read sender: %w", err)
	}

	// Read receiver
	receiverLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read receiver length: %w", err)
	}
	msg.ReceiverLength = receiverLen
	msg.Receiver = make([]byte, receiverLen)
	if _, err := io.ReadFull(reader, msg.Receiver); err != nil {
		return nil, fmt.Errorf("failed to read receiver: %w", err)
	}

	// Read dest blob
	var destBlobLen uint16
	if err := binary.Read(reader, binary.BigEndian, &destBlobLen); err != nil {
		return nil, fmt.Errorf("failed to read dest blob length: %w", err)
	}
	msg.DestBlobLength = destBlobLen
	msg.DestBlob = make([]byte, destBlobLen)
	if _, err := io.ReadFull(reader, msg.DestBlob); err != nil {
		return nil, fmt.Errorf("failed to read dest blob: %w", err)
	}

	// Read token transfer
	var tokenTransferLen uint16
	if err := binary.Read(reader, binary.BigEndian, &tokenTransferLen); err != nil {
		return nil, fmt.Errorf("failed to read token transfer length: %w", err)
	}
	msg.TokenTransferLength = tokenTransferLen
	msg.TokenTransfer = make([]byte, tokenTransferLen)
	if _, err := io.ReadFull(reader, msg.TokenTransfer); err != nil {
		return nil, fmt.Errorf("failed to read token transfer: %w", err)
	}

	// Read data
	var dataLen uint16
	if err := binary.Read(reader, binary.BigEndian, &dataLen); err != nil {
		return nil, fmt.Errorf("failed to read data length: %w", err)
	}
	msg.DataLength = dataLen
	msg.Data = make([]byte, dataLen)
	if _, err := io.ReadFull(reader, msg.Data); err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}

	// Ensure all data was consumed
	if reader.Len() != 0 {
		return nil, fmt.Errorf("trailing bytes after decoding")
	}

	return msg, nil
}

// MessageID returns the message ID of this message (keccak256 of the canonical encoding)
func (m *Message) MessageID() cciptypes.Bytes32 {
	encoded := m.Encode()
	hash := crypto.Keccak256(encoded)
	var result cciptypes.Bytes32
	copy(result[:], hash)
	return result
}

// ReceiptWithBlob represents a chain-agnostic receipt with blob
type ReceiptWithBlob struct {
	Issuer UnknownAddress `json:"issuer"`
	Blob   []byte         `json:"blob"`
}

// VerificationTask represents the complete CCIPMessageSent event data from the onRamp/proxy
type VerificationTask struct {
	Message      Message           `json:"message"`       // the complete message
	ReceiptBlobs []ReceiptWithBlob `json:"receipt_blobs"` // receipt blobs from event
}

// CCVData represents Cross-Chain Verification data
type CCVData struct {
	MessageID             cciptypes.Bytes32       `json:"message_id"`
	SequenceNumber        cciptypes.SeqNum        `json:"sequence_number"`
	SourceChainSelector   cciptypes.ChainSelector `json:"source_chain_selector"`
	DestChainSelector     cciptypes.ChainSelector `json:"dest_chain_selector"`
	SourceVerifierAddress UnknownAddress          `json:"source_verifier_address"`
	DestVerifierAddress   UnknownAddress          `json:"dest_verifier_address"`
	CCVData               []byte                  `json:"ccv_data"`  // The actual proof/signature
	BlobData              []byte                  `json:"blob_data"` // Additional verifier-specific data
	Timestamp             int64                   `json:"timestamp"` // Unix timestamp when verification completed (in microseconds)
	Message               Message                 `json:"message"`   // Complete message event being verified
}

// TimestampQueryResponse represents the response from timestamp-based CCV data queries.
type TimestampQueryResponse struct {
	// Data organized by destination chain selector
	Data map[cciptypes.ChainSelector][]CCVData `json:"data"`
	// Next timestamp to query (nil if no more data)
	NextTimestamp *int64 `json:"next_timestamp,omitempty"`
	// Whether more data exists at current timestamp
	HasMore bool `json:"has_more"`
	// Total number of items returned
	TotalCount int `json:"total_count"`
}

// OffchainStorageWriter defines the interface for verifiers to store CCV data.
type OffchainStorageWriter interface {
	// StoreCCVData stores multiple CCV data entries in the offchain storage
	StoreCCVData(ctx context.Context, ccvDataList []CCVData) error
}

// OffchainStorageReader defines the interface for executors to query CCV data by timestamp.
type OffchainStorageReader interface {
	// GetCCVDataByTimestamp queries CCV data by timestamp with offset-based pagination
	GetCCVDataByTimestamp(
		ctx context.Context,
		destChainSelectors []cciptypes.ChainSelector,
		startTimestamp int64,
		sourceChainSelectors []cciptypes.ChainSelector,
		limit int,
		offset int,
	) (*TimestampQueryResponse, error)
}

// Utility functions

// Keccak256 computes the Keccak256 hash of the input
func Keccak256(data []byte) [32]byte {
	hash := crypto.Keccak256(data)
	var result [32]byte
	copy(result[:], hash)
	return result
}

// CalculateSignatureHash calculates signature hash using canonical binary encoding:
// keccak256(messageHash || keccak256(verifierBlob))
func CalculateSignatureHash(messageHash cciptypes.Bytes32, verifierBlob []byte) ([32]byte, error) {
	verifierBlobHash := Keccak256(verifierBlob)

	// Canonical encoding: simply concatenate the two 32-byte hashes
	var buf bytes.Buffer
	buf.Write(messageHash[:])
	buf.Write(verifierBlobHash[:])

	return Keccak256(buf.Bytes()), nil
}

// EncodeVerifierBlob encodes nonce into verifier blob using canonical binary encoding
func EncodeVerifierBlob(nonce uint64) ([]byte, error) {
	// Canonical encoding: 8-byte big-endian uint64
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, nonce)
	return buf.Bytes(), nil
}

// DecodeReceiptBlob decodes nonce from receipt blob using canonical binary encoding
func DecodeReceiptBlob(receiptBlob []byte) (uint64, error) {
	if len(receiptBlob) < 8 {
		return 0, fmt.Errorf("receipt blob too short: %d bytes, expected at least 8", len(receiptBlob))
	}

	// Canonical decoding: 8-byte big-endian uint64
	reader := bytes.NewReader(receiptBlob)
	var nonce uint64
	err := binary.Read(reader, binary.BigEndian, &nonce)
	if err != nil {
		return 0, fmt.Errorf("failed to decode nonce from receipt blob: %w", err)
	}

	return nonce, nil
}

// EncodeSignatures encodes r and s arrays into signature format using canonical binary encoding
func EncodeSignatures(rs, ss [][32]byte) ([]byte, error) {
	if len(rs) != len(ss) {
		return nil, fmt.Errorf("rs and ss arrays must have the same length")
	}

	var buf bytes.Buffer

	// Encode array length as uint16 (big-endian)
	arrayLen := uint16(len(rs))
	binary.Write(&buf, binary.BigEndian, arrayLen)

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

// ValidateMessage validates a verification task message using the new format
func ValidateMessage(verificationTask *VerificationTask, verifierOnRampAddress UnknownAddress) error {
	if verificationTask == nil {
		return fmt.Errorf("verification task is nil")
	}

	message := &verificationTask.Message
	if message.Version != MessageVersion {
		return fmt.Errorf("unsupported message version: %d", message.Version)
	}

	messageID := message.MessageID()
	if bytes.Equal(messageID[:], make([]byte, 32)) {
		return fmt.Errorf("message ID is empty")
	}

	// Check if the verifier onramp address is found as issuer in any receipt blob
	found := false
	for _, receipt := range verificationTask.ReceiptBlobs {
		if bytes.Equal(receipt.Issuer.Bytes(), verifierOnRampAddress.Bytes()) {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("verifier onramp address %s not found as issuer in any receipt blob", verifierOnRampAddress.String())
	}

	return nil
}

// CreateCCVData creates CCVData from verification task, signature, and blob using the new format
func CreateCCVData(verificationTask *VerificationTask, signature []byte, verifierBlob []byte, sourceVerifierAddress UnknownAddress) *CCVData {
	message := &verificationTask.Message
	return &CCVData{
		MessageID:             message.MessageID(),
		SequenceNumber:        message.SequenceNumber,
		SourceChainSelector:   message.SourceChainSelector,
		DestChainSelector:     message.DestChainSelector,
		SourceVerifierAddress: sourceVerifierAddress,
		DestVerifierAddress:   UnknownAddress{}, // Will be set by the caller if needed
		CCVData:               signature,
		BlobData:              verifierBlob,
		Timestamp:             time.Now().UnixMicro(), // Unix timestamp in microseconds
		Message:               *message,
	}
}

// Helper functions for creating empty/default values

// NewEmptyTokenTransfer creates an empty token transfer
func NewEmptyTokenTransfer() *TokenTransfer {
	return &TokenTransfer{
		Version:                  MessageVersion,
		Amount:                   big.NewInt(0),
		SourceTokenAddressLength: 0,
		SourceTokenAddress:       []byte{},
		DestTokenAddressLength:   0,
		DestTokenAddress:         []byte{},
		TokenReceiverLength:      0,
		TokenReceiver:            []byte{},
		ExtraDataLength:          0,
		ExtraData:                []byte{},
	}
}

// NewMessage creates a new message with the given parameters
func NewMessage(
	sourceChain, destChain cciptypes.ChainSelector,
	sequenceNumber cciptypes.SeqNum,
	onRampAddress, offRampAddress UnknownAddress,
	finality uint16,
	sender, receiver UnknownAddress,
	destBlob, data []byte,
	tokenTransfer *TokenTransfer,
) *Message {
	if tokenTransfer == nil {
		tokenTransfer = NewEmptyTokenTransfer()
	}

	tokenTransferBytes := tokenTransfer.Encode()

	return &Message{
		Version:              MessageVersion,
		SourceChainSelector:  sourceChain,
		DestChainSelector:    destChain,
		SequenceNumber:       sequenceNumber,
		OnRampAddressLength:  uint8(len(onRampAddress)),
		OnRampAddress:        onRampAddress.Bytes(),
		OffRampAddressLength: uint8(len(offRampAddress)),
		OffRampAddress:       offRampAddress.Bytes(),
		Finality:             finality,
		SenderLength:         uint8(len(sender)),
		Sender:               sender.Bytes(),
		ReceiverLength:       uint8(len(receiver)),
		Receiver:             receiver.Bytes(),
		DestBlobLength:       uint16(len(destBlob)),
		DestBlob:             destBlob,
		TokenTransferLength:  uint16(len(tokenTransferBytes)),
		TokenTransfer:        tokenTransferBytes,
		DataLength:           uint16(len(data)),
		Data:                 data,
	}
}

// RandomAddress generates a random address for testing
func RandomAddress() UnknownAddress {
	addr := make([]byte, 20)
	rand.Read(addr)
	return UnknownAddress(addr)
}
