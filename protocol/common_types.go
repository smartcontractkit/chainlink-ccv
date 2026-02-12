package protocol

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// ChainSelector represents chainlink-specific chain id.
type ChainSelector uint64

func (c ChainSelector) String() string {
	return strconv.FormatUint(uint64(c), 10)
}

// Nonce represents a monotonic counter used for adding entropy and uniqueness to a CCIP message.
type Nonce uint64

func (n Nonce) String() string {
	return strconv.FormatUint(uint64(n), 10)
}

// SequenceNumber represents a sequential identifier for messages in a CCIP lane.
type SequenceNumber uint64

// UnknownAddress represents an address on an unknown chain.
type UnknownAddress []byte

// NewUnknownAddressFromHex creates an UnknownAddress from a hex string.
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

// String returns the hex representation of the address.
func (a UnknownAddress) String() string {
	if len(a) == 0 {
		return ""
	}
	return "0x" + hex.EncodeToString(a)
}

// Bytes returns the raw bytes of the address.
func (a UnknownAddress) Bytes() []byte {
	return []byte(a)
}

// MarshalJSON returns the hex representation of the address.
func (a UnknownAddress) MarshalJSON() ([]byte, error) {
	return fmt.Appendf(nil, `"%s"`, a.String()), nil
}

// UnmarshalJSON decodes a hex string into an UnknownAddress.
func (a *UnknownAddress) UnmarshalJSON(data []byte) error {
	v := string(data)
	if len(v) < 2 {
		return fmt.Errorf("invalid UnknownAddress: %s", v)
	}

	// Handle empty string
	if v == `""` {
		*a = UnknownAddress{}
		return nil
	}

	// trim quotes
	v = v[1 : len(v)-1]

	// Remove 0x prefix if present
	v = strings.TrimPrefix(v, "0x")

	bytes, err := hex.DecodeString(v)
	if err != nil {
		return fmt.Errorf("failed to decode hex: %w", err)
	}

	*a = UnknownAddress(bytes)
	return nil
}

// Equal checks if another UnknownAddress is equal to this one.
func (a UnknownAddress) Equal(other UnknownAddress) bool {
	return bytes.Equal(a.Bytes(), other.Bytes())
}

// ByteSlice is a wrapper around []byte that marshals/unmarshals to/from hex instead of base64.
type ByteSlice []byte

func NewByteSliceFromHex(s string) (ByteSlice, error) {
	if s == "" {
		return ByteSlice{}, nil
	}

	// Remove 0x prefix if present
	if len(s) >= 2 && s[:2] == "0x" {
		s = s[2:]
	}

	bytes, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %w", err)
	}

	return ByteSlice(bytes), nil
}

// MarshalJSON returns the hex representation of the bytes.
func (h ByteSlice) MarshalJSON() ([]byte, error) {
	if h == nil {
		return []byte("null"), nil
	}
	if len(h) == 0 {
		return []byte(`"0x"`), nil
	}
	return fmt.Appendf(nil, `"0x%s"`, hex.EncodeToString(h)), nil
}

// UnmarshalJSON decodes a hex string into HexBytes.
func (h *ByteSlice) UnmarshalJSON(data []byte) error {
	v := string(data)

	// Handle null
	if v == "null" {
		*h = nil
		return nil
	}

	if len(v) < 2 {
		return fmt.Errorf("invalid HexBytes: %s", v)
	}

	// Check that the string starts and ends with quotes before trimming
	if v[0] != '"' || v[len(v)-1] != '"' {
		return fmt.Errorf("invalid JSON string format for HexBytes: %s", v)
	}

	// trim quotes
	v = v[1 : len(v)-1]

	// Handle empty string
	if v == "" || v == "0x" {
		*h = ByteSlice{}
		return nil
	}

	// Remove 0x prefix if present
	v = strings.TrimPrefix(v, "0x")

	bytes, err := hex.DecodeString(v)
	if err != nil {
		return fmt.Errorf("failed to decode hex: %w", err)
	}

	*h = ByteSlice(bytes)
	return nil
}

// String returns the hex representation with 0x prefix.
func (h ByteSlice) String() string {
	if len(h) == 0 {
		return "0x"
	}
	return "0x" + hex.EncodeToString(h)
}

type Bytes16 [16]byte

// NewBytes16FromString creates 16-sized bytes array from hex-encoded string or returns an error.
func NewBytes16FromString(s string) (Bytes16, error) {
	if len(s) > 34 { // "0x" + 32 hex chars
		return Bytes16{}, fmt.Errorf("Bytes16 must be at most 16 bytes (32 hex chars) long: %s", s)
	}

	if !strings.HasPrefix(s, "0x") {
		return Bytes16{}, fmt.Errorf("Bytes16 must start with '0x' prefix: %s", s)
	}

	b, err := hex.DecodeString(s[2:])
	if err != nil {
		return Bytes16{}, fmt.Errorf("failed to decode hex: %w", err)
	}

	var res Bytes16
	copy(res[:], b)
	return res, nil
}

func (b Bytes16) String() string {
	return "0x" + hex.EncodeToString(b[:])
}

func (b Bytes16) IsEmpty() bool {
	return b == Bytes16{}
}

func (b Bytes16) MarshalJSON() ([]byte, error) {
	return fmt.Appendf(nil, `"%s"`, b.String()), nil
}

func (b *Bytes16) UnmarshalJSON(data []byte) error {
	v := string(data)
	if len(v) < 4 {
		return fmt.Errorf("invalid Bytes16: %s", v)
	}

	// Check that the string starts and ends with quotes before trimming
	if v[0] != '"' || v[len(v)-1] != '"' {
		return fmt.Errorf("invalid JSON string format for Bytes16: %s", v)
	}

	v = v[1 : len(v)-1] // trim quotes

	if !strings.HasPrefix(v, "0x") {
		return fmt.Errorf("bytes must start with '0x' prefix: %s", v)
	}
	v = v[2:] // trim 0x prefix

	// Check that the hex string is exactly 32 characters (16 bytes)
	if len(v) != 32 {
		return fmt.Errorf("Bytes16 must be exactly 32 hex characters (16 bytes), got %d characters: %s", len(v), v)
	}

	bCp, err := hex.DecodeString(v)
	if err != nil {
		return err
	}

	copy(b[:], bCp)
	return nil
}

type Bytes32 [32]byte

// NewBytes32FromString creates 32-sized bytes array from hex-encoded string or returns an error.
func NewBytes32FromString(s string) (Bytes32, error) {
	if len(s) > 66 { // "0x" + 64 hex chars
		return Bytes32{}, fmt.Errorf("Bytes32 must be at most 32 bytes (64 hex chars) long: %s", s)
	}

	if !strings.HasPrefix(s, "0x") {
		return Bytes32{}, fmt.Errorf("Bytes32 must start with '0x' prefix: %s", s)
	}

	b, err := hex.DecodeString(s[2:])
	if err != nil {
		return Bytes32{}, fmt.Errorf("failed to decode hex: %w", err)
	}

	var res Bytes32
	copy(res[:], b)
	return res, nil
}

func (b Bytes32) String() string {
	return "0x" + hex.EncodeToString(b[:])
}

func (b Bytes32) IsEmpty() bool {
	return b == Bytes32{}
}

func (b Bytes32) MarshalJSON() ([]byte, error) {
	return fmt.Appendf(nil, `"%s"`, b.String()), nil
}

func (b *Bytes32) UnmarshalJSON(data []byte) error {
	v := string(data)
	if len(v) < 4 {
		return fmt.Errorf("invalid Bytes32: %s", v)
	}

	// Check that the string starts and ends with quotes before trimming
	if v[0] != '"' || v[len(v)-1] != '"' {
		return fmt.Errorf("invalid JSON string format for Bytes32: %s", v)
	}

	v = v[1 : len(v)-1] // trim quotes

	if !strings.HasPrefix(v, "0x") {
		return fmt.Errorf("bytes must start with '0x' prefix: %s", v)
	}
	v = v[2:] // trim 0x prefix

	// Check that the hex string is exactly 64 characters (32 bytes)
	if len(v) != 64 {
		return fmt.Errorf("Bytes32 must be exactly 64 hex characters (32 bytes), got %d characters: %s", len(v), v)
	}

	bCp, err := hex.DecodeString(v)
	if err != nil {
		return err
	}

	copy(b[:], bCp)
	return nil
}

// MessageSentEvent represents a CCIPMessageSent event from the blockchain.
// This is the protocol-level representation of the OnRamp CCIPMessageSent event,
// decoupled from chain-specific implementations.
// Note: Message and ReceiptWithBlob types are defined in message_types.go.
type MessageSentEvent struct {
	MessageID   Bytes32           // Unique identifier for the message
	Message     Message           // The decoded CCIP message
	Receipts    []ReceiptWithBlob // Verifier receipts + executor receipt
	BlockNumber uint64            // Block number where event occurred
	TxHash      ByteSlice         // Transaction hash of the event
}

// CCVAddressInfo represents the ccv verifier addresses needed to submit a message.
// These addresses correspond to destination chain verifiers.
type CCVAddressInfo struct {
	RequiredCCVs      []UnknownAddress `json:"required_ccvs"`
	OptionalCCVs      []UnknownAddress `json:"optional_ccvs"`
	OptionalThreshold uint8            `json:"optional_threshold"`
}

// AbstractAggregatedReport represents the aggregated report for a message.
// This is the protocol-level representation of the report to submit to destination chain.
type AbstractAggregatedReport struct {
	CCVS    []UnknownAddress
	CCVData [][]byte
	Message Message
}

// MarshalJSON implements the json.Marshaler interface for AbstractAggregatedReport.
// CCVS and CCVData are marshaled as hex strings.
func (a AbstractAggregatedReport) MarshalJSON() ([]byte, error) {
	ccvData := make([]ByteSlice, len(a.CCVData))
	for i, data := range a.CCVData {
		ccvData[i] = ByteSlice(data)
	}
	return json.Marshal(struct {
		CCVS    []UnknownAddress `json:"ccvs"`
		CCVData []ByteSlice      `json:"ccv_data"`
		Message Message          `json:"message"`
	}{
		CCVS:    a.CCVS,
		CCVData: ccvData,
		Message: a.Message,
	})
}

// ExecutionAttempt represents a chain-agnostic on-chain attempt.
type ExecutionAttempt struct {
	Report              AbstractAggregatedReport
	TransactionGasLimit *big.Int
}
