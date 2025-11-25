package protocol

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// ChainSelector represents chainlink-specific chain id.
type ChainSelector uint64

func (c ChainSelector) String() string {
	return fmt.Sprintf("ChainSelector(%d)", c)
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
	return []byte(fmt.Sprintf(`"%s"`, a.String())), nil
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

// ByteSlice is a wrapper around []byte that marshals/unmarshals to/from hex instead of base64.
type ByteSlice []byte

// MarshalJSON returns the hex representation of the bytes.
func (h ByteSlice) MarshalJSON() ([]byte, error) {
	if h == nil {
		return []byte("null"), nil
	}
	if len(h) == 0 {
		return []byte(`"0x"`), nil
	}
	return []byte(fmt.Sprintf(`"0x%s"`, hex.EncodeToString(h))), nil
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
	return []byte(fmt.Sprintf(`"%s"`, b.String())), nil
}

func (b *Bytes16) UnmarshalJSON(data []byte) error {
	v := string(data)
	if len(v) < 4 {
		return fmt.Errorf("invalid Bytes16: %s", v)
	}
	v = v[1 : len(v)-1] // trim quotes

	if !strings.HasPrefix(v, "0x") {
		return fmt.Errorf("bytes must start with '0x' prefix: %s", v)
	}
	v = v[2:] // trim 0x prefix

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
	return []byte(fmt.Sprintf(`"%s"`, b.String())), nil
}

func (b *Bytes32) UnmarshalJSON(data []byte) error {
	v := string(data)
	if len(v) < 4 {
		return fmt.Errorf("invalid Bytes32: %s", v)
	}
	v = v[1 : len(v)-1] // trim quotes

	if !strings.HasPrefix(v, "0x") {
		return fmt.Errorf("bytes must start with '0x' prefix: %s", v)
	}
	v = v[2:] // trim 0x prefix

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
	DestChainSelector ChainSelector     // Destination chain for the message
	SequenceNumber    uint64            // Sequential nonce for this message
	MessageID         Bytes32           // Unique identifier for the message
	Message           Message           // The decoded CCIP message
	Receipts          []ReceiptWithBlob // Verifier receipts + executor receipt
	BlockNumber       uint64            // Block number where event occurred
}
