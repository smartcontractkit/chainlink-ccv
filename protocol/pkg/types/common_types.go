package types

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// ChainSelector represents chainlink-specific chain id
type ChainSelector uint64

func (c ChainSelector) String() string {
	return fmt.Sprintf("ChainSelector(%d)", c)
}

// SeqNum represents sequence number of the CCIP message.
type SeqNum uint64

func (s SeqNum) String() string {
	return strconv.FormatUint(uint64(s), 10)
}

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

type Bytes32 [32]byte

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
