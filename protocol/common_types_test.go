package protocol

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNilUnknownAddress(t *testing.T) {
	var ua UnknownAddress
	require.Equal(t, []byte(nil), ua.Bytes())
}

func TestBytes16_RoundTrip(t *testing.T) {
	original, err := NewBytes16FromString("0x0102030405060708090a0b0c0d0e0f10")
	require.NoError(t, err)

	// String -> NewBytes16FromString
	str := original.String()
	parsed, err := NewBytes16FromString(str)
	require.NoError(t, err)
	require.Equal(t, original, parsed)

	// Marshal -> Unmarshal
	jsonBytes, err := json.Marshal(original)
	require.NoError(t, err)
	var unmarshaled Bytes16
	err = json.Unmarshal(jsonBytes, &unmarshaled)
	require.NoError(t, err)
	require.Equal(t, original, unmarshaled)
}

func TestNewBytes16FromString_LeftPadding(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected Bytes16
	}{
		{
			name:  "full length - 32 hex chars",
			input: "0x0102030405060708090a0b0c0d0e0f10",
			expected: Bytes16{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			},
		},
		{
			name:  "short input - should be left-padded with zeros",
			input: "0x1234",
			expected: Bytes16{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34,
			},
		},
		{
			name:  "single byte",
			input: "0xff",
			expected: Bytes16{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
			},
		},
		{
			name:  "empty hex (just 0x)",
			input: "0x",
			expected: Bytes16{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			name:  "10 bytes - should be left-padded",
			input: "0x0102030405060708090a",
			expected: Bytes16{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02,
				0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := NewBytes16FromString(tt.input)
			require.NoError(t, err)
			require.Equal(t, tt.expected, result, "Expected %v, got %v", tt.expected, result)
		})
	}
}

func TestNewBytes32FromString_LeftPadding(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected Bytes32
	}{
		{
			name:  "full length - 64 hex chars",
			input: "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
			expected: Bytes32{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
				0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
				0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
			},
		},
		{
			name:  "short input - should be left-padded with zeros",
			input: "0x1234",
			expected: Bytes32{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34,
			},
		},
		{
			name:  "single byte",
			input: "0xff",
			expected: Bytes32{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
			},
		},
		{
			name:  "empty hex (just 0x)",
			input: "0x",
			expected: Bytes32{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			name:  "16 bytes - should be left-padded",
			input: "0x0102030405060708090a0b0c0d0e0f10",
			expected: Bytes32{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := NewBytes32FromString(tt.input)
			require.NoError(t, err)
			require.Equal(t, tt.expected, result, "Expected %v, got %v", tt.expected, result)
		})
	}
}

func TestByteSlice_UnmarshalJSON_Validation(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expectErr bool
		errMsg    string
	}{
		{
			name:      "valid hex string",
			input:     `"0x1234567890abcdef"`,
			expectErr: false,
		},
		{
			name:      "valid empty string",
			input:     `"0x"`,
			expectErr: false,
		},
		{
			name:      "valid null",
			input:     `null`,
			expectErr: false,
		},
		{
			name:      "invalid hex characters",
			input:     `"0xzzz"`,
			expectErr: true,
			errMsg:    "failed to decode hex",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var bs ByteSlice
			err := json.Unmarshal([]byte(tt.input), &bs)
			if tt.expectErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					require.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestByteSlice_UnmarshalJSON_DirectCall(t *testing.T) {
	// Test direct calls to UnmarshalJSON to verify quote validation
	tests := []struct {
		name      string
		input     []byte
		expectErr bool
		errMsg    string
	}{
		{
			name:      "valid quoted string",
			input:     []byte(`"0x1234"`),
			expectErr: false,
		},
		{
			name:      "missing starting quote",
			input:     []byte(`0x1234"`),
			expectErr: true,
			errMsg:    "invalid JSON string format",
		},
		{
			name:      "missing ending quote",
			input:     []byte(`"0x1234`),
			expectErr: true,
			errMsg:    "invalid JSON string format",
		},
		{
			name:      "no quotes at all",
			input:     []byte(`0x1234`),
			expectErr: true,
			errMsg:    "invalid JSON string format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var bs ByteSlice
			err := bs.UnmarshalJSON(tt.input)
			if tt.expectErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					require.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestBytes16_UnmarshalJSON_Validation(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expectErr bool
		errMsg    string
	}{
		{
			name:      "valid 16 bytes (32 hex chars)",
			input:     `"0x0102030405060708090a0b0c0d0e0f10"`,
			expectErr: false,
		},
		{
			name:      "invalid - too short (missing leading zeros)",
			input:     `"0x0102030405060708090a0b0c0d0e0f"`,
			expectErr: true,
			errMsg:    "must be exactly 32 hex characters",
		},
		{
			name:      "invalid - too long",
			input:     `"0x0102030405060708090a0b0c0d0e0f1011"`,
			expectErr: true,
			errMsg:    "must be exactly 32 hex characters",
		},
		{
			name:      "invalid - trimmed leading zeros",
			input:     `"0x1234"`,
			expectErr: true,
			errMsg:    "must be exactly 32 hex characters",
		},
		{
			name:      "missing 0x prefix",
			input:     `"0102030405060708090a0b0c0d0e0f10"`,
			expectErr: true,
			errMsg:    "must start with '0x' prefix",
		},
		{
			name:      "invalid hex characters",
			input:     `"0x0102030405060708090a0b0c0d0e0fzz"`,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b Bytes16
			err := json.Unmarshal([]byte(tt.input), &b)
			if tt.expectErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					require.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestBytes16_UnmarshalJSON_DirectCall(t *testing.T) {
	// Test direct calls to UnmarshalJSON to verify quote validation
	tests := []struct {
		name      string
		input     []byte
		expectErr bool
		errMsg    string
	}{
		{
			name:      "valid quoted string",
			input:     []byte(`"0x0102030405060708090a0b0c0d0e0f10"`),
			expectErr: false,
		},
		{
			name:      "missing starting quote",
			input:     []byte(`0x0102030405060708090a0b0c0d0e0f10"`),
			expectErr: true,
			errMsg:    "invalid JSON string format",
		},
		{
			name:      "missing ending quote",
			input:     []byte(`"0x0102030405060708090a0b0c0d0e0f10`),
			expectErr: true,
			errMsg:    "invalid JSON string format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b Bytes16
			err := b.UnmarshalJSON(tt.input)
			if tt.expectErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					require.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestBytes32_UnmarshalJSON_Validation(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expectErr bool
		errMsg    string
	}{
		{
			name:      "valid 32 bytes (64 hex chars)",
			input:     `"0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"`,
			expectErr: false,
		},
		{
			name:      "invalid - too short (missing leading zeros)",
			input:     `"0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"`,
			expectErr: true,
			errMsg:    "must be exactly 64 hex characters",
		},
		{
			name:      "invalid - too long",
			input:     `"0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021"`,
			expectErr: true,
			errMsg:    "must be exactly 64 hex characters",
		},
		{
			name:      "invalid - trimmed leading zeros",
			input:     `"0x1234"`,
			expectErr: true,
			errMsg:    "must be exactly 64 hex characters",
		},
		{
			name:      "missing 0x prefix",
			input:     `"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"`,
			expectErr: true,
			errMsg:    "must start with '0x' prefix",
		},
		{
			name:      "invalid hex characters",
			input:     `"0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fzz"`,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b Bytes32
			err := json.Unmarshal([]byte(tt.input), &b)
			if tt.expectErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					require.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestBytes32_UnmarshalJSON_DirectCall(t *testing.T) {
	// Test direct calls to UnmarshalJSON to verify quote validation
	tests := []struct {
		name      string
		input     []byte
		expectErr bool
		errMsg    string
	}{
		{
			name:      "valid quoted string",
			input:     []byte(`"0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"`),
			expectErr: false,
		},
		{
			name:      "missing starting quote",
			input:     []byte(`0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"`),
			expectErr: true,
			errMsg:    "invalid JSON string format",
		},
		{
			name:      "missing ending quote",
			input:     []byte(`"0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20`),
			expectErr: true,
			errMsg:    "invalid JSON string format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b Bytes32
			err := b.UnmarshalJSON(tt.input)
			if tt.expectErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					require.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}
