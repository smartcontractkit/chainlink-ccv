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
