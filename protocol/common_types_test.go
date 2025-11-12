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
