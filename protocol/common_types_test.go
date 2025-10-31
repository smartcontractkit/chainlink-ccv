package protocol

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNilUnknownAddress(t *testing.T) {
	var ua UnknownAddress
	require.Equal(t, []byte(nil), ua.Bytes())
}
