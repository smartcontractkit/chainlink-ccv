package verifiercli

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseLCABlockNumber(t *testing.T) {
	t.Parallel()

	out := `{"level":"INFO","logger":"ccv-cli","msg":"Using the EVM database"}
Last Common Ancestor

--------------------------------------------------------------------------------
ChainID:      1337
Block Hash:   0x6b3f8f1f2a6c8f1e5d0a9e0c1b2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d
Block Number: 42
--------------------------------------------------------------------------------
`
	got, err := ParseLCABlockNumber(out)
	require.NoError(t, err)
	require.Equal(t, uint64(42), got)

	_, err = ParseLCABlockNumber("find-lca for EVM chain ID 1337 failed")
	require.ErrorContains(t, err, "no block number")
}
