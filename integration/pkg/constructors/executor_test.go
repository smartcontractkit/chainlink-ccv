package constructors

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func TestParseSourceExecutorAddresses_SourceOnly(t *testing.T) {
	const selector protocol.ChainSelector = 42
	const rawAddress = "0x0000000000000000000000000000000000000000000000000000000000000002"
	addresses, err := parseSourceExecutorAddresses(executor.Configuration{
		SourceExecutorAddresses: map[string]string{"42": rawAddress},
	})
	require.NoError(t, err)
	expected, err := protocol.NewUnknownAddressFromHex(rawAddress)
	require.NoError(t, err)
	require.True(t, expected.Equal(addresses[selector]))
}

func TestParseSourceExecutorAddresses_InvalidSourceOnlyAddress(t *testing.T) {
	addresses, err := parseSourceExecutorAddresses(executor.Configuration{
		SourceExecutorAddresses: map[string]string{"42": "not-valid-hex"},
	})
	assert.Empty(t, addresses)
	require.ErrorContains(t, err, "failed to parse source executor address")
}
