package test

import (
	"testing"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/stretchr/testify/require"
)

// Test constants.
const (
	defaultDestChain  = protocol.ChainSelector(100)
	sourceChain1      = protocol.ChainSelector(42)
	sourceChain2      = protocol.ChainSelector(84)
	unconfiguredChain = protocol.ChainSelector(999)
)

func CreateTestMessage(t *testing.T, nonce protocol.Nonce, sourceChainSelector, destChainSelector protocol.ChainSelector, finality uint16) protocol.Message {
	// Create empty token transfer
	tokenTransfer := protocol.NewEmptyTokenTransfer()

	sender := protocol.UnknownAddress([]byte("sender_address"))
	receiver := protocol.UnknownAddress([]byte("receiver_address"))
	onRampAddr := protocol.UnknownAddress([]byte("onramp_address"))
	offRampAddr := protocol.UnknownAddress([]byte("offramp_address"))

	message, err := protocol.NewMessage(
		sourceChainSelector,
		destChainSelector,
		nonce,
		onRampAddr,
		offRampAddr,
		finality,
		sender,
		receiver,
		[]byte("test data"), // dest blob
		[]byte("test data"), // data
		tokenTransfer,
	)
	require.NoError(t, err)
	return *message
}
