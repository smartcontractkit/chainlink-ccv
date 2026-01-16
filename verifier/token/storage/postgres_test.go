package storage

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func TestPostgresJSONSerialization(t *testing.T) {
	// Test that Message and UnknownAddress can be properly marshaled/unmarshaled to JSON
	message, err := protocol.NewMessage(
		protocol.ChainSelector(1),
		protocol.ChainSelector(2),
		protocol.SequenceNumber(1),
		protocol.UnknownAddress{0x01, 0x02},
		protocol.UnknownAddress{0x03, 0x04},
		100,
		50000,
		40000,
		protocol.Bytes32{},
		protocol.UnknownAddress{0x05, 0x06},
		protocol.UnknownAddress{0x07, 0x08},
		[]byte{},
		[]byte("test data"),
		protocol.NewEmptyTokenTransfer(),
	)
	require.NoError(t, err)

	// Test Message JSON serialization
	messageJSON, err := json.Marshal(message)
	require.NoError(t, err)

	var unmarshaledMessage protocol.Message
	err = json.Unmarshal(messageJSON, &unmarshaledMessage)
	require.NoError(t, err)

	assert.Equal(t, message.SourceChainSelector, unmarshaledMessage.SourceChainSelector)
	assert.Equal(t, message.DestChainSelector, unmarshaledMessage.DestChainSelector)
	assert.Equal(t, message.SequenceNumber, unmarshaledMessage.SequenceNumber)

	// Test CCV addresses JSON serialization
	ccvAddresses := []protocol.UnknownAddress{
		{0x01, 0x02},
		{0x03, 0x04, 0x05},
	}

	ccvJSON, err := json.Marshal(ccvAddresses)
	require.NoError(t, err)

	var unmarshaledCCV []protocol.UnknownAddress
	err = json.Unmarshal(ccvJSON, &unmarshaledCCV)
	require.NoError(t, err)

	assert.Equal(t, ccvAddresses, unmarshaledCCV)
}
