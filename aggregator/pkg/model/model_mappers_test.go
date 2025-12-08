package model

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func TestMessageMappingRoundTrip_PreservesMessageID(t *testing.T) {
	message := createComprehensiveMessage(t)

	originalID, err := message.MessageID()
	require.NoError(t, err)

	protoMessage := common.MapProtocolMessageToProtoMessage(message)
	require.NotNil(t, protoMessage)

	convertedMessage, err := common.MapProtoMessageToProtocolMessage(protoMessage)
	require.NoError(t, err)
	require.NotNil(t, convertedMessage)

	convertedID, err := convertedMessage.MessageID()
	require.NoError(t, err)

	assert.Equal(t, originalID, convertedID, "MessageID should remain identical after round-trip conversion")
	assertMessagesEqual(t, message, convertedMessage)
}

func createComprehensiveMessage(t *testing.T) *protocol.Message {
	t.Helper()

	sender, err := protocol.RandomAddress()
	require.NoError(t, err)
	receiver, err := protocol.RandomAddress()
	require.NoError(t, err)
	onRamp, err := protocol.RandomAddress()
	require.NoError(t, err)
	offRamp, err := protocol.RandomAddress()
	require.NoError(t, err)

	tokenTransfer := &protocol.TokenTransfer{
		Version:                  protocol.MessageVersion,
		Amount:                   big.NewInt(1000000),
		SourceTokenAddressLength: 20,
		SourceTokenAddress:       make([]byte, 20),
		DestTokenAddressLength:   20,
		DestTokenAddress:         make([]byte, 20),
		TokenReceiverLength:      20,
		TokenReceiver:            make([]byte, 20),
		ExtraDataLength:          10,
		ExtraData:                []byte("extra_data"),
	}

	for i := range tokenTransfer.SourceTokenAddress {
		tokenTransfer.SourceTokenAddress[i] = byte(i + 1)
	}
	for i := range tokenTransfer.DestTokenAddress {
		tokenTransfer.DestTokenAddress[i] = byte(i + 50)
	}
	for i := range tokenTransfer.TokenReceiver {
		tokenTransfer.TokenReceiver[i] = byte(i + 100)
	}

	destBlob := make([]byte, 50)
	for i := range destBlob {
		destBlob[i] = byte(i + 200)
	}

	messageData := make([]byte, 100)
	for i := range messageData {
		messageData[i] = byte(i + 150)
	}

	message, err := protocol.NewMessage(
		protocol.ChainSelector(1337),
		protocol.ChainSelector(2337),
		protocol.SequenceNumber(12345),
		onRamp,
		offRamp,
		25,
		300_000,
		300_000,            // ccipReceiveGasLimit
		protocol.Bytes32{}, // ccvAndExecutorHash
		sender,
		receiver,
		destBlob,
		messageData,
		tokenTransfer,
	)
	require.NoError(t, err)
	return message
}

func assertMessagesEqual(t *testing.T, expected, actual *protocol.Message) {
	t.Helper()

	assert.Equal(t, expected.Version, actual.Version)
	assert.Equal(t, expected.SourceChainSelector, actual.SourceChainSelector)
	assert.Equal(t, expected.DestChainSelector, actual.DestChainSelector)
	assert.Equal(t, expected.SequenceNumber, actual.SequenceNumber)
	assert.Equal(t, expected.OnRampAddressLength, actual.OnRampAddressLength)
	assert.Equal(t, expected.OnRampAddress, actual.OnRampAddress)
	assert.Equal(t, expected.OffRampAddressLength, actual.OffRampAddressLength)
	assert.Equal(t, expected.OffRampAddress, actual.OffRampAddress)
	assert.Equal(t, expected.Finality, actual.Finality)
	assert.Equal(t, expected.SenderLength, actual.SenderLength)
	assert.Equal(t, expected.Sender, actual.Sender)
	assert.Equal(t, expected.ReceiverLength, actual.ReceiverLength)
	assert.Equal(t, expected.Receiver, actual.Receiver)
	assert.Equal(t, expected.DestBlobLength, actual.DestBlobLength)
	assert.Equal(t, expected.DestBlob, actual.DestBlob)
	assert.Equal(t, expected.TokenTransferLength, actual.TokenTransferLength)
	assert.Equal(t, expected.TokenTransfer, actual.TokenTransfer)
	assert.Equal(t, expected.DataLength, actual.DataLength)
	assert.Equal(t, expected.Data, actual.Data)

	expectedJSON, err := json.Marshal(expected)
	require.NoError(t, err, "Failed to marshal expected message to JSON")

	actualJSON, err := json.Marshal(actual)
	require.NoError(t, err, "Failed to marshal actual message to JSON")

	assert.JSONEq(t, string(expectedJSON), string(actualJSON), "JSON representations should be identical")
}
