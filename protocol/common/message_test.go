package common

import (
	"math/big"
	"testing"

	cciptypes "github.com/smartcontractkit/chainlink-common/pkg/types/ccipocr3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenTransferEncodeDecode(t *testing.T) {
	// Create a test token transfer
	tt := &TokenTransfer{
		Version:                  1,
		Amount:                   big.NewInt(1000),
		SourceTokenAddressLength: 3,
		SourceTokenAddress:       []byte("abc"),
		DestTokenAddressLength:   4,
		DestTokenAddress:         []byte("wxyz"),
		TokenReceiverLength:      2,
		TokenReceiver:            []byte("R1"),
		ExtraDataLength:          5,
		ExtraData:                []byte("hello"),
	}

	// Encode
	encoded := tt.Encode()
	require.NotEmpty(t, encoded)

	// Decode
	decoded, err := DecodeTokenTransfer(encoded)
	require.NoError(t, err)

	// Verify all fields match
	assert.Equal(t, tt.Version, decoded.Version)
	assert.Equal(t, tt.Amount.Cmp(decoded.Amount), 0)
	assert.Equal(t, tt.SourceTokenAddressLength, decoded.SourceTokenAddressLength)
	assert.Equal(t, tt.SourceTokenAddress, decoded.SourceTokenAddress)
	assert.Equal(t, tt.DestTokenAddressLength, decoded.DestTokenAddressLength)
	assert.Equal(t, tt.DestTokenAddress, decoded.DestTokenAddress)
	assert.Equal(t, tt.TokenReceiverLength, decoded.TokenReceiverLength)
	assert.Equal(t, tt.TokenReceiver, decoded.TokenReceiver)
	assert.Equal(t, tt.ExtraDataLength, decoded.ExtraDataLength)
	assert.Equal(t, tt.ExtraData, decoded.ExtraData)
}

func TestMessageEncodeDecode(t *testing.T) {
	// Create test addresses
	sender := RandomAddress()
	receiver := RandomAddress()
	onRampAddr := RandomAddress()
	offRampAddr := RandomAddress()

	// Create empty token transfer
	tokenTransfer := NewEmptyTokenTransfer()

	// Create a test message
	msg := NewMessage(
		cciptypes.ChainSelector(1337),
		cciptypes.ChainSelector(2337),
		cciptypes.SeqNum(123),
		onRampAddr,
		offRampAddr,
		10, // finality
		sender,
		receiver,
		[]byte("test dest blob"),
		[]byte("test data"),
		tokenTransfer,
	)

	// Encode
	encoded := msg.Encode()
	require.NotEmpty(t, encoded)

	// Decode
	decoded, err := DecodeMessage(encoded)
	require.NoError(t, err)

	// Verify all fields match
	assert.Equal(t, msg.Version, decoded.Version)
	assert.Equal(t, msg.SourceChainSelector, decoded.SourceChainSelector)
	assert.Equal(t, msg.DestChainSelector, decoded.DestChainSelector)
	assert.Equal(t, msg.SequenceNumber, decoded.SequenceNumber)
	assert.Equal(t, msg.OnRampAddressLength, decoded.OnRampAddressLength)
	assert.Equal(t, msg.OnRampAddress, decoded.OnRampAddress)
	assert.Equal(t, msg.OffRampAddressLength, decoded.OffRampAddressLength)
	assert.Equal(t, msg.OffRampAddress, decoded.OffRampAddress)
	assert.Equal(t, msg.Finality, decoded.Finality)
	assert.Equal(t, msg.SenderLength, decoded.SenderLength)
	assert.Equal(t, msg.Sender, decoded.Sender)
	assert.Equal(t, msg.ReceiverLength, decoded.ReceiverLength)
	assert.Equal(t, msg.Receiver, decoded.Receiver)
	assert.Equal(t, msg.DestBlobLength, decoded.DestBlobLength)
	assert.Equal(t, msg.DestBlob, decoded.DestBlob)
	assert.Equal(t, msg.TokenTransferLength, decoded.TokenTransferLength)
	assert.Equal(t, msg.TokenTransfer, decoded.TokenTransfer)
	assert.Equal(t, msg.DataLength, decoded.DataLength)
	assert.Equal(t, msg.Data, decoded.Data)
}

func TestMessageID(t *testing.T) {
	// Create two identical messages
	sender := RandomAddress()
	receiver := RandomAddress()
	onRampAddr := RandomAddress()
	offRampAddr := RandomAddress()
	tokenTransfer := NewEmptyTokenTransfer()

	msg1 := NewMessage(
		cciptypes.ChainSelector(1337),
		cciptypes.ChainSelector(2337),
		cciptypes.SeqNum(123),
		onRampAddr,
		offRampAddr,
		10,
		sender,
		receiver,
		[]byte("test data"),
		[]byte("test data"),
		tokenTransfer,
	)

	msg2 := NewMessage(
		cciptypes.ChainSelector(1337),
		cciptypes.ChainSelector(2337),
		cciptypes.SeqNum(123),
		onRampAddr,
		offRampAddr,
		10,
		sender,
		receiver,
		[]byte("test data"),
		[]byte("test data"),
		tokenTransfer,
	)

	// Same messages should have same message ID
	assert.Equal(t, msg1.MessageID(), msg2.MessageID())

	// Different sequence number should give different message ID
	msg3 := NewMessage(
		cciptypes.ChainSelector(1337),
		cciptypes.ChainSelector(2337),
		cciptypes.SeqNum(124), // Different sequence number
		onRampAddr,
		offRampAddr,
		10,
		sender,
		receiver,
		[]byte("test data"),
		[]byte("test data"),
		tokenTransfer,
	)

	assert.NotEqual(t, msg1.MessageID(), msg3.MessageID())
}

func TestEmptyTokenTransfer(t *testing.T) {
	tt := NewEmptyTokenTransfer()

	assert.Equal(t, uint8(MessageVersion), tt.Version)
	assert.Equal(t, big.NewInt(0).Cmp(tt.Amount), 0)
	assert.Equal(t, uint8(0), tt.SourceTokenAddressLength)
	assert.Empty(t, tt.SourceTokenAddress)
	assert.Equal(t, uint8(0), tt.DestTokenAddressLength)
	assert.Empty(t, tt.DestTokenAddress)
	assert.Equal(t, uint8(0), tt.TokenReceiverLength)
	assert.Empty(t, tt.TokenReceiver)
	assert.Equal(t, uint8(0), tt.ExtraDataLength)
	assert.Empty(t, tt.ExtraData)

	// Should be able to encode/decode
	encoded := tt.Encode()
	decoded, err := DecodeTokenTransfer(encoded)
	require.NoError(t, err)
	assert.Equal(t, tt.Version, decoded.Version)
	assert.Equal(t, tt.Amount.Cmp(decoded.Amount), 0)
}

func TestValidateMessage(t *testing.T) {
	sender := RandomAddress()
	receiver := RandomAddress()
	onRampAddr := RandomAddress()
	offRampAddr := RandomAddress()
	verifierAddr := RandomAddress()

	message := NewMessage(
		cciptypes.ChainSelector(1337),
		cciptypes.ChainSelector(2337),
		cciptypes.SeqNum(123),
		onRampAddr,
		offRampAddr,
		10,
		sender,
		receiver,
		[]byte("test data"),
		[]byte("test data"),
		NewEmptyTokenTransfer(),
	)

	// Create verification task with matching verifier address
	task := &VerificationTask{
		Message: *message,
		ReceiptBlobs: []ReceiptWithBlob{
			{
				Issuer: verifierAddr,
				Blob:   []byte("test blob"),
			},
		},
	}

	// Should validate successfully
	err := ValidateMessage(task, verifierAddr)
	assert.NoError(t, err)

	// Should fail with different verifier address
	differentAddr := RandomAddress()
	err = ValidateMessage(task, differentAddr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found as issuer")
}
