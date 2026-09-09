package chainaccess

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func TestNewMessageDetails_AddressNormalization(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  []byte
		want string
	}{
		{name: "nil"},
		{name: "empty", raw: []byte{}},
		{name: "20 bytes", raw: bytes.Repeat([]byte{0xab}, 20), want: strings.Repeat("00", 12) + strings.Repeat("ab", 20)},
		{name: "already padded", raw: append(make([]byte, 12), bytes.Repeat([]byte{0xab}, 20)...), want: strings.Repeat("00", 12) + strings.Repeat("ab", 20)},
		{name: "32 significant bytes", raw: bytes.Repeat([]byte{0xab}, 32), want: strings.Repeat("ab", 32)},
		{name: "32 bytes with leading zeros", raw: append([]byte{0, 0}, bytes.Repeat([]byte{0xab}, 30)...), want: "0000" + strings.Repeat("ab", 30)},
		{name: "long address", raw: append([]byte{0}, bytes.Repeat([]byte{0xab}, 63)...), want: "00" + strings.Repeat("ab", 63)},
		{name: "maximum address", raw: bytes.Repeat([]byte{0xab}, protocol.MaxUnknownAddressBytes), want: strings.Repeat("ab", protocol.MaxUnknownAddressBytes)},
		{name: "zero address", raw: make([]byte, 20), want: strings.Repeat("00", 32)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			message := protocol.Message{
				OnRampAddress:  tc.raw,
				OffRampAddress: tc.raw,
				Sender:         tc.raw,
				Receiver:       tc.raw,
				Data:           tc.raw,
				DestBlob:       tc.raw,
				TokenTransfer: &protocol.TokenTransfer{
					SourcePoolAddress:  tc.raw,
					SourceTokenAddress: tc.raw,
					DestTokenAddress:   tc.raw,
					TokenReceiver:      tc.raw,
					ExtraData:          tc.raw,
				},
			}
			before, err := json.Marshal(message)
			require.NoError(t, err)
			details := NewMessageDetails(message, nil, tc.raw)
			for _, address := range []protocol.UnknownAddress{
				details.OnRampAddress, details.OffRampAddress, details.Sender, details.Receiver,
				details.SourcePoolAddress, details.SourceTokenAddress, details.DestTokenAddress,
				details.TokenReceiver, details.FeeToken,
			} {
				assert.Equal(t, tc.want, hex.EncodeToString(address))
				if len(address) > 0 {
					// Consumers of the view cannot mutate the original message's backing arrays.
					address[len(address)-1] ^= 0xff
				}
			}
			after, err := json.Marshal(message)
			require.NoError(t, err)
			assert.Equal(t, before, after)
		})
	}
}

func TestNewMessageDetails_FeeTotal(t *testing.T) {
	largeFee, ok := new(big.Int).SetString("123456789012345678901234567890", 10)
	require.True(t, ok)
	receipts := []protocol.ReceiptWithBlob{
		{FeeTokenAmount: largeFee},
		{FeeTokenAmount: big.NewInt(2)},
		{FeeTokenAmount: big.NewInt(3)},
		{FeeTokenAmount: big.NewInt(4)},
	}
	details := NewMessageDetails(protocol.Message{}, receipts, nil)
	require.NotNil(t, details.FeeTokenAmount)
	assert.Equal(t, "123456789012345678901234567899", details.FeeTokenAmount.String())
	assert.Equal(t, "123456789012345678901234567890", largeFee.String())
	assert.Nil(t, NewMessageDetails(protocol.Message{}, nil, nil).FeeTokenAmount)
	assert.Nil(t, NewMessageDetails(protocol.Message{}, append(receipts, protocol.ReceiptWithBlob{}), nil).FeeTokenAmount)
	details = NewMessageDetails(protocol.Message{}, []protocol.ReceiptWithBlob{{FeeTokenAmount: big.NewInt(0)}}, nil)
	require.NotNil(t, details.FeeTokenAmount)
	assert.Zero(t, details.FeeTokenAmount.Sign())
}

func TestNewMessageDetails_PreservesEncodedMessage(t *testing.T) {
	message, err := protocol.NewMessage(1, 2, 3,
		protocol.UnknownAddress{0x01}, protocol.UnknownAddress{0x02},
		protocol.NewFinality().WithSafe(), 300000, 200000, protocol.Bytes32{0x03},
		protocol.UnknownAddress{0x04}, protocol.UnknownAddress{0x05}, []byte{0, 6}, []byte{0, 7}, nil)
	require.NoError(t, err)
	before, err := message.Encode()
	require.NoError(t, err)
	messageID, err := message.MessageID()
	require.NoError(t, err)
	details := NewMessageDetails(*message, nil, nil)
	assert.Len(t, details.Sender, 32)
	assert.Equal(t, protocol.FinalityRequirement{Mode: protocol.FinalityModeFinalized, Safe: true}, details.Finality)
	after, err := message.Encode()
	require.NoError(t, err)
	assert.Equal(t, before, after)
	assert.Equal(t, messageID, message.MustMessageID())
}
