package pkg

import (
	"crypto/rand"

	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

// RandomAddress generates a random address for testing.
func RandomAddress() (types.UnknownAddress, error) {
	addr := make([]byte, 20)
	if _, err := rand.Read(addr); err != nil {
		return nil, err
	}
	return addr, nil
}

func RandomBytes(length int) []byte {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return nil
	}
	return bytes
}

func MockMessage(overrides ...func(*types.Message)) types.Message {
	sourceChainSelector := types.ChainSelector(3379446385462418246)
	destChainSelector := types.ChainSelector(12922642891491394802)

	msg := types.Message{
		Version:              1,
		SourceChainSelector:  sourceChainSelector,
		DestChainSelector:    destChainSelector,
		SequenceNumber:       1,
		OnRampAddressLength:  20,
		OnRampAddress:        RandomBytes(20),
		OffRampAddressLength: 20,
		OffRampAddress:       RandomBytes(20),
		Finality:             10,
		SenderLength:         20,
		Sender:               RandomBytes(20),
		ReceiverLength:       20,
		Receiver:             RandomBytes(20),
		DestBlobLength:       0,
		DestBlob:             RandomBytes(0),
		TokenTransferLength:  0,
		TokenTransfer:        RandomBytes(20),
		DataLength:           8,
		Data:                 RandomBytes(8),
	}

	for _, override := range overrides {
		override(&msg)
	}

	return msg
}
