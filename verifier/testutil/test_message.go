package testutil

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// DefaultDestChain is a common destination chain selector used across tests.
const DefaultDestChain = protocol.ChainSelector(100)

// CreateTestMessage creates a test protocol.Message with deterministic addresses.
// The CCV address has first byte 0x11 and executor address has first byte 0x22,
// so callers that need to match those addresses should use the same pattern.
func CreateTestMessage(t *testing.T, sequenceNumber protocol.SequenceNumber, sourceChainSelector, destChainSelector protocol.ChainSelector, finality protocol.Finality, gasLimit uint32) protocol.Message {
	t.Helper()

	sender := protocol.UnknownAddress([]byte("sender_address"))
	receiver := protocol.UnknownAddress([]byte("receiver_address"))
	onRampAddr := protocol.UnknownAddress([]byte("onramp_address"))
	offRampAddr := protocol.UnknownAddress([]byte("offramp_address"))

	ccvAddr := make([]byte, 20)
	ccvAddr[0] = 0x11

	executorAddr := make([]byte, 20)
	executorAddr[0] = 0x22

	ccvAndExecutorHash, err := protocol.ComputeCCVAndExecutorHash(
		[]protocol.UnknownAddress{protocol.UnknownAddress(ccvAddr)},
		protocol.UnknownAddress(executorAddr),
	)
	require.NoError(t, err)

	message, err := protocol.NewMessage(
		sourceChainSelector,
		destChainSelector,
		sequenceNumber,
		onRampAddr,
		offRampAddr,
		finality,
		gasLimit,
		gasLimit,
		ccvAndExecutorHash,
		sender,
		receiver,
		[]byte("test data"),
		[]byte("test data"),
		nil,
	)
	require.NoError(t, err)
	return *message
}

// CreateTestMessageSentEvents creates a batch of MessageSentEvent for testing.
// The addresses in the receipts (CCV 0x11, executor 0x22, router 0x44) match those in CreateTestMessage.
func CreateTestMessageSentEvents(
	t *testing.T,
	startNonce uint64,
	chainSelector, destChain protocol.ChainSelector,
	blockNumbers []uint64,
) []protocol.MessageSentEvent {
	t.Helper()

	ccvAddr := make([]byte, 20)
	ccvAddr[0] = 0x11

	executorAddr := make([]byte, 20)
	executorAddr[0] = 0x22

	routerAddr := make([]byte, 20)
	routerAddr[0] = 0x44

	events := make([]protocol.MessageSentEvent, len(blockNumbers))
	for i, blockNum := range blockNumbers {
		seqNum := startNonce + uint64(i)
		message := CreateTestMessage(t, protocol.SequenceNumber(seqNum), chainSelector, destChain, 0, 300_000)
		messageID, _ := message.MessageID()

		events[i] = protocol.MessageSentEvent{
			MessageID: messageID,
			Message:   message,
			Receipts: []protocol.ReceiptWithBlob{
				{Issuer: protocol.UnknownAddress(ccvAddr), Blob: []byte("receipt1")},
				{Issuer: protocol.UnknownAddress(executorAddr), Blob: []byte{}},
				{Issuer: protocol.UnknownAddress(routerAddr), Blob: []byte("router-blob")},
			},
			BlockNumber: blockNum,
		}
	}
	return events
}
