package internal

import (
	"fmt"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/common/batcher"
	"github.com/smartcontractkit/chainlink-ccv/verifier"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

var (
	CCVAddress1     = protocol.UnknownAddress{0x11, 0x12, 0x13}
	CCVAddress2     = protocol.UnknownAddress{0x21, 0x22, 0x23}
	ExecutorAddress = protocol.UnknownAddress{0x31, 0x32, 0x33}
	RouterAddress   = protocol.UnknownAddress{0x41, 0x42, 0x43}
)

func ReadResultsFromChannel(
	t *testing.T,
	outCh <-chan batcher.BatchResult[protocol.VerifierNodeResult],
) []protocol.VerifierNodeResult {
	var results []protocol.VerifierNodeResult
	select {
	case batch, ok := <-outCh:
		if !ok {
			t.Fatal("Output channel closed without sending batch")
		}
		results = append(results, batch.Items...)
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for batch from output channel")
	}
	return results
}

func MustByteSliceFromHex(s string) protocol.ByteSlice {
	bs, err := protocol.NewByteSliceFromHex(s)
	if err != nil {
		panic(fmt.Sprintf("failed to decode hex string: %v", err))
	}
	return bs
}

func MustUnknownAddressFromHex(s string) protocol.UnknownAddress {
	addr, err := protocol.NewUnknownAddressFromHex(s)
	if err != nil {
		panic(fmt.Sprintf("failed to decode address: %v", err))
	}
	return addr
}

func CreateTestVerificationTask(sequenceNumber int) verifier.VerificationTask {
	message := protocol.Message{
		SourceChainSelector: protocol.ChainSelector(1),
		DestChainSelector:   protocol.ChainSelector(2),
		//nolint:gosec // used in tests
		SequenceNumber: protocol.SequenceNumber(sequenceNumber),
	}

	messageID := message.MustMessageID()
	return verifier.VerificationTask{
		MessageID: messageID.String(),
		Message:   message,
		TxHash:    protocol.ByteSlice{0xaa, 0xbb, 0xcc},
		ReceiptBlobs: []protocol.ReceiptWithBlob{
			// Create receipt structure: [CCV1, CCV2, Executor, NetworkFee]
			{Issuer: CCVAddress1, Blob: []byte("ccv1-blob")},
			{Issuer: CCVAddress2, Blob: []byte("ccv2-blob")},
			{Issuer: ExecutorAddress, Blob: []byte("executor-blob")},
			{Issuer: RouterAddress, Blob: []byte("router-blob")},
		},
		BlockNumber: 12345,
		FirstSeenAt: time.Now(),
		QueuedAt:    time.Now(),
	}
}
