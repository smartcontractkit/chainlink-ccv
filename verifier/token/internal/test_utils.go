package internal

import (
	"fmt"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
)

func ReadResultsFromChannel(
	t *testing.T,
	outCh chan batcher.BatchResult[protocol.VerifierNodeResult],
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
