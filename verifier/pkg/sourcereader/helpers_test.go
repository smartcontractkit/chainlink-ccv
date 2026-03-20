package sourcereader

import (
	"testing"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
)

// defaultDestChain is the common destination chain selector used in sourcereader tests.
const defaultDestChain = testutil.DefaultDestChain

// createTestMessageSentEvents creates a batch of MessageSentEvent for testing.
func createTestMessageSentEvents(
	t *testing.T,
	startNonce uint64,
	chainSelector, destChain protocol.ChainSelector,
	blockNumbers []uint64,
) []protocol.MessageSentEvent {
	t.Helper()
	return testutil.CreateTestMessageSentEvents(t, startNonce, chainSelector, destChain, blockNumbers)
}

// noopFilter is a chainaccess.MessageFilter that passes all messages through.
type noopFilter struct{}

func (n *noopFilter) Filter(_ protocol.MessageSentEvent) bool { return true }

// Ensure noopFilter satisfies the interface at compile time.
var _ chainaccess.MessageFilter = (*noopFilter)(nil)
