package sourcereader

import (
	"sync/atomic"
	"testing"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"

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

// fakeFinalityReporter is a chain's own finality signal, like the EVM log poller's.
type fakeFinalityReporter struct {
	violated atomic.Bool
}

func (f *fakeFinalityReporter) FinalityViolated() bool { return f.violated.Load() }

var _ chainaccess.FinalityViolationReporter = (*fakeFinalityReporter)(nil)

// loadingReader is a source reader that must load a local index from the start block before serving reads.
type loadingReader struct {
	*mocks.MockSourceReader
	loaded []uint64
	closed atomic.Bool
}

func (r *loadingReader) LoadFrom(startBlock uint64) { r.loaded = append(r.loaded, startBlock) }

func (r *loadingReader) Close() error { r.closed.Store(true); return nil }

var _ chainaccess.SourceLoader = (*loadingReader)(nil)

// closingReader is a source reader with a Close but no local index, so the verifier must not close it.
type closingReader struct {
	*mocks.MockSourceReader
	closed atomic.Bool
}

func (c *closingReader) Close() error { c.closed.Store(true); return nil }
