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

// violationReportingReader is a source reader whose data source reports finality violations,
// like the EVM reader backed by the log poller.
type violationReportingReader struct {
	*mocks.MockSourceReader
	violated atomic.Bool
}

func (v *violationReportingReader) FinalityViolated() bool { return v.violated.Load() }

var _ chainaccess.FinalityViolationReporter = (*violationReportingReader)(nil)

// loadingReader is a source reader that must load a local index from the start block before serving reads.
type loadingReader struct {
	*mocks.MockSourceReader
	loaded []uint64
}

func (r *loadingReader) LoadFrom(startBlock uint64) { r.loaded = append(r.loaded, startBlock) }

var _ chainaccess.SourceLoader = (*loadingReader)(nil)

// closingReader is a source reader that owns resources released on Close.
type closingReader struct {
	*mocks.MockSourceReader
	closed atomic.Bool
}

func (c *closingReader) Close() error { c.closed.Store(true); return nil }
