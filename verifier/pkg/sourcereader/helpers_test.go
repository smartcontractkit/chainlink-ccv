package sourcereader

import (
	"context"
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

// replayingReader is a source reader backed by a local log index that must be replayed on start.
type replayingReader struct {
	*mocks.MockSourceReader
	err   error
	calls []uint64
}

func (r *replayingReader) ReplayFrom(_ context.Context, fromBlock uint64) error {
	r.calls = append(r.calls, fromBlock)
	return r.err
}

var _ chainaccess.SourceReplayer = (*replayingReader)(nil)
