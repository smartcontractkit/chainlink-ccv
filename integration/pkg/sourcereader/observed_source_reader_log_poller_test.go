package sourcereader

import (
	"context"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
)

// logPollerSource mirrors the structural interface verifier/pkg/sourcereader checks for.
type logPollerSource interface {
	ReplayFrom(ctx context.Context, lastProcessedBlock *big.Int) error
	LatestIngestedBlock(ctx context.Context) (block int64, ok bool, err error)
}

type fakeLogPollerReader struct {
	*mocks.MockSourceReader
	replayedFrom *big.Int
}

func (f *fakeLogPollerReader) ReplayFrom(_ context.Context, lastProcessedBlock *big.Int) error {
	f.replayedFrom = lastProcessedBlock
	return nil
}

func (f *fakeLogPollerReader) LatestIngestedBlock(context.Context) (int64, bool, error) {
	return 42, true, nil
}

// The service type-asserts the wrapped reader, so the wrapper must not hide these methods.
func TestObservedSourceReader_ForwardsLogPollerMethods(t *testing.T) {
	t.Parallel()

	delegate := &fakeLogPollerReader{MockSourceReader: mocks.NewMockSourceReader(t)}
	rd, err := NewObservedSourceReader(delegate, "v1", protocol.ChainSelector(1), monitoring.NewFakeVerifierMonitoring())
	require.NoError(t, err)

	source, ok := rd.(logPollerSource)
	require.True(t, ok, "observed reader hides the delegate's log poller methods")

	require.NoError(t, source.ReplayFrom(t.Context(), big.NewInt(100)))
	require.Equal(t, big.NewInt(100), delegate.replayedFrom)

	block, ok, err := source.LatestIngestedBlock(t.Context())
	require.NoError(t, err)
	require.True(t, ok)
	require.EqualValues(t, 42, block)
}

func TestObservedSourceReader_LogPollerMethodsNoOpWithoutPoller(t *testing.T) {
	t.Parallel()

	rd, err := NewObservedSourceReader(mocks.NewMockSourceReader(t), "v1", protocol.ChainSelector(1), monitoring.NewFakeVerifierMonitoring())
	require.NoError(t, err)

	source, ok := rd.(logPollerSource)
	require.True(t, ok)
	require.NoError(t, source.ReplayFrom(t.Context(), big.NewInt(100)))
	_, ok, err = source.LatestIngestedBlock(t.Context())
	require.NoError(t, err)
	require.False(t, ok)
}
