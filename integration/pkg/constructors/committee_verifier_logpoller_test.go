package constructors

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	"github.com/smartcontractkit/chainlink-evm/pkg/client/clienttest"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads"
	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"
	lpmocks "github.com/smartcontractkit/chainlink-evm/pkg/logpoller/mocks"
	evmtypes "github.com/smartcontractkit/chainlink-evm/pkg/types"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/sourcereader"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	verifiermonitoring "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
)

// logPollerChain is a node chain with the log poller enabled, so the in-node verifier reads logs from it.
type logPollerChain struct {
	stubChain
	lp          logpoller.LogPoller
	headTracker heads.Tracker
}

func (c logPollerChain) LogPoller() logpoller.LogPoller { return c.lp }
func (c logPollerChain) HeadTracker() heads.Tracker     { return c.headTracker }
func (c logPollerChain) ID() *big.Int                   { return big.NewInt(1337) }

// fixedHeadTracker serves fixed heads; any other Tracker call panics on the nil embedded interface.
type fixedHeadTracker struct {
	heads.Tracker
	latest, finalized, safe int64
}

func (h fixedHeadTracker) LatestAndFinalizedBlock(context.Context) (*evmtypes.Head, *evmtypes.Head, error) {
	return &evmtypes.Head{Number: h.latest}, &evmtypes.Head{Number: h.finalized}, nil
}

func (h fixedHeadTracker) LatestSafeBlock(context.Context) (*evmtypes.Head, error) {
	return &evmtypes.Head{Number: h.safe}, nil
}

// noFiltersDataSource answers the startup's stale-filter query with no rows; any other use panics.
type noFiltersDataSource struct {
	sqlutil.DataSource
}

func (noFiltersDataSource) SelectContext(context.Context, any, string, ...any) error { return nil }

// newInNodeLogPollerReader builds a chain's reader as the in-node coordinator does, inside the observed wrapper.
func newInNodeLogPollerReader(t *testing.T, lp *lpmocks.LogPoller, ht heads.Tracker) chainaccess.SourceReader {
	const sel = protocol.ChainSelector(5009297550715157269)
	chain := logPollerChain{stubChain: stubChain{chainClient: clienttest.NewClient(t)}, lp: lp, headTracker: ht}
	params := evm.SourceReaderParams{
		ChainClient:          chain.Client(),
		HeadTracker:          chain.HeadTracker(),
		OnRampAddress:        common.HexToAddress("0x1234"),
		CCIPMessageSentTopic: common.HexToHash("0x01").Hex(),
		ChainSelector:        sel,
		Logger:               logger.Test(t),
		HeaderFetchBatchSize: 25,
	}
	reader, reporter, err := newChainSourceReader(logger.Test(t), chain, params, noFiltersDataSource{}, "test-verifier")
	require.NoError(t, err)
	require.IsType(t, &evm.LogPollerSourceReader{}, reader)
	require.NotNil(t, reporter)

	observed, err := sourcereader.NewObservedSourceReader(reader, "test-verifier", sel, verifiermonitoring.NewFakeVerifierMonitoring())
	require.NoError(t, err)
	lp.EXPECT().UnregisterFilter(mock.Anything, mock.Anything).Return(nil).Maybe()
	t.Cleanup(func() { require.NoError(t, observed.(chainaccess.SourceLoader).Close()) })
	return observed
}

// The in-node verifier shares the reader, so it gets the same startup gating as the standalone one.
func TestInNodeLogPollerReader(t *testing.T) {
	t.Run("block reads come from the head tracker before LoadFrom and are gated until the load finishes", func(t *testing.T) {
		errRPCDown := errors.New("rpc down")
		lp := lpmocks.NewLogPoller(t) // no LatestBlock expected: any log poller read fails the test
		lp.EXPECT().RegisterFilter(mock.Anything, mock.Anything).Return(errRPCDown).Maybe()
		reader := newInNodeLogPollerReader(t, lp, fixedHeadTracker{latest: 1000, finalized: 900, safe: 950})

		_, finalized, err := reader.LatestAndFinalizedBlock(t.Context())
		require.NoError(t, err)
		require.Equal(t, uint64(900), finalized.Number, "the no-checkpoint start block comes from the head tracker")

		loader := reader.(chainaccess.SourceLoader)
		loader.LoadFrom(501)
		require.Eventually(t, func() bool { return errors.Is(loader.Loaded(), errRPCDown) }, 5*time.Second, 5*time.Millisecond)
		require.ErrorIs(t, loader.Loaded(), chainaccess.ErrSourceNotReady)
		_, _, err = reader.LatestAndFinalizedBlock(t.Context())
		require.ErrorIs(t, err, chainaccess.ErrSourceNotReady)
		_, err = reader.LatestSafeBlock(t.Context())
		require.ErrorIs(t, err, chainaccess.ErrSourceNotReady)
		_, err = reader.FetchMessageSentEvents(t.Context(), 501, 0)
		require.ErrorIs(t, err, chainaccess.ErrSourceNotReady)
	})

	t.Run("a checkpoint above finality leaves the chain not loaded, naming both blocks", func(t *testing.T) {
		lp := lpmocks.NewLogPoller(t) // only registration is expected: no anchor or replay above finality
		lp.EXPECT().RegisterFilter(mock.Anything, mock.Anything).Return(nil)
		reader := newInNodeLogPollerReader(t, lp, fixedHeadTracker{latest: 450, finalized: 400})

		loader := reader.(chainaccess.SourceLoader)
		loader.LoadFrom(501)
		var checkpointErr evm.CheckpointAboveFinalizedError
		require.Eventually(t, func() bool { return errors.As(loader.Loaded(), &checkpointErr) }, 5*time.Second, 5*time.Millisecond)
		require.Equal(t, evm.CheckpointAboveFinalizedError{Checkpoint: 500, Finalized: 400}, checkpointErr)
		require.ErrorIs(t, loader.Loaded(), chainaccess.ErrSourceNotReady)
		_, err := reader.FetchMessageSentEvents(t.Context(), 501, 0)
		require.ErrorIs(t, err, chainaccess.ErrSourceNotReady)
	})
}
