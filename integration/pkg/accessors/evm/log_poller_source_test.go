package evm

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads/headstest"
	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"
	lpmocks "github.com/smartcontractkit/chainlink-evm/pkg/logpoller/mocks"
	evmtypes "github.com/smartcontractkit/chainlink-evm/pkg/types"
)

const (
	testOnRampAddress = "0x0000000000000000000000000000000000001234"
	testChainSelector = protocol.ChainSelector(1337)
)

var testMessageSentTopic = common.HexToHash("0xabc")

func newLogPollerTestReader(t *testing.T, tracker heads.Tracker) *SourceReader {
	t.Helper()
	return &SourceReader{
		headTracker:          tracker,
		onRampAddress:        common.HexToAddress(testOnRampAddress),
		ccipMessageSentTopic: testMessageSentTopic.Hex(),
		chainSelector:        testChainSelector,
		lggr:                 logger.Test(t),
	}
}

func TestSourceReaderAttachLogPoller(t *testing.T) {
	t.Parallel()

	t.Run("registers the filter and keeps the poller", func(t *testing.T) {
		t.Parallel()

		var got logpoller.Filter
		lp := lpmocks.NewLogPoller(t)
		lp.On("RegisterFilter", mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) { got = args.Get(1).(logpoller.Filter) }).
			Return(nil)

		reader := newLogPollerTestReader(t, heads.NullTracker)
		require.NoError(t, reader.AttachLogPoller(context.Background(), lp))

		// The name is hashed and upserted, so changing it strands the deployed filter row.
		require.Equal(t, "ccv-source-reader-ccip-message-sent - 1337", got.Name)
		require.Equal(t, evmtypes.AddressArray{common.HexToAddress(testOnRampAddress)}, got.Addresses)
		require.Equal(t, evmtypes.HashArray{testMessageSentTopic}, got.EventSigs)
		// Non-zero would let LogPoller prune behind the answerability window.
		require.Zero(t, got.Retention)
		require.Zero(t, got.MaxLogsKept)
		require.Equal(t, lp, reader.logPoller)
	})

	t.Run("leaves the reader on RPC when registration fails", func(t *testing.T) {
		t.Parallel()

		lp := lpmocks.NewLogPoller(t)
		lp.On("RegisterFilter", mock.Anything, mock.Anything).Return(errors.New("no such index"))

		reader := newLogPollerTestReader(t, heads.NullTracker)
		require.ErrorContains(t, reader.AttachLogPoller(context.Background(), lp), "no such index")
		require.Nil(t, reader.logPoller)
	})
}

// Replay is expensive and only useful when the poller is behind, so ReplayFrom has three exits
// before it runs. Unexpected calls fail the mock, so a skipped replay needs no assertion.
func TestSourceReaderReplayFrom(t *testing.T) {
	t.Parallel()

	const lastProcessed = 100 // so a replay starts at 101

	tests := []struct {
		name    string
		attach  bool
		setupLP func(*lpmocks.LogPoller)
		head    int64 // 0 means the tracker is never consulted
	}{
		{
			name:   "no poller attached",
			attach: false,
		},
		{
			name:   "poller is already past the checkpoint",
			attach: true,
			setupLP: func(lp *lpmocks.LogPoller) {
				lp.On("LatestBlock", mock.Anything).Return(logpoller.Block{BlockNumber: 200}, nil)
			},
		},
		{
			name:   "nothing behind the head to backfill",
			attach: true,
			setupLP: func(lp *lpmocks.LogPoller) {
				lp.On("LatestBlock", mock.Anything).Return(logpoller.Block{}, errors.New("no rows"))
			},
			head: 50,
		},
		{
			// An empty poller table is the first enablement: it must replay, not skip.
			name:   "first enablement replays from the checkpoint",
			attach: true,
			setupLP: func(lp *lpmocks.LogPoller) {
				lp.On("LatestBlock", mock.Anything).Return(logpoller.Block{}, errors.New("no rows"))
				lp.On("Replay", mock.Anything, int64(lastProcessed+1)).Return(nil)
			},
			head: 500,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tracker := heads.NullTracker
			if tt.head > 0 {
				m := headstest.NewTracker[*evmtypes.Head, common.Hash](t)
				head := &evmtypes.Head{Number: tt.head}
				m.On("LatestAndFinalizedBlock", mock.Anything).Return(head, head, nil)
				tracker = m
			}

			reader := newLogPollerTestReader(t, tracker)
			if tt.attach {
				lp := lpmocks.NewLogPoller(t)
				tt.setupLP(lp)
				reader.logPoller = lp
			}

			require.NoError(t, reader.ReplayFrom(context.Background(), big.NewInt(lastProcessed)))
		})
	}
}
