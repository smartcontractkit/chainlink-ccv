package evm

import (
	"context"
	"database/sql"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evmconfig"
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
		require.NoError(t, reader.AttachLogPoller(context.Background(), lp, evmconfig.LogPollerModeShadow))

		// The name is hashed and upserted, so changing it strands the deployed filter row.
		require.Equal(t, "ccv-source-reader-ccip-message-sent - 1337", got.Name)
		require.Equal(t, evmtypes.AddressArray{common.HexToAddress(testOnRampAddress)}, got.Addresses)
		require.Equal(t, evmtypes.HashArray{testMessageSentTopic}, got.EventSigs)
		// Non-zero would let LogPoller prune behind the answerability window.
		require.Zero(t, got.Retention)
		require.Zero(t, got.MaxLogsKept)
		require.Equal(t, lp, reader.logPoller)
		require.Equal(t, evmconfig.LogPollerMode(evmconfig.LogPollerModeShadow), reader.logPollerMode)
	})

	t.Run("leaves the reader on RPC when registration fails", func(t *testing.T) {
		t.Parallel()

		lp := lpmocks.NewLogPoller(t)
		lp.On("RegisterFilter", mock.Anything, mock.Anything).Return(errors.New("no such index"))

		reader := newLogPollerTestReader(t, heads.NullTracker)
		require.ErrorContains(t, reader.AttachLogPoller(context.Background(), lp, evmconfig.LogPollerModeRead), "no such index")
		require.Nil(t, reader.logPoller)
		require.Empty(t, reader.logPollerMode)
	})
}

// ReplayFrom always backfills from the checkpoint, so the poller provably holds every log from
// there on. Unexpected calls fail the mock, so a skipped replay needs no assertion.
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
			// Its latest block says nothing about the blocks between the checkpoint and it: a poller
			// that started before this replay began at latest finalized, not at the checkpoint.
			name:   "replays even when the poller is past the checkpoint",
			attach: true,
			setupLP: func(lp *lpmocks.LogPoller) {
				lp.On("Replay", mock.Anything, int64(lastProcessed+1)).Return(nil)
			},
			head: 500,
		},
		{
			name:    "nothing behind the head to backfill",
			attach:  true,
			setupLP: func(*lpmocks.LogPoller) {},
			head:    50,
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

func TestSourceReaderLatestIngestedBlock(t *testing.T) {
	t.Parallel()

	t.Run("reports the poller cursor", func(t *testing.T) {
		t.Parallel()

		lp := lpmocks.NewLogPoller(t)
		lp.On("LatestBlock", mock.Anything).Return(logpoller.Block{BlockNumber: 150}, nil)

		reader := newLogPollerTestReader(t, heads.NullTracker)
		reader.logPoller = lp

		block, ok, err := reader.LatestIngestedBlock(context.Background())
		require.NoError(t, err)
		require.True(t, ok)
		require.EqualValues(t, 150, block)
	})

	// Neither an absent poller nor an empty block table is a failure: both mean "nothing to
	// report", so the gauge is skipped rather than recording a misleading zero.
	t.Run("not ok without a cursor", func(t *testing.T) {
		t.Parallel()

		t.Run("no poller", func(t *testing.T) {
			t.Parallel()
			reader := newLogPollerTestReader(t, heads.NullTracker)
			_, ok, err := reader.LatestIngestedBlock(context.Background())
			require.NoError(t, err)
			require.False(t, ok)
		})

		t.Run("poller has ingested nothing", func(t *testing.T) {
			t.Parallel()
			lp := lpmocks.NewLogPoller(t)
			lp.On("LatestBlock", mock.Anything).Return(logpoller.Block{}, sql.ErrNoRows)

			reader := newLogPollerTestReader(t, heads.NullTracker)
			reader.logPoller = lp

			_, ok, err := reader.LatestIngestedBlock(context.Background())
			require.NoError(t, err)
			require.False(t, ok)
		})
	})
}
