package evm

import (
	"context"
	"database/sql"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/onramp"
	ccvcommon "github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evmconfig"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads/headstest"
	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"
	lpmocks "github.com/smartcontractkit/chainlink-evm/pkg/logpoller/mocks"
	evmtypes "github.com/smartcontractkit/chainlink-evm/pkg/types"
)

func TestPollerLogToGeth(t *testing.T) {
	t.Parallel()

	pollerLog := logpoller.Log{
		LogIndex:       3,
		BlockHash:      common.HexToHash("0xb1"),
		BlockNumber:    95,
		BlockTimestamp: time.Unix(1700000000, 0),
		Topics:         [][]byte{testMessageSentTopic.Bytes()},
		Address:        common.HexToAddress(testOnRampAddress),
		TxHash:         common.HexToHash("0xdeadbeef"),
		Data:           []byte{0x01},
	}

	t.Run("carries the block timestamp ToGethLog drops", func(t *testing.T) {
		t.Parallel()

		got := pollerLogToGeth(pollerLog)
		require.EqualValues(t, 1700000000, got.BlockTimestamp)
		require.EqualValues(t, 95, got.BlockNumber)
		require.EqualValues(t, 3, got.Index)
		require.Equal(t, pollerLog.TxHash, got.TxHash)
		require.Equal(t, pollerLog.BlockHash, got.BlockHash)
		require.Equal(t, pollerLog.Address, got.Address)
		require.Equal(t, []common.Hash{testMessageSentTopic}, got.Topics)
		require.Equal(t, pollerLog.Data, got.Data)
	})

	// A zero time.Time has a negative Unix value, which would wrap to a huge uint64.
	t.Run("leaves a missing timestamp unavailable", func(t *testing.T) {
		t.Parallel()

		noTimestamp := pollerLog
		noTimestamp.BlockTimestamp = time.Time{}
		require.Zero(t, pollerLogToGeth(noTimestamp).BlockTimestamp)
	})
}

// The poller answers only ranges it has provably ingested; anything else is an error, because
// an empty result would let the service withdraw tasks and advance its cursor past them.
func TestSourceReaderFetchLogsFromPoller(t *testing.T) {
	t.Parallel()

	const ceiling = 200

	storedLog := logpoller.Log{
		BlockNumber:    150,
		BlockTimestamp: time.Unix(1700000000, 0),
		Address:        common.HexToAddress(testOnRampAddress),
		TxHash:         common.HexToHash("0x01"),
	}

	tests := []struct {
		name       string
		from       int64
		to         *big.Int // nil asks for everything up to the ceiling
		latestErr  error
		finalized  int64 // consulted only when to is nil
		wantEnd    int64 // the end block queried; 0 means no query
		unanswered bool
		wantErr    string
	}{
		{name: "nothing ingested", from: 100, to: big.NewInt(150), latestErr: sql.ErrNoRows, unanswered: true},
		{name: "latest block lookup fails", from: 100, to: big.NewInt(150), latestErr: errors.New("db down"), wantErr: "db down"},
		{name: "range inside the ceiling", from: 100, to: big.NewInt(150), wantEnd: 150},
		{name: "range ends at the ceiling", from: 100, to: big.NewInt(ceiling), wantEnd: ceiling},
		// Clamping would make the service record to as covered while (ceiling, to] was never read.
		{name: "range ends past the ceiling", from: 100, to: big.NewInt(ceiling + 1), unanswered: true},
		{name: "range starts past the ceiling", from: ceiling + 1, to: big.NewInt(ceiling + 10), unanswered: true},
		{name: "open range answers up to the ceiling", from: 100, finalized: 180, wantEnd: ceiling},
		// A nil upper bound lets the service advance to finalized, so the poller must cover it.
		{name: "open range with the ceiling below finalized", from: 100, finalized: ceiling + 1, unanswered: true},
		{name: "open range starting past the ceiling", from: ceiling + 1, finalized: 150, unanswered: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			lp := lpmocks.NewLogPoller(t)
			lp.On("LatestBlock", mock.Anything).Return(logpoller.Block{BlockNumber: ceiling}, tt.latestErr)
			if tt.wantEnd > 0 {
				lp.On("Logs", mock.Anything, tt.from, tt.wantEnd, testMessageSentTopic, common.HexToAddress(testOnRampAddress)).
					Return([]logpoller.Log{storedLog}, nil)
			}

			tracker := heads.NullTracker
			if tt.to == nil && tt.latestErr == nil {
				m := headstest.NewTracker[*evmtypes.Head, common.Hash](t)
				m.On("LatestAndFinalizedBlock", mock.Anything).
					Return(&evmtypes.Head{Number: ceiling + 50}, &evmtypes.Head{Number: tt.finalized}, nil)
				tracker = m
			}

			reader := newLogPollerTestReader(t, tracker)
			reader.logPoller = lp

			logs, err := reader.fetchLogsFromPoller(context.Background(), big.NewInt(tt.from), tt.to)
			switch {
			case tt.unanswered:
				require.ErrorIs(t, err, ccvcommon.ErrSourceRangeUnanswerable)
			case tt.wantErr != "":
				require.ErrorContains(t, err, tt.wantErr)
				require.NotErrorIs(t, err, ccvcommon.ErrSourceRangeUnanswerable)
			default:
				require.NoError(t, err)
				require.Equal(t, []types.Log{pollerLogToGeth(storedLog)}, logs)
			}
		})
	}
}

// toPollerLog is the row the poller would have stored for a log.
func toPollerLog(l types.Log, blockTimestamp time.Time) logpoller.Log {
	topics := make([][]byte, 0, len(l.Topics))
	for _, topic := range l.Topics {
		topics = append(topics, topic.Bytes())
	}
	return logpoller.Log{
		LogIndex:       int64(l.Index),
		BlockHash:      l.BlockHash,
		BlockNumber:    int64(l.BlockNumber),
		BlockTimestamp: blockTimestamp,
		Topics:         topics,
		EventSig:       l.Topics[0],
		Address:        l.Address,
		TxHash:         l.TxHash,
		Data:           l.Data,
	}
}

// newModeTestReader returns a reader over onRampAddress whose RPC client fails the test if used,
// unless rpcLogs is non-nil.
func newModeTestReader(t *testing.T, onRampAddress common.Address, mode evmconfig.LogPollerMode, lp logpoller.LogPoller, rpcLogs []types.Log) *SourceReader {
	t.Helper()
	onRampABI, err := onramp.OnRampMetaData.GetAbi()
	require.NoError(t, err)
	reader := &SourceReader{
		chainClient: &mockFilterLogsClient{
			filterLogsFunc: func(context.Context, ethereum.FilterQuery) ([]types.Log, error) {
				if rpcLogs == nil {
					t.Error("unexpected RPC log query")
				}
				return rpcLogs, nil
			},
		},
		headTracker:          heads.NullTracker,
		lggr:                 logger.Test(t),
		onRampAddress:        onRampAddress,
		chainSelector:        protocol.ChainSelector(1337),
		onRampABI:            onRampABI,
		ccipMessageSentTopic: onRampABI.Events["CCIPMessageSent"].ID.Hex(),
		logPoller:            lp,
		logPollerMode:        mode,
	}
	reader.SetCriticalSourceInvariantCallback(func(context.Context) { t.Error("unexpected invalid event") })
	return reader
}

func TestFetchMessageSentEvents_ReadMode(t *testing.T) {
	t.Parallel()

	onRampAddress := common.HexToAddress("0x1234")
	gethLog, message, _ := newMessageSentLog(t, onRampAddress, common.HexToAddress("0xabcd"))
	topic := gethLog.Topics[0]

	t.Run("sources events from the poller with their block timestamp", func(t *testing.T) {
		t.Parallel()

		lp := lpmocks.NewLogPoller(t)
		lp.On("LatestBlock", mock.Anything).Return(logpoller.Block{BlockNumber: 200}, nil)
		lp.On("Logs", mock.Anything, int64(90), int64(100), topic, onRampAddress).
			Return([]logpoller.Log{toPollerLog(gethLog, time.Unix(1700000000, 0))}, nil)

		reader := newModeTestReader(t, onRampAddress, evmconfig.LogPollerModeRead, lp, nil)
		events, err := reader.FetchMessageSentEvents(t.Context(), big.NewInt(90), big.NewInt(100))
		require.NoError(t, err)
		require.Len(t, events, 1)
		require.Equal(t, message.MustMessageID(), events[0].MessageID)
		require.Equal(t, time.Unix(1700000000, 0).UTC(), events[0].BlockTimestamp)
	})

	t.Run("an unanswerable range is an error, not an empty result", func(t *testing.T) {
		t.Parallel()

		lp := lpmocks.NewLogPoller(t)
		lp.On("LatestBlock", mock.Anything).Return(logpoller.Block{}, sql.ErrNoRows)

		reader := newModeTestReader(t, onRampAddress, evmconfig.LogPollerModeRead, lp, nil)
		events, err := reader.FetchMessageSentEvents(t.Context(), big.NewInt(90), big.NewInt(100))
		require.ErrorIs(t, err, ccvcommon.ErrSourceRangeUnanswerable)
		require.Nil(t, events)
	})
}

// Shadow mode returns RPC's answer unchanged and only warns when the poller disagrees with it.
func TestFetchMessageSentEvents_ShadowMode(t *testing.T) {
	t.Parallel()

	onRampAddress := common.HexToAddress("0x1234")
	gethLog, message, _ := newMessageSentLog(t, onRampAddress, common.HexToAddress("0xabcd"))
	gethLog.BlockTimestamp = 1700000000
	topic := gethLog.Topics[0]
	stored := toPollerLog(gethLog, time.Unix(1700000000, 0))
	noTimestamp := toPollerLog(gethLog, time.Time{})

	const disagreement = "Log poller shadow read disagrees with RPC"

	tests := []struct {
		name      string
		to        *big.Int
		finalized int64
		rpcLog    types.Log
		setupLP   func(lp *lpmocks.LogPoller)
		wantWarn  bool
	}{
		{
			name: "poller agrees", to: big.NewInt(100), finalized: 150, rpcLog: gethLog,
			setupLP: func(lp *lpmocks.LogPoller) {
				lp.On("LatestBlock", mock.Anything).Return(logpoller.Block{BlockNumber: 200}, nil)
				lp.On("Logs", mock.Anything, int64(90), int64(100), topic, onRampAddress).Return([]logpoller.Log{stored}, nil)
			},
		},
		{
			name: "poller is missing a log", to: big.NewInt(100), finalized: 150, rpcLog: gethLog, wantWarn: true,
			setupLP: func(lp *lpmocks.LogPoller) {
				lp.On("LatestBlock", mock.Anything).Return(logpoller.Block{BlockNumber: 200}, nil)
				lp.On("Logs", mock.Anything, int64(90), int64(100), topic, onRampAddress).Return([]logpoller.Log{}, nil)
			},
		},
		{
			name: "poller dropped the block timestamp", to: big.NewInt(100), finalized: 150, rpcLog: gethLog, wantWarn: true,
			setupLP: func(lp *lpmocks.LogPoller) {
				lp.On("LatestBlock", mock.Anything).Return(logpoller.Block{BlockNumber: 200}, nil)
				lp.On("Logs", mock.Anything, int64(90), int64(100), topic, onRampAddress).Return([]logpoller.Log{noTimestamp}, nil)
			},
		},
		{
			// Many providers omit the timestamp from eth_getLogs; the poller filling it in is not a mismatch.
			name: "only the poller has a timestamp", to: big.NewInt(100), finalized: 150,
			rpcLog: func() types.Log { l := gethLog; l.BlockTimestamp = 0; return l }(),
			setupLP: func(lp *lpmocks.LogPoller) {
				lp.On("LatestBlock", mock.Anything).Return(logpoller.Block{BlockNumber: 200}, nil)
				lp.On("Logs", mock.Anything, int64(90), int64(100), topic, onRampAddress).Return([]logpoller.Log{stored}, nil)
			},
		},
		{
			name: "poller cannot answer yet", to: big.NewInt(100), finalized: 150, rpcLog: gethLog,
			setupLP: func(lp *lpmocks.LogPoller) {
				lp.On("LatestBlock", mock.Anything).Return(logpoller.Block{BlockNumber: 99}, nil)
			},
		},
		{
			name: "poller query fails", to: big.NewInt(100), finalized: 150, rpcLog: gethLog,
			setupLP: func(lp *lpmocks.LogPoller) {
				lp.On("LatestBlock", mock.Anything).Return(logpoller.Block{}, errors.New("db down"))
			},
		},
		{
			// Unfinalized blocks can still reorg or be un-ingested, so they are left out of the comparison.
			name: "open range compares only up to finalized", finalized: 92, rpcLog: gethLog,
			setupLP: func(lp *lpmocks.LogPoller) {
				lp.On("LatestBlock", mock.Anything).Return(logpoller.Block{BlockNumber: 200}, nil)
				lp.On("Logs", mock.Anything, int64(90), int64(92), topic, onRampAddress).Return([]logpoller.Log{}, nil)
			},
		},
		{
			name: "nothing finalized in the range", to: big.NewInt(100), finalized: 80, rpcLog: gethLog,
			setupLP: func(*lpmocks.LogPoller) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			lp := lpmocks.NewLogPoller(t)
			tt.setupLP(lp)
			tracker := headstest.NewTracker[*evmtypes.Head, common.Hash](t)
			tracker.On("LatestAndFinalizedBlock", mock.Anything).
				Return(&evmtypes.Head{Number: 300}, &evmtypes.Head{Number: tt.finalized}, nil)

			reader := newModeTestReader(t, onRampAddress, evmconfig.LogPollerModeShadow, lp, []types.Log{tt.rpcLog})
			reader.headTracker = tracker
			lggr, observed := logger.TestObserved(t, zapcore.WarnLevel)
			reader.lggr = lggr

			events, err := reader.FetchMessageSentEvents(t.Context(), big.NewInt(90), tt.to)
			require.NoError(t, err)
			require.Len(t, events, 1)
			require.Equal(t, message.MustMessageID(), events[0].MessageID)
			require.Equal(t, tt.wantWarn, observed.FilterMessage(disagreement).Len() > 0, observed.All())
		})
	}
}
