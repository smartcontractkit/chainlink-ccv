package sourcereader

import (
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func newInitialStartTestService(
	t *testing.T,
	reader *mocks.MockSourceReader,
	statuses map[protocol.ChainSelector]*protocol.ChainStatusInfo,
	initialStart *uint64,
) *Service {
	t.Helper()
	chain := protocol.ChainSelector(1337)
	status := mocks.NewMockChainStatusManager(t)
	status.EXPECT().ReadChainStatuses(mock.Anything, []protocol.ChainSelector{chain}).Return(statuses, nil).Once()
	curse := mocks.NewMockCurseCheckerService(t)
	srs, _, _ := newTestSRS(t, chain, reader, status, curse, time.Millisecond, 5000)
	srs.sourceCfg.InitialStartBlock = initialStart
	return srs
}

func TestInitializeStartBlockMigrationOverride(t *testing.T) {
	t.Run("default retains the 500-block fallback", func(t *testing.T) {
		reader := mocks.NewMockSourceReader(t)
		reader.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(
			&protocol.BlockHeader{Number: 2100}, &protocol.BlockHeader{Number: 2000}, nil).Once()
		srs := newInitialStartTestService(t, reader, map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil)
		start, err := srs.initializeStartBlock(t.Context())
		require.NoError(t, err)
		require.Equal(t, uint64(1500), start)
	})

	t.Run("new verifier can start older than the fallback", func(t *testing.T) {
		initial := uint64(100)
		reader := mocks.NewMockSourceReader(t)
		reader.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(
			&protocol.BlockHeader{Number: 2100}, &protocol.BlockHeader{Number: 2000}, nil).Once()
		srs := newInitialStartTestService(t, reader, map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, &initial)
		start, err := srs.initializeStartBlock(t.Context())
		require.NoError(t, err)
		require.Equal(t, initial, start)
	})

	t.Run("non-finalized start is rejected", func(t *testing.T) {
		initial := uint64(2001)
		reader := mocks.NewMockSourceReader(t)
		reader.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(
			&protocol.BlockHeader{Number: 2100}, &protocol.BlockHeader{Number: 2000}, nil).Once()
		srs := newInitialStartTestService(t, reader, map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, &initial)
		_, err := srs.initializeStartBlock(t.Context())
		require.ErrorContains(t, err, "is not finalized")
		require.ErrorContains(t, err, "2001")
		require.ErrorContains(t, err, "2000")
	})

	t.Run("checkpoint and disabled state take precedence", func(t *testing.T) {
		initial := uint64(100)
		chain := protocol.ChainSelector(1337)
		reader := mocks.NewMockSourceReader(t)
		srs := newInitialStartTestService(t, reader, map[protocol.ChainSelector]*protocol.ChainStatusInfo{
			chain: {ChainSelector: chain, FinalizedBlockHeight: big.NewInt(777), Disabled: true},
		}, &initial)
		start, err := srs.initializeStartBlock(t.Context())
		require.NoError(t, err)
		require.Equal(t, uint64(778), start)
		require.True(t, srs.disabled.Load())
		reader.AssertNotCalled(t, "LatestAndFinalizedBlock", mock.Anything)
	})
}
