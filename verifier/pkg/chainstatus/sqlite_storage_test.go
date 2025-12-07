package chainstatus

import (
	"context"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func newTestChainStatusManager(t *testing.T) (*SQLiteChainStatusManager, func()) {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "chainstatus-test-*")
	require.NoError(t, err)

	dbPath := filepath.Join(tmpDir, "test.db")
	lggr, err := logger.New()
	require.NoError(t, err)

	mgr, err := NewSQLiteChainStatusManager(dbPath, lggr)
	require.NoError(t, err)

	cleanup := func() {
		mgr.Close()
		os.RemoveAll(tmpDir)
	}

	return mgr, cleanup
}

func TestNewSQLiteChainStatusManager_ReturnsErrorWhenDBPathIsEmpty(t *testing.T) {
	lggr, err := logger.New()
	require.NoError(t, err)

	mgr, err := NewSQLiteChainStatusManager("", lggr)
	assert.Nil(t, mgr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database path cannot be empty")
}

func TestNewSQLiteChainStatusManager_CreatesDatabase(t *testing.T) {
	mgr, cleanup := newTestChainStatusManager(t)
	defer cleanup()

	assert.NotNil(t, mgr)
	assert.NotNil(t, mgr.db)
}

func TestWriteChainStatuses_WritesStatusesSuccessfully(t *testing.T) {
	mgr, cleanup := newTestChainStatusManager(t)
	defer cleanup()

	ctx := context.Background()
	statuses := []protocol.ChainStatusInfo{
		{
			ChainSelector:        protocol.ChainSelector(1),
			FinalizedBlockHeight: big.NewInt(100),
			Disabled:             false,
		},
		{
			ChainSelector:        protocol.ChainSelector(2),
			FinalizedBlockHeight: big.NewInt(200),
			Disabled:             true,
		},
	}

	err := mgr.WriteChainStatuses(ctx, statuses)
	require.NoError(t, err)

	result, err := mgr.ReadChainStatuses(ctx, []protocol.ChainSelector{1, 2})
	require.NoError(t, err)
	assert.Len(t, result, 2)

	assert.Equal(t, big.NewInt(100), result[protocol.ChainSelector(1)].FinalizedBlockHeight)
	assert.False(t, result[protocol.ChainSelector(1)].Disabled)

	assert.Equal(t, big.NewInt(200), result[protocol.ChainSelector(2)].FinalizedBlockHeight)
	assert.True(t, result[protocol.ChainSelector(2)].Disabled)
}

func TestWriteChainStatuses_UpdatesExistingStatuses(t *testing.T) {
	mgr, cleanup := newTestChainStatusManager(t)
	defer cleanup()

	ctx := context.Background()
	chainSelector := protocol.ChainSelector(1)

	err := mgr.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
		{
			ChainSelector:        chainSelector,
			FinalizedBlockHeight: big.NewInt(100),
			Disabled:             false,
		},
	})
	require.NoError(t, err)

	err = mgr.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
		{
			ChainSelector:        chainSelector,
			FinalizedBlockHeight: big.NewInt(200),
			Disabled:             true,
		},
	})
	require.NoError(t, err)

	result, err := mgr.ReadChainStatuses(ctx, []protocol.ChainSelector{chainSelector})
	require.NoError(t, err)
	require.Len(t, result, 1)

	status := result[chainSelector]
	assert.Equal(t, big.NewInt(200), status.FinalizedBlockHeight)
	assert.True(t, status.Disabled)
}

func TestWriteChainStatuses_NilBlockHeightReturnsError(t *testing.T) {
	mgr, cleanup := newTestChainStatusManager(t)
	defer cleanup()

	ctx := context.Background()
	chainSelector := protocol.ChainSelector(1)

	err := mgr.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
		{
			ChainSelector:        chainSelector,
			FinalizedBlockHeight: nil,
			Disabled:             false,
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "finalized block height cannot be nil")
}

func TestWriteChainStatuses_HandlesEmptyStatuses(t *testing.T) {
	mgr, cleanup := newTestChainStatusManager(t)
	defer cleanup()

	ctx := context.Background()
	err := mgr.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{})
	require.NoError(t, err)
}

func TestReadChainStatuses_ReturnsEmptyMapWhenNoSelectorsProvided(t *testing.T) {
	mgr, cleanup := newTestChainStatusManager(t)
	defer cleanup()

	ctx := context.Background()
	result, err := mgr.ReadChainStatuses(ctx, []protocol.ChainSelector{})
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestReadChainStatuses_ReturnsEmptyMapWhenChainsNotFound(t *testing.T) {
	mgr, cleanup := newTestChainStatusManager(t)
	defer cleanup()

	ctx := context.Background()
	result, err := mgr.ReadChainStatuses(ctx, []protocol.ChainSelector{999})
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestReadChainStatuses_NonExistingChainReturnsNilNotDisabled(t *testing.T) {
	mgr, cleanup := newTestChainStatusManager(t)
	defer cleanup()

	ctx := context.Background()
	nonExistingChain := protocol.ChainSelector(999)

	result, err := mgr.ReadChainStatuses(ctx, []protocol.ChainSelector{nonExistingChain})
	require.NoError(t, err)

	status, exists := result[nonExistingChain]
	assert.False(t, exists, "non-existing chain should not be present in the result map")
	assert.Nil(t, status, "non-existing chain status should be nil")
}

func TestReadChainStatuses_ReturnsOnlyRequestedChains(t *testing.T) {
	mgr, cleanup := newTestChainStatusManager(t)
	defer cleanup()

	ctx := context.Background()

	err := mgr.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
		{ChainSelector: protocol.ChainSelector(1), FinalizedBlockHeight: big.NewInt(100)},
		{ChainSelector: protocol.ChainSelector(2), FinalizedBlockHeight: big.NewInt(200)},
		{ChainSelector: protocol.ChainSelector(3), FinalizedBlockHeight: big.NewInt(300)},
	})
	require.NoError(t, err)

	result, err := mgr.ReadChainStatuses(ctx, []protocol.ChainSelector{1, 3})
	require.NoError(t, err)
	assert.Len(t, result, 2)
	assert.Contains(t, result, protocol.ChainSelector(1))
	assert.Contains(t, result, protocol.ChainSelector(3))
	assert.NotContains(t, result, protocol.ChainSelector(2))
}

func TestReadChainStatuses_HandlesLargeBlockHeights(t *testing.T) {
	mgr, cleanup := newTestChainStatusManager(t)
	defer cleanup()

	ctx := context.Background()
	chainSelector := protocol.ChainSelector(1)

	largeBlockHeight := new(big.Int)
	largeBlockHeight.SetString("999999999999999999999999999999", 10)

	err := mgr.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
		{
			ChainSelector:        chainSelector,
			FinalizedBlockHeight: largeBlockHeight,
			Disabled:             false,
		},
	})
	require.NoError(t, err)

	result, err := mgr.ReadChainStatuses(ctx, []protocol.ChainSelector{chainSelector})
	require.NoError(t, err)
	require.Len(t, result, 1)

	assert.Equal(t, 0, largeBlockHeight.Cmp(result[chainSelector].FinalizedBlockHeight))
}

func TestClose_ClosesDatabase(t *testing.T) {
	mgr, cleanup := newTestChainStatusManager(t)
	defer cleanup()

	err := mgr.Close()
	require.NoError(t, err)

	ctx := context.Background()
	_, err = mgr.ReadChainStatuses(ctx, []protocol.ChainSelector{1})
	assert.Error(t, err)
}
