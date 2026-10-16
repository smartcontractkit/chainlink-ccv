package logpollerdb

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"
	evmtypes "github.com/smartcontractkit/chainlink-evm/pkg/types"

	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
)

var (
	ormTestAddress = common.HexToAddress("0x00000000000000000000000000000000000000a1")
	ormTestEvent   = common.HexToHash("0x00000000000000000000000000000000000000000000000000000000000000e1")
)

// Runs the pinned chainlink-evm ORM against the schema from the verifier's own migrations,
// so a chainlink-evm bump that expects a different schema fails here.
// Any ORM method the LogPoller starts calling must get a case below.
func TestLogPollerORMAgainstVerifierSchema(t *testing.T) {
	testDB := testutil.NewTestDB(t)
	handle := NewDB(testDB.DB)
	ctx := context.Background()

	newORM := func(t *testing.T, chainID int64) (*logpoller.DSORM, *big.Int) {
		t.Helper()
		id := big.NewInt(chainID)
		return logpoller.NewORM(id, handle, logger.Test(t)), id
	}

	t.Run("filters are idempotent and removable", func(t *testing.T) {
		orm, chainID := newORM(t, 910_001)
		name := logpoller.FilterName("ccv-verifier", "verifier-1", ormTestAddress)
		filter := logpoller.Filter{
			Name:      name,
			Addresses: evmtypes.AddressArray{ormTestAddress},
			EventSigs: evmtypes.HashArray{ormTestEvent},
			Retention: time.Hour,
		}

		require.NoError(t, orm.InsertFilter(ctx, filter))
		filter.Retention = 2 * time.Hour
		require.NoError(t, orm.InsertFilter(ctx, filter))

		loaded, err := orm.LoadFilters(ctx)
		require.NoError(t, err)
		require.Len(t, loaded, 1)
		require.Equal(t, 2*time.Hour, loaded[name].Retention)
		require.Equal(t, 1, countRows(t, handle, "log_poller_filters", chainID), "second insert must upsert, not duplicate")

		require.NoError(t, orm.DeleteFilter(ctx, name))
		loaded, err = orm.LoadFilters(ctx)
		require.NoError(t, err)
		require.Empty(t, loaded)
	})

	t.Run("blocks insert once and read back", func(t *testing.T) {
		orm, chainID := newORM(t, 910_002)
		blocks := make([]logpoller.Block, 0, 5)
		for n := int64(1); n <= 5; n++ {
			blocks = append(blocks, testBlock(chainID, n, 3))
		}

		require.NoError(t, orm.InsertLogsWithBlocks(ctx, nil, blocks))
		require.NoError(t, orm.InsertBlock(ctx, blocks[4].BlockHash, 5, blocks[4].BlockTimestamp, 3, 4))
		require.Equal(t, 5, countRows(t, handle, "log_poller_blocks", chainID), "duplicate block must be ignored")

		latest, err := orm.SelectLatestBlock(ctx)
		require.NoError(t, err)
		require.Equal(t, int64(5), latest.BlockNumber)

		byNumber, err := orm.SelectBlockByNumber(ctx, 2)
		require.NoError(t, err)
		require.Equal(t, blocks[1].BlockHash, byNumber.BlockHash)

		inRange, err := orm.GetBlocksRange(ctx, 2, 4)
		require.NoError(t, err)
		require.Len(t, inRange, 3)

		finalized, err := orm.SelectLatestFinalizedBlock(ctx)
		require.NoError(t, err)
		require.Equal(t, int64(3), finalized.BlockNumber)
	})

	t.Run("logs insert once and read back", func(t *testing.T) {
		orm, chainID := newORM(t, 910_003)
		logs := []logpoller.Log{
			testLog(chainID, 1, 0, ormTestAddress, ormTestEvent),
			testLog(chainID, 1, 1, ormTestAddress, ormTestEvent),
			testLog(chainID, 2, 0, ormTestAddress, ormTestEvent),
		}

		require.NoError(t, orm.InsertLogs(ctx, logs))
		require.NoError(t, orm.InsertLogs(ctx, logs))
		require.Equal(t, 3, countRows(t, handle, "logs", chainID), "replayed logs must not duplicate")

		bySig, err := orm.SelectLogs(ctx, 1, 2, ormTestAddress, ormTestEvent)
		require.NoError(t, err)
		require.Len(t, bySig, 3)

		byRange, err := orm.SelectLogsByBlockRange(ctx, 2, 2)
		require.NoError(t, err)
		require.Len(t, byRange, 1)
	})

	t.Run("reorg delete keeps rows below the start block", func(t *testing.T) {
		orm, chainID := newORM(t, 910_004)
		var logs []logpoller.Log
		var blocks []logpoller.Block
		for n := int64(1); n <= 4; n++ {
			blocks = append(blocks, testBlock(chainID, n, 0))
			logs = append(logs, testLog(chainID, n, 0, ormTestAddress, ormTestEvent))
		}
		require.NoError(t, orm.InsertLogsWithBlocks(ctx, logs, blocks))

		require.NoError(t, orm.DeleteLogsAndBlocksAfter(ctx, 3))

		require.Equal(t, 2, countRows(t, handle, "log_poller_blocks", chainID))
		require.Equal(t, 2, countRows(t, handle, "logs", chainID))
	})

	t.Run("pruning removes expired, unmatched, excess logs and old blocks", func(t *testing.T) {
		orm, chainID := newORM(t, 910_005)
		unmatched := common.HexToAddress("0x00000000000000000000000000000000000000b2")

		require.NoError(t, orm.InsertFilter(ctx, logpoller.Filter{
			Name:        "kept",
			Addresses:   evmtypes.AddressArray{ormTestAddress},
			EventSigs:   evmtypes.HashArray{ormTestEvent},
			Retention:   time.Hour,
			MaxLogsKept: 2,
		}))

		expired := testLog(chainID, 1, 0, ormTestAddress, ormTestEvent)
		expired.BlockTimestamp = time.Now().Add(-3 * time.Hour)
		logs := []logpoller.Log{
			expired,
			testLog(chainID, 2, 0, ormTestAddress, ormTestEvent),
			testLog(chainID, 3, 0, ormTestAddress, ormTestEvent),
			testLog(chainID, 4, 0, ormTestAddress, ormTestEvent),
			testLog(chainID, 5, 0, unmatched, ormTestEvent),
		}
		var blocks []logpoller.Block
		for n := int64(1); n <= 6; n++ {
			blocks = append(blocks, testBlock(chainID, n, 6))
		}
		require.NoError(t, orm.InsertLogsWithBlocks(ctx, logs, blocks))

		deleted, err := orm.DeleteExpiredLogs(ctx, 0)
		require.NoError(t, err)
		require.Equal(t, int64(1), deleted)

		unmatchedIDs, err := orm.SelectUnmatchedLogIDs(ctx, 100)
		require.NoError(t, err)
		require.Len(t, unmatchedIDs, 1)

		excessIDs, err := orm.SelectExcessLogIDs(ctx, 100)
		require.NoError(t, err)
		require.Len(t, excessIDs, 1, "three matching logs with MaxLogsKept=2 leaves one excess")

		removed, err := orm.DeleteLogsByRowID(ctx, append(unmatchedIDs, excessIDs...))
		require.NoError(t, err)
		require.Equal(t, int64(2), removed)
		require.Equal(t, 2, countRows(t, handle, "logs", chainID))

		blocksRemoved, err := orm.DeleteBlocksBefore(ctx, 3, 0)
		require.NoError(t, err)
		require.Equal(t, int64(3), blocksRemoved)
		require.Equal(t, 3, countRows(t, handle, "log_poller_blocks", chainID))
	})
}

func countRows(t *testing.T, handle *sqlx.DB, table string, chainID *big.Int) int {
	t.Helper()
	var n int
	require.NoError(t, handle.Get(&n, `SELECT COUNT(*) FROM evm.`+table+` WHERE evm_chain_id = $1`, sqlutil.New(chainID)))
	return n
}

func testBlock(chainID *big.Int, number, finalized int64) logpoller.Block {
	return logpoller.Block{
		EVMChainID:           sqlutil.New(chainID),
		BlockHash:            common.BigToHash(big.NewInt(number)),
		BlockNumber:          number,
		BlockTimestamp:       time.Now().UTC(),
		FinalizedBlockNumber: finalized,
		SafeBlockNumber:      finalized,
	}
}

func testLog(chainID *big.Int, block, index int64, address common.Address, event common.Hash) logpoller.Log {
	return logpoller.Log{
		EVMChainID:     sqlutil.New(chainID),
		LogIndex:       index,
		BlockHash:      common.BigToHash(big.NewInt(block)),
		BlockNumber:    block,
		BlockTimestamp: time.Now().UTC(),
		Topics:         [][]byte{event.Bytes()},
		EventSig:       event,
		Address:        address,
		TxHash:         common.BigToHash(big.NewInt(block*1000 + index)),
		Data:           []byte{0x01},
	}
}
