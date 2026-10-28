package db_test

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

	evmdb "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm/db"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
)

var (
	ormTestAddress = common.HexToAddress("0x00000000000000000000000000000000000000a1")
	ormTestEvent   = common.HexToHash("0x00000000000000000000000000000000000000000000000000000000000000e1")
)

// Runs the pinned chainlink-evm ORM against the EVM accessor's own migrations, so our copied
// schema SQL drifting from what that ORM needs fails here.
func TestLogPollerORMAgainstEVMSchema(t *testing.T) {
	testDB := testutil.NewTestDB(t)
	handle := evmdb.NewLogPollerDB(testDB.DB)
	require.Same(t, testDB.DB, handle.DB, "the wrapper must reuse the shared pool, not open another")
	ctx := context.Background()

	newORM := func(t *testing.T, chainID int64) (*logpoller.DSORM, *big.Int) {
		t.Helper()
		id := big.NewInt(chainID)
		return logpoller.NewORM(id, handle, logger.Test(t)), id
	}

	t.Run("filters upsert and delete", func(t *testing.T) {
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
		require.Equal(t, 1, countRows(t, handle, "log_poller_filters", chainID), "second insert must upsert, not duplicate")

		_, err := orm.LoadFilters(ctx)
		require.NoError(t, err)
		require.NoError(t, orm.DeleteFilter(ctx, name))
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

		_, err := orm.SelectLatestBlock(ctx)
		require.NoError(t, err)
		_, err = orm.SelectBlockByNumber(ctx, 2)
		require.NoError(t, err)
		_, err = orm.GetBlocksRange(ctx, 2, 4)
		require.NoError(t, err)
		_, err = orm.SelectLatestFinalizedBlock(ctx)
		require.NoError(t, err)
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

		_, err := orm.SelectLogsWithSigs(ctx, 1, 2, ormTestAddress, []common.Hash{ormTestEvent})
		require.NoError(t, err)
	})

	t.Run("pruning queries run", func(t *testing.T) {
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

		_, err := orm.DeleteExpiredLogs(ctx, 0)
		require.NoError(t, err)
		unmatchedIDs, err := orm.SelectUnmatchedLogIDs(ctx, 100)
		require.NoError(t, err)
		excessIDs, err := orm.SelectExcessLogIDs(ctx, 100)
		require.NoError(t, err)
		_, err = orm.DeleteLogsByRowID(ctx, append(unmatchedIDs, excessIDs...))
		require.NoError(t, err)
		_, err = orm.DeleteBlocksBefore(ctx, 3, 0)
		require.NoError(t, err)
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
