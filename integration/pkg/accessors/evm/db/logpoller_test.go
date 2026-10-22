package db_test

import (
	"context"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"

	evmdb "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm/db"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
)

// The ORM maps struct fields to snake_case columns. A plain sqlx handle (what the verifier
// uses for its own storage) cannot insert logs, so the wrapper must not be simplified away.
func TestNewDB_MapperAndSharedPool(t *testing.T) {
	testDB := testutil.NewTestDB(t)
	ctx := context.Background()
	chainID := big.NewInt(900_001)
	logs := []logpoller.Log{testLog(chainID, 1, 0, common.HexToAddress("0x01"), common.HexToHash("0xaa"))}

	t.Run("plain handle cannot insert logs", func(t *testing.T) {
		orm := logpoller.NewORM(chainID, testDB, logger.Test(t))
		require.Error(t, orm.InsertLogs(ctx, logs))
	})

	t.Run("wrapped handle inserts logs on the shared pool", func(t *testing.T) {
		func() {
			handle := evmdb.NewLogPollerDB(testDB.DB)
			require.Same(t, testDB.DB, handle.DB, "wrapper must reuse the shared pool, not open another")
			require.NoError(t, logpoller.NewORM(chainID, handle, logger.Test(t)).InsertLogs(ctx, logs))
		}()

		require.NoError(t, testDB.PingContext(ctx), "shared pool must outlive the dropped wrapper")

		var n int
		require.NoError(t, testDB.GetContext(ctx, &n, `SELECT COUNT(*) FROM evm.logs WHERE evm_chain_id = $1`, sqlutil.New(chainID)))
		require.Equal(t, 1, n)
	})
}
