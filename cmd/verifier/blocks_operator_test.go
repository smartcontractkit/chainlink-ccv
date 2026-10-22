package verifier

import (
	"context"
	"database/sql"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm/logpollerdb"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
)

const (
	sepolia   int64 = 11155111
	unknownID int64 = 4242424242
)

// operatorHarness builds an operator whose database opens are counted, so a test can show a check
// failed before anything was opened.
type operatorHarness struct {
	op        *blocksOperator
	dbOpens   int
	db        *sql.DB
	infoCalls int
}

func newOperatorHarness(t *testing.T, logPollerOn bool, db *sql.DB) *operatorHarness {
	t.Helper()
	h := &operatorHarness{db: db}
	h.op = &blocksOperator{
		lggr:     logger.Test(t),
		features: func() (bootstrap.Features, error) { return bootstrap.Features{LogPoller: logPollerOn}, nil },
		evmInfo: func(s protocol.ChainSelector) (evm.Info, error) {
			h.infoCalls++
			return evm.Info{ChainID: "11155111"}, nil
		},
		openDB: func(context.Context) (*sql.DB, func(), error) {
			h.dbOpens++
			if h.db == nil {
				return nil, nil, errors.New("no database")
			}
			return h.db, func() {}, nil
		},
	}
	return h
}

func TestBlocksOperatorFailsSafeBeforeTouchingAnything(t *testing.T) {
	t.Run("flag off", func(t *testing.T) {
		h := newOperatorHarness(t, false, nil)

		_, lcaErr := h.op.FindLCA(t.Context(), sepolia)
		removeErr := h.op.RemoveFrom(t.Context(), sepolia, 5)
		require.ErrorContains(t, lcaErr, "FindLCA is only available if LogPoller is enabled")
		require.ErrorContains(t, removeErr, "DeleteLogPollerDataAfter is only available if LogPoller is enabled")
		for _, err := range []error{lcaErr, removeErr} {
			require.ErrorContains(t, err, "RPC source reader")
			require.ErrorContains(t, err, bootstrap.ConfigPathEnv)
		}
		require.Zero(t, h.dbOpens, "no database is opened when the chain reads through RPC")
		require.Zero(t, h.infoCalls, "no RPC config is read either")
	})
	t.Run("feature section unreadable", func(t *testing.T) {
		h := newOperatorHarness(t, true, nil)
		h.op.features = func() (bootstrap.Features, error) { return bootstrap.Features{}, errors.New("no bootstrap config") }

		err := h.op.RemoveFrom(t.Context(), sepolia, 5)
		require.ErrorContains(t, err, "no bootstrap config")
		require.Zero(t, h.dbOpens)
	})
	t.Run("unknown chain ID", func(t *testing.T) {
		h := newOperatorHarness(t, true, nil)

		err := h.op.RemoveFrom(t.Context(), unknownID, 5)
		require.ErrorContains(t, err, "4242424242")
		require.ErrorContains(t, err, "not a known EVM chain")
		require.Zero(t, h.dbOpens)
	})
	t.Run("find-lca on a chain missing from the EVM config", func(t *testing.T) {
		h := newOperatorHarness(t, true, nil)
		h.op.evmInfo = func(s protocol.ChainSelector) (evm.Info, error) {
			return evm.Info{}, errors.New("chain selector 16015286601757825753 is not in the EVM config")
		}

		_, err := h.op.FindLCA(t.Context(), sepolia)
		require.ErrorContains(t, err, "not in the EVM config")
		require.Zero(t, h.dbOpens, "the RPC config is checked before the database is opened")
	})
	t.Run("no database configured", func(t *testing.T) {
		h := newOperatorHarness(t, true, nil)

		err := h.op.RemoveFrom(t.Context(), sepolia, 5)
		require.ErrorContains(t, err, "no database")
	})
}

func seedSepolia(t *testing.T, db *sql.DB, chainID *big.Int, n int64) {
	t.Helper()
	orm := logpoller.NewORM(chainID, logpollerdb.NewDB(db), logger.Test(t))
	var blocks []logpoller.Block
	var logs []logpoller.Log
	event := common.HexToHash("0xe1")
	for i := int64(1); i <= n; i++ {
		hash := common.BigToHash(big.NewInt(i))
		blocks = append(blocks, logpoller.Block{EVMChainID: sqlutil.New(chainID), BlockHash: hash, BlockNumber: i, BlockTimestamp: time.Now().UTC()})
		logs = append(logs, logpoller.Log{
			EVMChainID: sqlutil.New(chainID), BlockHash: hash, BlockNumber: i, BlockTimestamp: time.Now().UTC(),
			Topics: [][]byte{event.Bytes()}, EventSig: event, Address: common.HexToAddress("0xa1"),
			TxHash: common.BigToHash(big.NewInt(i * 1000)), Data: []byte{1},
		})
	}
	require.NoError(t, orm.InsertLogsWithBlocks(t.Context(), logs, blocks))
}

func TestBlocksOperatorRemovesThroughTheAdapter(t *testing.T) {
	db := testutil.NewTestDB(t).DB
	chainID := big.NewInt(11155111)
	seedSepolia(t, db, chainID, 6)
	h := newOperatorHarness(t, true, db)

	require.NoError(t, h.op.RemoveFrom(t.Context(), sepolia, 4))

	var blocks, logs int
	require.NoError(t, db.QueryRowContext(t.Context(),
		`SELECT (SELECT COUNT(*) FROM evm.log_poller_blocks WHERE evm_chain_id = $1), (SELECT COUNT(*) FROM evm.logs WHERE evm_chain_id = $1)`,
		sqlutil.New(chainID)).Scan(&blocks, &logs))
	require.Equal(t, 3, blocks)
	require.Equal(t, 3, logs)
	require.Zero(t, h.infoCalls, "remove-blocks needs no RPC config")
}

func TestBlocksOperatorFailsWhenTheLogPollerSchemaIsMissing(t *testing.T) {
	db := testutil.NewTestDB(t).DB
	_, err := db.ExecContext(t.Context(), `DROP SCHEMA evm CASCADE`)
	require.NoError(t, err)
	h := newOperatorHarness(t, true, db)

	err = h.op.RemoveFrom(t.Context(), sepolia, 4)
	require.ErrorContains(t, err, "evm.log_poller_blocks")
}

func TestUnsupportedBlocksOperatorExplainsWhy(t *testing.T) {
	op := unsupportedBlocksOperator{reason: "the token verifier has no LogPoller"}

	_, lcaErr := op.FindLCA(t.Context(), sepolia)
	removeErr := op.RemoveFrom(t.Context(), sepolia, 1)
	for _, err := range []error{lcaErr, removeErr} {
		require.ErrorContains(t, err, "the token verifier has no LogPoller")
	}
}
