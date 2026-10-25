package blocks

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
	evmdb "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm/db"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evmconfig"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vsecrets"
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
		lggr:        logger.Test(t),
		logPollerOn: func() (bool, error) { return logPollerOn, nil },
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
			require.ErrorContains(t, err, evmconfig.EVMConfigPathEnv)
		}
		require.Zero(t, h.dbOpens, "no database is opened when the chain reads through RPC")
		require.Zero(t, h.infoCalls, "no RPC config is read either")
	})
	t.Run("EVM config unreadable", func(t *testing.T) {
		h := newOperatorHarness(t, true, nil)
		h.op.logPollerOn = func() (bool, error) { return false, errors.New("no EVM config") }

		err := h.op.RemoveFrom(t.Context(), sepolia, 5)
		require.ErrorContains(t, err, "no EVM config")
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
}

func seedBlocks(t *testing.T, db *sql.DB, chainID *big.Int, n int64) {
	t.Helper()
	orm := logpoller.NewORM(chainID, evmdb.NewLogPollerDB(db), logger.Test(t))
	var blocks []logpoller.Block
	for i := int64(1); i <= n; i++ {
		blocks = append(blocks, logpoller.Block{EVMChainID: sqlutil.New(chainID), BlockHash: common.BigToHash(big.NewInt(i)), BlockNumber: i, BlockTimestamp: time.Now().UTC()})
	}
	require.NoError(t, orm.InsertLogsWithBlocks(t.Context(), nil, blocks))
}

func TestOpenEVMDBNeedsTheEVMDatabase(t *testing.T) {
	t.Setenv(evmconfig.EVMSecretsPathEnv, filepath.Join(t.TempDir(), "secrets.toml"))

	_, _, err := openEVMDB(t.Context(), logger.Test(t))
	require.ErrorContains(t, err, "[db].url in the EVM secrets file")
	require.ErrorContains(t, err, evmconfig.EVMSecretsPathEnv)
}

// Shares one database; the schema-drop case runs last because it is destructive.
func TestBlocksOperatorAgainstTheEVMDatabase(t *testing.T) {
	testDB, dbURL := testutil.NewTestDBWithURL(t)
	db := testDB.DB

	// The LogPoller tables live in the EVM database, so the verifier's own database settings
	// must not be used.
	t.Run("openEVMDB opens the database from the EVM secrets file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "secrets.toml")
		require.NoError(t, os.WriteFile(path, []byte(fmt.Sprintf("[db]\nurl = %q\n", dbURL)), 0o600))
		t.Setenv(evmconfig.EVMSecretsPathEnv, path)
		t.Setenv(vsecrets.DatabaseURLEnvVar, "postgres://nobody@127.0.0.1:1/not-the-evm-db")

		opened, closeDB, err := openEVMDB(t.Context(), logger.Test(t))
		require.NoError(t, err)
		defer closeDB()
		require.NoError(t, evm.CheckLogPollerSchema(t.Context(), opened))
	})

	t.Run("remove-blocks deletes through the adapter", func(t *testing.T) {
		chainID := big.NewInt(sepolia)
		seedBlocks(t, db, chainID, 6)
		h := newOperatorHarness(t, true, db)

		require.NoError(t, h.op.RemoveFrom(t.Context(), sepolia, 4))

		var highest int64
		require.NoError(t, db.QueryRowContext(t.Context(),
			`SELECT MAX(block_number) FROM evm.log_poller_blocks WHERE evm_chain_id = $1`, sqlutil.New(chainID)).Scan(&highest))
		require.Equal(t, int64(3), highest, "blocks from --start up are deleted")
		require.Zero(t, h.infoCalls, "remove-blocks needs no RPC config")
	})

	t.Run("fails when the LogPoller schema is missing", func(t *testing.T) {
		_, err := db.ExecContext(t.Context(), `DROP SCHEMA evm CASCADE`)
		require.NoError(t, err)
		h := newOperatorHarness(t, true, db)

		err = h.op.RemoveFrom(t.Context(), sepolia, 4)
		require.ErrorContains(t, err, "evm.log_poller_blocks")
	})
}
