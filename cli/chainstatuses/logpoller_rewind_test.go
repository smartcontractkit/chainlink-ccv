package chainstatuses

import (
	"context"
	"math"
	"math/big"
	"strconv"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jmoiron/sqlx"
	"github.com/scylladb/go-reflectx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"

	chainselectors "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"

	"github.com/smartcontractkit/chainlink-ccv/cli/chainstatuses/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/chainstatus"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
)

const rewindTestVerifierID = "rewind-verifier"

var (
	rewindEVMSelector    = protocol.ChainSelector(chainselectors.ETHEREUM_TESTNET_SEPOLIA.Selector)
	rewindEVMChainID     = int64(chainselectors.ETHEREUM_TESTNET_SEPOLIA.EvmChainID)
	rewindNonEVMSelector = protocol.ChainSelector(chainselectors.SOLANA_MAINNET.Selector)
	// Rows for another chain must never be touched by a rewind.
	rewindOtherChainID = int64(1)
	rewindOnRamp       = common.HexToAddress("0x00000000000000000000000000000000000000aa")
)

// newRewindTestDB returns a test database whose sqlx handle maps CamelCase fields to snake_case columns, as the
// Chainlink node's handle does. The LogPoller ORM scans into structs without db tags and relies on that mapper.
func newRewindTestDB(t *testing.T) *sqlx.DB {
	t.Helper()
	db := testutil.NewTestDB(t)
	db.MapperFunc(reflectx.CamelToSnakeASCII)
	return db
}

// createLogPollerSchema creates the LogPoller tables with the columns the LogPoller ORM reads or deletes by.
func createLogPollerSchema(t *testing.T, db *sqlx.DB) {
	t.Helper()
	_, err := db.Exec(`
		CREATE SCHEMA evm;
		CREATE TABLE evm.log_poller_blocks (
			evm_chain_id numeric(78,0) NOT NULL,
			block_hash bytea NOT NULL,
			block_number bigint NOT NULL,
			block_timestamp timestamptz NOT NULL,
			finalized_block_number bigint NOT NULL DEFAULT 0,
			safe_block_number bigint NOT NULL DEFAULT 0,
			created_at timestamptz NOT NULL,
			PRIMARY KEY (evm_chain_id, block_number)
		);
		CREATE TABLE evm.logs (
			evm_chain_id numeric(78,0) NOT NULL,
			block_number bigint NOT NULL,
			log_index bigint NOT NULL
		);
		CREATE TABLE evm.log_poller_filters (
			evm_chain_id numeric(78,0) NOT NULL,
			name text NOT NULL,
			address bytea NOT NULL DEFAULT decode(repeat('00', 20), 'hex'),
			event bytea NOT NULL DEFAULT decode(repeat('00', 32), 'hex'),
			topic2 bytea,
			topic3 bytea,
			topic4 bytea,
			retention bigint DEFAULT 0,
			max_logs_kept bigint NOT NULL DEFAULT 0,
			logs_per_block bigint NOT NULL DEFAULT 0
		);`)
	require.NoError(t, err)
}

func resetRewindDB(t *testing.T, db *sqlx.DB, withLogPoller bool, height int64) {
	t.Helper()
	_, err := db.Exec(`DROP SCHEMA IF EXISTS evm CASCADE`)
	require.NoError(t, err)
	if withLogPoller {
		createLogPollerSchema(t, db)
	}
	_, err = db.Exec(`DELETE FROM ccv_chain_statuses`)
	require.NoError(t, err)
	store := chainstatus.NewPostgresChainStatusStore(db, logger.Test(t))
	for _, sel := range []protocol.ChainSelector{rewindEVMSelector, rewindNonEVMSelector} {
		err = chainstatus.NewPostgresChainStatusManager(store, rewindTestVerifierID).WriteChainStatuses(t.Context(), []protocol.ChainStatusInfo{
			{ChainSelector: sel, FinalizedBlockHeight: big.NewInt(height)},
		})
		require.NoError(t, err)
	}
}

func insertFilter(t *testing.T, db *sqlx.DB, chainID int64, name string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO evm.log_poller_filters (evm_chain_id, name) VALUES ($1, $2)`, strconv.FormatInt(chainID, 10), name)
	require.NoError(t, err)
}

// insertBlocks stores LogPoller blocks and one log per block for [from, to].
func insertBlocks(t *testing.T, db *sqlx.DB, chainID, from, to int64) {
	t.Helper()
	for n := from; n <= to; n++ {
		_, err := db.Exec(`INSERT INTO evm.log_poller_blocks
			(evm_chain_id, block_hash, block_number, block_timestamp, finalized_block_number, safe_block_number, created_at)
			VALUES ($1, $2, $3, $4, $3, $3, NOW())`,
			strconv.FormatInt(chainID, 10), common.BigToHash(big.NewInt(n)).Bytes(), n, time.Unix(n, 0))
		require.NoError(t, err)
	}
	insertLogs(t, db, chainID, from, to)
}

// insertLogs stores one log per block for [from, to] without a matching block row.
func insertLogs(t *testing.T, db *sqlx.DB, chainID, from, to int64) {
	t.Helper()
	for n := from; n <= to; n++ {
		_, err := db.Exec(`INSERT INTO evm.logs (evm_chain_id, block_number, log_index) VALUES ($1, $2, 0)`, strconv.FormatInt(chainID, 10), n)
		require.NoError(t, err)
	}
}

type blockRange struct {
	Count int64  `db:"count"`
	Max   *int64 `db:"max"`
}

func lpBlocks(t *testing.T, db *sqlx.DB, chainID int64) blockRange {
	t.Helper()
	var r blockRange
	require.NoError(t, db.Get(&r, `SELECT COUNT(*) AS count, MAX(block_number) AS max FROM evm.log_poller_blocks WHERE evm_chain_id = $1`, strconv.FormatInt(chainID, 10)))
	return r
}

func lpLogs(t *testing.T, db *sqlx.DB, chainID int64) blockRange {
	t.Helper()
	var r blockRange
	require.NoError(t, db.Get(&r, `SELECT COUNT(*) AS count, MAX(block_number) AS max FROM evm.logs WHERE evm_chain_id = $1`, strconv.FormatInt(chainID, 10)))
	return r
}

type storedStatus struct {
	Height   string `db:"finalized_block_height"`
	Disabled bool   `db:"disabled"`
}

func storedRow(t *testing.T, db *sqlx.DB, sel protocol.ChainSelector) storedStatus {
	t.Helper()
	var s storedStatus
	require.NoError(t, db.Get(&s, `SELECT finalized_block_height, disabled FROM ccv_chain_statuses WHERE chain_selector = $1 AND verifier_id = $2`,
		strconv.FormatUint(uint64(sel), 10), rewindTestVerifierID))
	return s
}

func storedHeight(t *testing.T, db *sqlx.DB, sel protocol.ChainSelector) string {
	t.Helper()
	return storedRow(t, db, sel).Height
}

func runSetFinalizedHeightWithStore(t *testing.T, store ChainStatusStore, sel protocol.ChainSelector, height string) error {
	t.Helper()
	deps := Deps{Logger: logger.Test(t), Store: store}
	cmd := findCmd(InitCCVChainStatusesCommands(deps), cmdNameSetFinalizedHeight)
	require.NotNil(t, cmd)
	app := cli.NewApp()
	app.Commands = []cli.Command{*cmd}
	return app.Run([]string{
		"chainlink", cmdNameSetFinalizedHeight,
		"--chain-selector", strconv.FormatUint(uint64(sel), 10),
		"--verifier-id", rewindTestVerifierID,
		"--block-height", height,
	})
}

func runSetFinalizedHeight(t *testing.T, db *sqlx.DB, sel protocol.ChainSelector, height int64) error {
	t.Helper()
	return runSetFinalizedHeightWithStore(t, chainstatus.NewPostgresChainStatusStore(db, logger.Test(t)), sel, strconv.FormatInt(height, 10))
}

// rewindTarget builds the rewind target for the EVM test chain against db.
func rewindTarget(t *testing.T, db *sqlx.DB, verifierID string, height int64) *logPollerRewindTarget {
	t.Helper()
	target, reason, err := newLogPollerRewindTarget(chainstatus.NewPostgresChainStatusStore(db, logger.Test(t)), rewindEVMSelector, verifierID, big.NewInt(height))
	require.NoError(t, err)
	require.Empty(t, reason)
	require.NotNil(t, target)
	return target
}

func TestSetFinalizedHeight_LogPollerRewind(t *testing.T) {
	db := newRewindTestDB(t)
	filterName := logpoller.FilterName(rewindTestVerifierID, rewindOnRamp.Hex())

	t.Run("rewind deletes blocks and logs after height", func(t *testing.T) {
		resetRewindDB(t, db, true, 200)
		insertFilter(t, db, rewindEVMChainID, filterName)
		insertBlocks(t, db, rewindEVMChainID, 100, 200)
		insertBlocks(t, db, rewindOtherChainID, 100, 200)

		require.NoError(t, runSetFinalizedHeight(t, db, rewindEVMSelector, 150))

		row := storedRow(t, db, rewindEVMSelector)
		assert.Equal(t, "150", row.Height)
		assert.False(t, row.Disabled)
		blocks := lpBlocks(t, db, rewindEVMChainID)
		require.NotNil(t, blocks.Max)
		assert.Equal(t, int64(150), *blocks.Max)
		assert.Equal(t, int64(51), blocks.Count)
		logs := lpLogs(t, db, rewindEVMChainID)
		require.NotNil(t, logs.Max)
		assert.Equal(t, int64(150), *logs.Max)
		// Other chains are untouched.
		assert.Equal(t, int64(101), lpBlocks(t, db, rewindOtherChainID).Count)
		assert.Equal(t, int64(101), lpLogs(t, db, rewindOtherChainID).Count)
	})

	t.Run("sparse blocks keep logs at or below the height that have no block row", func(t *testing.T) {
		resetRewindDB(t, db, true, 300)
		insertFilter(t, db, rewindEVMChainID, filterName)
		// Backfill stores only the end block of each batch, so logs exist for blocks with no block row.
		insertBlocks(t, db, rewindEVMChainID, 100, 100)
		insertLogs(t, db, rewindEVMChainID, 101, 299)
		insertBlocks(t, db, rewindEVMChainID, 300, 300)
		lggr := logger.Test(t)
		store := chainstatus.NewPostgresChainStatusStore(db, lggr)
		target := rewindTarget(t, db, rewindTestVerifierID, 200)

		var msg string
		err := store.SetFinalizedBlockHeightWith(t.Context(), rewindEVMSelector, rewindTestVerifierID, big.NewInt(200),
			func(ctx context.Context, tx sqlutil.DataSource, txStore *chainstatus.PostgresChainStatusStore) error {
				var rerr error
				msg, rerr = target.rewind(ctx, tx, txStore, lggr)
				return rerr
			})
		require.NoError(t, err)

		assert.Contains(t, msg, "from block 201 onward")
		assert.Contains(t, msg, "verifier resumes at block 201")
		row := storedRow(t, db, rewindEVMSelector)
		assert.Equal(t, "200", row.Height)
		assert.False(t, row.Disabled)
		blocks := lpBlocks(t, db, rewindEVMChainID)
		assert.Equal(t, int64(1), blocks.Count)
		require.NotNil(t, blocks.Max)
		assert.Equal(t, int64(100), *blocks.Max)
		logs := lpLogs(t, db, rewindEVMChainID)
		assert.Equal(t, int64(101), logs.Count)
		require.NotNil(t, logs.Max)
		assert.Equal(t, int64(200), *logs.Max)
	})

	t.Run("height at min keeps that block", func(t *testing.T) {
		resetRewindDB(t, db, true, 200)
		insertFilter(t, db, rewindEVMChainID, filterName)
		insertBlocks(t, db, rewindEVMChainID, 100, 200)

		require.NoError(t, runSetFinalizedHeight(t, db, rewindEVMSelector, 100))

		row := storedRow(t, db, rewindEVMSelector)
		assert.Equal(t, "100", row.Height)
		assert.False(t, row.Disabled)
		blocks := lpBlocks(t, db, rewindEVMChainID)
		assert.Equal(t, int64(1), blocks.Count)
		require.NotNil(t, blocks.Max)
		assert.Equal(t, int64(100), *blocks.Max)
	})

	t.Run("forward height is a no-op for the LogPoller", func(t *testing.T) {
		resetRewindDB(t, db, true, 100)
		insertFilter(t, db, rewindEVMChainID, filterName)
		insertBlocks(t, db, rewindEVMChainID, 100, 200)

		require.NoError(t, runSetFinalizedHeight(t, db, rewindEVMSelector, 250))

		row := storedRow(t, db, rewindEVMSelector)
		assert.Equal(t, "250", row.Height)
		assert.False(t, row.Disabled)
		assert.Equal(t, int64(101), lpBlocks(t, db, rewindEVMChainID).Count)
		assert.Equal(t, int64(101), lpLogs(t, db, rewindEVMChainID).Count)
	})

	t.Run("height equal to max is a no-op for the LogPoller", func(t *testing.T) {
		resetRewindDB(t, db, true, 100)
		insertFilter(t, db, rewindEVMChainID, filterName)
		insertBlocks(t, db, rewindEVMChainID, 100, 200)

		require.NoError(t, runSetFinalizedHeight(t, db, rewindEVMSelector, 200))

		assert.Equal(t, "200", storedHeight(t, db, rewindEVMSelector))
		assert.Equal(t, int64(101), lpBlocks(t, db, rewindEVMChainID).Count)
	})

	t.Run("no LogPoller blocks deletes stray logs, sets height and disables the chain", func(t *testing.T) {
		resetRewindDB(t, db, true, 200)
		insertFilter(t, db, rewindEVMChainID, filterName)
		insertLogs(t, db, rewindEVMChainID, 140, 160)
		insertBlocks(t, db, rewindOtherChainID, 100, 200)

		require.NoError(t, runSetFinalizedHeight(t, db, rewindEVMSelector, 150))

		row := storedRow(t, db, rewindEVMSelector)
		assert.Equal(t, "150", row.Height)
		assert.True(t, row.Disabled)
		assert.Equal(t, int64(0), lpBlocks(t, db, rewindEVMChainID).Count)
		logs := lpLogs(t, db, rewindEVMChainID)
		assert.Equal(t, int64(11), logs.Count)
		require.NotNil(t, logs.Max)
		assert.Equal(t, int64(150), *logs.Max)
		// Other chains are untouched, and so is this verifier's row for another chain.
		assert.Equal(t, int64(101), lpBlocks(t, db, rewindOtherChainID).Count)
		assert.Equal(t, int64(101), lpLogs(t, db, rewindOtherChainID).Count)
		assert.False(t, storedRow(t, db, rewindNonEVMSelector).Disabled)
	})

	t.Run("height below lowest LogPoller block deletes everything above it, sets height and disables the chain", func(t *testing.T) {
		resetRewindDB(t, db, true, 200)
		insertFilter(t, db, rewindEVMChainID, filterName)
		insertBlocks(t, db, rewindEVMChainID, 100, 200)
		insertBlocks(t, db, rewindOtherChainID, 100, 200)

		require.NoError(t, runSetFinalizedHeight(t, db, rewindEVMSelector, 99))

		row := storedRow(t, db, rewindEVMSelector)
		assert.Equal(t, "99", row.Height)
		assert.True(t, row.Disabled)
		assert.Equal(t, int64(0), lpBlocks(t, db, rewindEVMChainID).Count)
		assert.Equal(t, int64(0), lpLogs(t, db, rewindEVMChainID).Count)
		assert.Equal(t, int64(101), lpBlocks(t, db, rewindOtherChainID).Count)
		assert.Equal(t, int64(101), lpLogs(t, db, rewindOtherChainID).Count)
	})

	t.Run("LogPoller tables absent sets height only", func(t *testing.T) {
		resetRewindDB(t, db, false, 200)

		require.NoError(t, runSetFinalizedHeight(t, db, rewindEVMSelector, 150))

		row := storedRow(t, db, rewindEVMSelector)
		assert.Equal(t, "150", row.Height)
		assert.False(t, row.Disabled)
	})

	t.Run("no filter for this verifier sets height only", func(t *testing.T) {
		resetRewindDB(t, db, true, 200)
		// Filters for another verifier on this chain, and for this verifier on another chain, do not count.
		insertFilter(t, db, rewindEVMChainID, logpoller.FilterName("other-verifier", rewindOnRamp.Hex()))
		insertFilter(t, db, rewindOtherChainID, filterName)
		insertBlocks(t, db, rewindEVMChainID, 100, 200)

		require.NoError(t, runSetFinalizedHeight(t, db, rewindEVMSelector, 150))

		row := storedRow(t, db, rewindEVMSelector)
		assert.Equal(t, "150", row.Height)
		assert.False(t, row.Disabled)
		assert.Equal(t, int64(101), lpBlocks(t, db, rewindEVMChainID).Count)
	})

	t.Run("non-EVM chain sets height only", func(t *testing.T) {
		resetRewindDB(t, db, true, 200)
		insertFilter(t, db, rewindEVMChainID, filterName)
		insertBlocks(t, db, rewindEVMChainID, 100, 200)

		require.NoError(t, runSetFinalizedHeight(t, db, rewindNonEVMSelector, 150))

		row := storedRow(t, db, rewindNonEVMSelector)
		assert.Equal(t, "150", row.Height)
		assert.False(t, row.Disabled)
		assert.Equal(t, int64(101), lpBlocks(t, db, rewindEVMChainID).Count)
	})

	t.Run("height out of int64 range fails and changes nothing", func(t *testing.T) {
		resetRewindDB(t, db, true, 200)
		insertFilter(t, db, rewindEVMChainID, filterName)
		insertBlocks(t, db, rewindEVMChainID, 100, 200)

		for _, h := range []string{strconv.FormatInt(math.MaxInt64, 10), strconv.FormatUint(math.MaxInt64+1, 10)} {
			err := runSetFinalizedHeightWithStore(t, chainstatus.NewPostgresChainStatusStore(db, logger.Test(t)), rewindEVMSelector, h)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "out of range")
		}

		row := storedRow(t, db, rewindEVMSelector)
		assert.Equal(t, "200", row.Height)
		assert.False(t, row.Disabled)
		assert.Equal(t, int64(101), lpBlocks(t, db, rewindEVMChainID).Count)
	})

	t.Run("missing status row returns error and changes nothing", func(t *testing.T) {
		resetRewindDB(t, db, true, 200)
		_, err := db.Exec(`DELETE FROM ccv_chain_statuses`)
		require.NoError(t, err)
		insertFilter(t, db, rewindEVMChainID, filterName)
		insertBlocks(t, db, rewindEVMChainID, 100, 200)

		err = runSetFinalizedHeight(t, db, rewindEVMSelector, 150)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no row found")
		assert.Equal(t, int64(101), lpBlocks(t, db, rewindEVMChainID).Count)
		assert.Equal(t, int64(101), lpLogs(t, db, rewindEVMChainID).Count)
	})

	t.Run("failure after the rewind rolls back height, disable and delete", func(t *testing.T) {
		resetRewindDB(t, db, true, 200)
		insertFilter(t, db, rewindEVMChainID, filterName)
		insertBlocks(t, db, rewindEVMChainID, 100, 200)
		lggr := logger.Test(t)
		store := chainstatus.NewPostgresChainStatusStore(db, lggr)
		// Height 99 is below the lowest stored block, so the rewind deletes, sets the height and disables.
		target := rewindTarget(t, db, rewindTestVerifierID, 99)

		err := store.SetFinalizedBlockHeightWith(t.Context(), rewindEVMSelector, rewindTestVerifierID, big.NewInt(99),
			func(ctx context.Context, tx sqlutil.DataSource, txStore *chainstatus.PostgresChainStatusStore) error {
				msg, err := target.rewind(ctx, tx, txStore, lggr)
				require.NoError(t, err)
				require.Contains(t, msg, "chainlink blocks replay")
				return assert.AnError
			})
		require.ErrorIs(t, err, assert.AnError)

		row := storedRow(t, db, rewindEVMSelector)
		assert.Equal(t, "200", row.Height)
		assert.False(t, row.Disabled)
		assert.Equal(t, int64(101), lpBlocks(t, db, rewindEVMChainID).Count)
		assert.Equal(t, int64(101), lpLogs(t, db, rewindEVMChainID).Count)
	})
}

func TestLogPollerRewind_messages(t *testing.T) {
	db := newRewindTestDB(t)
	lggr := logger.Test(t)
	filterName := logpoller.FilterName(rewindTestVerifierID, rewindOnRamp.Hex())

	resetRewindDB(t, db, false, 0)
	msg, err := rewindTarget(t, db, rewindTestVerifierID, 150).rewind(t.Context(), db, chainstatus.NewPostgresChainStatusStore(db, lggr), lggr)
	require.NoError(t, err)
	assert.Contains(t, msg, "not in use")

	resetRewindDB(t, db, true, 0)
	insertFilter(t, db, rewindEVMChainID, filterName)
	insertBlocks(t, db, rewindEVMChainID, 100, 200)
	msg, err = rewindTarget(t, db, rewindTestVerifierID, 250).rewind(t.Context(), db, chainstatus.NewPostgresChainStatusStore(db, lggr), lggr)
	require.NoError(t, err)
	assert.Contains(t, msg, "nothing to rewind")

	msg, err = rewindTarget(t, db, rewindTestVerifierID, 150).rewind(t.Context(), db, chainstatus.NewPostgresChainStatusStore(db, lggr), lggr)
	require.NoError(t, err)
	assert.Contains(t, msg, "verifier resumes at block 151")

	msg, err = rewindTarget(t, db, rewindTestVerifierID, 49).rewind(t.Context(), db, chainstatus.NewPostgresChainStatusStore(db, lggr), lggr)
	require.NoError(t, err)
	chainID := strconv.FormatInt(rewindEVMChainID, 10)
	assert.Contains(t, msg, "lowest stored: 100")
	assert.Contains(t, msg, "chainlink blocks replay --family evm --chain-id "+chainID+" --block-number 50")
	assert.Contains(t, msg, "chain ID "+chainID)
	assert.Contains(t, msg, "ccv chain-statuses enable --chain-selector "+strconv.FormatUint(uint64(rewindEVMSelector), 10)+" --verifier-id "+rewindTestVerifierID)
	assert.Contains(t, msg, "30 days")
	assert.Contains(t, msg, "above the chain's latest block")

	msg, err = rewindTarget(t, db, rewindTestVerifierID, 10).rewind(t.Context(), db, chainstatus.NewPostgresChainStatusStore(db, lggr), lggr)
	require.NoError(t, err)
	assert.Contains(t, msg, "lowest stored: none")
	assert.Contains(t, msg, "--block-number 11")
}

func TestLogPollerInUse_filter_shape(t *testing.T) {
	db := newRewindTestDB(t)
	chainID := big.NewInt(rewindEVMChainID)
	addr := rewindOnRamp.Hex()

	inUse := func(t *testing.T, verifierID string) bool {
		t.Helper()
		ok, err := logPollerInUse(t.Context(), db, logpoller.NewORM(chainID, db, logger.Test(t)), verifierID)
		require.NoError(t, err)
		return ok
	}

	t.Run("tables absent", func(t *testing.T) {
		resetRewindDB(t, db, false, 0)
		assert.False(t, inUse(t, "a"))
	})

	t.Run("FilterName with an address matches", func(t *testing.T) {
		resetRewindDB(t, db, true, 0)
		// The source reader registers its filter as logpoller.FilterName(verifierID, onRampAddress.Hex()).
		insertFilter(t, db, rewindEVMChainID, logpoller.FilterName("a", addr))
		assert.True(t, inUse(t, "a"))
	})

	t.Run("filter of another verifier does not match", func(t *testing.T) {
		resetRewindDB(t, db, true, 0)
		insertFilter(t, db, rewindEVMChainID, logpoller.FilterName("b", addr))
		assert.False(t, inUse(t, "a"))
	})

	t.Run("names without the verifier prefix do not match", func(t *testing.T) {
		resetRewindDB(t, db, true, 0)
		for _, name := range []string{
			"a",
			"a-" + addr,
			"xa - " + addr,
		} {
			insertFilter(t, db, rewindEVMChainID, name)
		}
		assert.False(t, inUse(t, "a"))
	})

	t.Run("filter on another chain does not match", func(t *testing.T) {
		resetRewindDB(t, db, true, 0)
		insertFilter(t, db, rewindOtherChainID, logpoller.FilterName("a", addr))
		assert.False(t, inUse(t, "a"))
	})

	t.Run("verifier ID with LIKE or regex characters is matched literally", func(t *testing.T) {
		resetRewindDB(t, db, true, 0)
		insertFilter(t, db, rewindEVMChainID, logpoller.FilterName("x.y", addr))
		assert.False(t, inUse(t, "x%"))
		assert.False(t, inUse(t, "x_y"))
		assert.True(t, inUse(t, "x.y"))
	})
}

func TestNewLogPollerRewindTarget_gates(t *testing.T) {
	// No query is run here, so a store without a database is enough.
	store := chainstatus.NewPostgresChainStatusStore(nil, logger.Test(t))

	target, reason, err := newLogPollerRewindTarget(store, rewindNonEVMSelector, rewindTestVerifierID, big.NewInt(1))
	require.NoError(t, err)
	assert.Nil(t, target)
	assert.Contains(t, reason, "not EVM")

	target, reason, err = newLogPollerRewindTarget(store, protocol.ChainSelector(789), rewindTestVerifierID, big.NewInt(1))
	require.NoError(t, err)
	assert.Nil(t, target)
	assert.Contains(t, reason, "unknown")

	target, reason, err = newLogPollerRewindTarget(mocks.NewMockChainStatusStore(t), rewindEVMSelector, rewindTestVerifierID, big.NewInt(1))
	require.NoError(t, err)
	assert.Nil(t, target)
	assert.Contains(t, reason, "same transaction")

	for _, h := range []*big.Int{
		big.NewInt(math.MaxInt64),
		new(big.Int).Add(big.NewInt(math.MaxInt64), big.NewInt(1)),
		nil,
	} {
		_, _, err = newLogPollerRewindTarget(store, rewindEVMSelector, rewindTestVerifierID, h)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "out of range")
	}

	target, reason, err = newLogPollerRewindTarget(store, rewindEVMSelector, rewindTestVerifierID, big.NewInt(1))
	require.NoError(t, err)
	assert.Empty(t, reason)
	require.NotNil(t, target)
	assert.Equal(t, big.NewInt(rewindEVMChainID), target.chainID)
	assert.Equal(t, int64(1), target.height)
}

func TestSetFinalizedHeight_out_of_range_height_fails_before_any_query(t *testing.T) {
	// The store has no database, so any query would panic; the range check must fail first.
	store := chainstatus.NewPostgresChainStatusStore(nil, logger.Test(t))
	err := runSetFinalizedHeightWithStore(t, store, rewindEVMSelector, strconv.FormatInt(math.MaxInt64, 10))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out of range")
}

func TestLogPollerFilterPrefix_matches_source_reader_filter_name(t *testing.T) {
	onRamp := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	name := logpoller.FilterName(rewindTestVerifierID, onRamp.Hex())
	prefix := logPollerFilterPrefix(rewindTestVerifierID)
	assert.Equal(t, rewindTestVerifierID+" - ", prefix)
	assert.Equal(t, prefix+onRamp.Hex(), name)
	assert.Len(t, name[len(prefix):], 42)
}
