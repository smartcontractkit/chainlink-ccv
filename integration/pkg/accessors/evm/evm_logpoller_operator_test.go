package evm

import (
	"context"
	"database/sql"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"

	evmdb "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm/db"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
)

var operatorTestEvent = common.HexToHash("0x00000000000000000000000000000000000000000000000000000000000000e1")

func operatorTestBlock(chainID *big.Int, number int64) logpoller.Block {
	return logpoller.Block{
		EVMChainID:     sqlutil.New(chainID),
		BlockHash:      common.BigToHash(big.NewInt(number)),
		BlockNumber:    number,
		BlockTimestamp: time.Now().UTC(),
	}
}

func operatorTestLog(chainID *big.Int, block int64) logpoller.Log {
	return logpoller.Log{
		EVMChainID:     sqlutil.New(chainID),
		LogIndex:       0,
		BlockHash:      common.BigToHash(big.NewInt(block)),
		BlockNumber:    block,
		BlockTimestamp: time.Now().UTC(),
		Topics:         [][]byte{operatorTestEvent.Bytes()},
		EventSig:       operatorTestEvent,
		Address:        common.HexToAddress("0xa1"),
		TxHash:         common.BigToHash(big.NewInt(block * 1000)),
		Data:           []byte{0x01},
	}
}

// seedOperatorChain stores blocks 1..n and one log per block for the chain.
func seedOperatorChain(t *testing.T, db *sql.DB, chainID *big.Int, n int64) {
	t.Helper()
	orm := logpoller.NewORM(chainID, evmdb.NewLogPollerDB(db), logger.Test(t))
	var blocks []logpoller.Block
	var logs []logpoller.Log
	for i := int64(1); i <= n; i++ {
		blocks = append(blocks, operatorTestBlock(chainID, i))
		logs = append(logs, operatorTestLog(chainID, i))
	}
	require.NoError(t, orm.InsertLogsWithBlocks(t.Context(), logs, blocks))
}

// rowCounts is how many rows a chain has in each LogPoller table.
type rowCounts struct{ Blocks, Logs int64 }

func operatorRowCounts(t *testing.T, db *sql.DB, chainID *big.Int) rowCounts {
	t.Helper()
	var counts rowCounts
	require.NoError(t, db.QueryRowContext(t.Context(),
		`SELECT (SELECT COUNT(*) FROM evm.log_poller_blocks WHERE evm_chain_id = $1),
		        (SELECT COUNT(*) FROM evm.logs WHERE evm_chain_id = $1)`, sqlutil.New(chainID)).Scan(&counts.Blocks, &counts.Logs))
	return counts
}

func TestRemoveBlocksFromIsScopedByChainAndRangeAndInclusive(t *testing.T) {
	db := testutil.NewTestDB(t).DB
	chainA, chainB := big.NewInt(920_001), big.NewInt(920_002)
	seedOperatorChain(t, db, chainA, 6)
	seedOperatorChain(t, db, chainB, 6)

	require.NoError(t, RemoveBlocksFrom(t.Context(), db, logger.Test(t), chainA, 4))

	require.Equal(t, rowCounts{Blocks: 3, Logs: 3}, operatorRowCounts(t, db, chainA), "blocks 1 to 3 stay, 4 to 6 go")
	require.Equal(t, rowCounts{Blocks: 6, Logs: 6}, operatorRowCounts(t, db, chainB), "another chain is untouched")
}

func TestCheckLogPollerSchema(t *testing.T) {
	db := testutil.NewTestDB(t).DB
	require.NoError(t, CheckLogPollerSchema(t.Context(), db))

	_, err := db.ExecContext(t.Context(), `DROP TABLE evm.lease_lock`)
	require.NoError(t, err)
	err = CheckLogPollerSchema(t.Context(), db)
	require.ErrorContains(t, err, "evm.lease_lock")
	require.ErrorContains(t, err, "start a verifier on this version once")

	_, err = db.ExecContext(t.Context(), `DROP SCHEMA evm CASCADE`)
	require.NoError(t, err)
	err = CheckLogPollerSchema(t.Context(), db)
	require.ErrorContains(t, err, "evm.log_poller_blocks")
	require.ErrorContains(t, err, "migration")
}

func chainThrough(n int64) map[common.Hash]int64 {
	onChain := make(map[common.Hash]int64)
	for i := int64(1); i <= n; i++ {
		onChain[common.BigToHash(big.NewInt(i))] = i
	}
	return onChain
}

// fakeRPC serves a chain whose blocks are the given hashes, which is all FindLCA needs of it.
func fakeRPC(t *testing.T, onChain map[common.Hash]int64, chainIDHex string) *httptest.Server {
	t.Helper()
	header := func(hash common.Hash, number int64) map[string]any {
		return map[string]any{
			"hash":       hash.Hex(),
			"number":     "0x" + big.NewInt(number).Text(16),
			"parentHash": common.Hash{}.Hex(),
			"timestamp":  "0x1",
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var result any
		switch req.Method {
		case "eth_chainId":
			result = chainIDHex
		case "eth_blockNumber":
			result = "0x64"
		case "eth_getBlockByNumber":
			result = header(common.BigToHash(big.NewInt(100)), 100)
		case "eth_getBlockByHash":
			var hash common.Hash
			if err := json.Unmarshal(req.Params[0], &hash); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if n, ok := onChain[hash]; ok {
				result = header(hash, n)
			}
		default:
			http.Error(w, "unexpected RPC method: "+req.Method, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}))
	t.Cleanup(server.Close)
	return server
}

// FindLCA builds its own chain client and must close it, along with everything else it opened.
func TestFindLCABuildsAndClosesItsClient(t *testing.T) {
	// Not parallel: goleak sees every goroutine in the process.
	db := testutil.NewTestDB(t).DB
	chainID := big.NewInt(1337)
	seedOperatorChain(t, db, chainID, 8)
	server := fakeRPC(t, chainThrough(5), "0x539")
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	lca, err := FindLCA(ctx, db, Info{ChainID: "1337", Nodes: []Node{{HTTPUrl: server.URL}}}, logger.Test(t))
	require.NoError(t, err)
	require.Equal(t, int64(5), lca.BlockNumber)
	require.Equal(t, "1337", lca.ChainID)
	require.Equal(t, common.BigToHash(big.NewInt(5)).Hex(), lca.BlockHash)
	server.CloseClientConnections()
}

func TestRemoveBlocksFromWaitsForTheLease(t *testing.T) {
	db := testutil.NewTestDB(t).DB
	chainID := big.NewInt(920_020)
	seedOperatorChain(t, db, chainID, 10)

	verifier := evmdb.NewLease(db, logger.Test(t), evmdb.DefaultLeaseConfig())
	require.NoError(t, verifier.TakeAndHold(t.Context(), nil))

	done := make(chan error, 1)
	go func() { done <- RemoveBlocksFrom(t.Context(), db, logger.Test(t), chainID, 5) }()
	require.Never(t, func() bool { return len(done) > 0 }, time.Second, 50*time.Millisecond,
		"remove-blocks must not delete while the verifier holds the lease")
	require.Equal(t, rowCounts{Blocks: 10, Logs: 10}, operatorRowCounts(t, db, chainID))

	verifier.Release()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("remove-blocks did not run after the verifier released the lease")
	}
	require.Equal(t, rowCounts{Blocks: 4, Logs: 4}, operatorRowCounts(t, db, chainID))
}

func TestRemoveBlocksFromStopsWaitingWithTheContext(t *testing.T) {
	db := testutil.NewTestDB(t).DB
	chainID := big.NewInt(920_021)
	seedOperatorChain(t, db, chainID, 10)
	verifier := evmdb.NewLease(db, logger.Test(t), evmdb.DefaultLeaseConfig())
	require.NoError(t, verifier.TakeAndHold(t.Context(), nil))
	t.Cleanup(verifier.Release)

	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	err := RemoveBlocksFrom(ctx, db, logger.Test(t), chainID, 5)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.ErrorContains(t, err, "stopped waiting for the EVM database lease")
	require.Equal(t, rowCounts{Blocks: 10, Logs: 10}, operatorRowCounts(t, db, chainID), "nothing is deleted when the wait is cut short")
}
