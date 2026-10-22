package evm

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"
	evmtypes "github.com/smartcontractkit/chainlink-evm/pkg/types"

	evmdb "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm/db"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
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

	require.NoError(t, RemoveBlocksFrom(t.Context(), db, logger.Test(t), chainA, 100))
	require.Equal(t, rowCounts{Blocks: 3, Logs: 3}, operatorRowCounts(t, db, chainA), "a start above the highest block deletes nothing")
}

func TestCheckLogPollerSchema(t *testing.T) {
	db := testutil.NewTestDB(t).DB
	require.NoError(t, CheckLogPollerSchema(t.Context(), db))

	_, err := db.ExecContext(t.Context(), `DROP SCHEMA evm CASCADE`)
	require.NoError(t, err)
	err = CheckLogPollerSchema(t.Context(), db)
	require.ErrorContains(t, err, "evm.log_poller_blocks")
	require.ErrorContains(t, err, "migration")
}

// forkedClient answers HeadByHash from a set of hashes the chain still has.
type forkedClient struct {
	logpoller.Client
	onChain map[common.Hash]int64
	err     error
}

func (c forkedClient) HeadByHash(_ context.Context, hash common.Hash) (*evmtypes.Head, error) {
	if c.err != nil {
		return nil, c.err
	}
	n, ok := c.onChain[hash]
	if !ok {
		return nil, ethereum.NotFound
	}
	return &evmtypes.Head{Hash: hash, Number: n}, nil
}

func chainThrough(n int64) map[common.Hash]int64 {
	onChain := make(map[common.Hash]int64)
	for i := int64(1); i <= n; i++ {
		onChain[common.BigToHash(big.NewInt(i))] = i
	}
	return onChain
}

func TestFindLCA(t *testing.T) {
	chainID := big.NewInt(920_010)

	t.Run("highest stored block the chain still has", func(t *testing.T) {
		db := testutil.NewTestDB(t).DB
		seedOperatorChain(t, db, chainID, 10)

		lca, err := findLCA(t.Context(), db, chainID, forkedClient{onChain: chainThrough(6)}, logger.Test(t))
		require.NoError(t, err)
		require.Equal(t, LCA{ChainID: "920010", BlockHash: common.BigToHash(big.NewInt(6)).Hex(), BlockNumber: 6}, lca)
		require.Equal(t, rowCounts{Blocks: 10, Logs: 10}, operatorRowCounts(t, db, chainID), "find-lca only reads")
	})

	t.Run("the whole stored chain is on the RPC", func(t *testing.T) {
		db := testutil.NewTestDB(t).DB
		seedOperatorChain(t, db, chainID, 5)

		lca, err := findLCA(t.Context(), db, chainID, forkedClient{onChain: chainThrough(5)}, logger.Test(t))
		require.NoError(t, err)
		require.Equal(t, int64(5), lca.BlockNumber)
	})

	t.Run("no stored block matches", func(t *testing.T) {
		db := testutil.NewTestDB(t).DB
		seedOperatorChain(t, db, chainID, 4)

		_, err := findLCA(t.Context(), db, chainID, forkedClient{onChain: map[common.Hash]int64{}}, logger.Test(t))
		require.ErrorContains(t, err, "failed to find LCA")
	})

	t.Run("no stored blocks", func(t *testing.T) {
		db := testutil.NewTestDB(t).DB

		_, err := findLCA(t.Context(), db, chainID, forkedClient{onChain: chainThrough(5)}, logger.Test(t))
		require.ErrorContains(t, err, "failed to find lca")
	})

	t.Run("RPC failure", func(t *testing.T) {
		db := testutil.NewTestDB(t).DB
		seedOperatorChain(t, db, chainID, 4)

		_, err := findLCA(t.Context(), db, chainID, forkedClient{err: errors.New("rpc down")}, logger.Test(t))
		require.ErrorContains(t, err, "rpc down")
	})
}

func TestSelectorFromChainID(t *testing.T) {
	t.Parallel()

	selector, err := SelectorFromChainID(11155111)
	require.NoError(t, err)
	require.Equal(t, protocol.ChainSelector(chainsel.ETHEREUM_TESTNET_SEPOLIA.Selector), selector)

	_, err = SelectorFromChainID(4242424242)
	require.ErrorContains(t, err, "4242424242")
	require.ErrorContains(t, err, "not a known EVM chain")
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
	require.True(t, strings.HasPrefix(lca.BlockHash, "0x"))
	server.CloseClientConnections()
}

func TestFindLCAReportsAnUnreachableRPC(t *testing.T) {
	db := testutil.NewTestDB(t).DB
	seedOperatorChain(t, db, big.NewInt(1337), 3)
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	_, err := FindLCA(ctx, db, Info{ChainID: "1337", Nodes: []Node{{HTTPUrl: dead.URL}}}, logger.Test(t))
	require.Error(t, err)
}
