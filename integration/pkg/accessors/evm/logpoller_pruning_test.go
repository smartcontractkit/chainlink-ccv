package evm

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"
	evmtypes "github.com/smartcontractkit/chainlink-evm/pkg/types"

	evmdb "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm/db"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evmconfig"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
)

const (
	pruneChainID     = 910_201
	unconfiguredID   = 910_202
	pruneKeepDepth   = 5
	pruneRetention   = time.Second
	pruneBlockCount  = 30
	pruneFinalizedAt = 25
)

// The log poller prunes its own rows: expired logs by filter retention and old blocks by
// LogKeepBlocksDepth. The background schedule starts at least five minutes after start, so the prune
// entry points are called directly; the schedule itself is covered by chainlink-evm.
func TestLogPollerPrunesItsOwnRows(t *testing.T) {
	testDB := testutil.NewTestDB(t)
	handle := evmdb.NewLogPollerDB(testDB.DB)
	ctx := t.Context()
	onRamp := common.HexToAddress("0x1234")
	topic := common.HexToHash("0x01")

	seed := func(chainID int64, withFilter bool) *logpoller.DSORM {
		orm := logpoller.NewORM(big.NewInt(chainID), handle, logger.Test(t))
		if withFilter {
			require.NoError(t, orm.InsertFilter(ctx, logpoller.Filter{
				Name:      verifierFilterName("verifier-1", onRamp),
				Addresses: evmtypes.AddressArray{onRamp},
				EventSigs: evmtypes.HashArray{topic},
				Retention: pruneRetention,
			}))
		}
		now := time.Now()
		for n := int64(1); n <= pruneBlockCount; n++ {
			finalized := int64(pruneFinalizedAt)
			require.NoError(t, orm.InsertBlock(ctx, common.BigToHash(big.NewInt(n)), n, now, finalized, finalized))
		}
		require.NoError(t, orm.InsertLogs(ctx, []logpoller.Log{
			seedLog(chainID, 1, onRamp, topic, now.Add(-time.Hour)), // past the filter's retention
			seedLog(chainID, 2, onRamp, topic, now.Add(-time.Hour)),
			seedLog(chainID, 3, onRamp, topic, now), // inside it
		}))
		return orm
	}
	count := func(table string, chainID int64) int {
		var n int
		require.NoError(t, testDB.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM evm."+table+" WHERE evm_chain_id = $1", chainID).Scan(&n))
		return n
	}

	orm := seed(pruneChainID, true)
	seed(unconfiguredID, false) // a chain no longer configured: no log poller runs for it

	lp := newPruningLogPoller(t, orm)
	require.Equal(t, 3, count("logs", pruneChainID))
	require.Equal(t, pruneBlockCount, count("log_poller_blocks", pruneChainID))

	_, err := lp.(interface {
		PruneExpiredLogs(context.Context) (bool, error)
	}).PruneExpiredLogs(ctx)
	require.NoError(t, err)
	_, err = lp.(logpoller.LogPollerTest).PruneOldBlocks(ctx)
	require.NoError(t, err)

	require.Equal(t, 1, count("logs", pruneChainID), "only the log inside its retention stays")
	// Blocks up to and including finalized - depth are removed: 25 - 5 = 20, so 21..30 stay.
	require.Equal(t, pruneBlockCount-(pruneFinalizedAt-pruneKeepDepth), count("log_poller_blocks", pruneChainID))

	require.Equal(t, 3, count("logs", unconfiguredID), "nothing prunes a chain that has no running log poller")
	require.Equal(t, pruneBlockCount, count("log_poller_blocks", unconfiguredID))
}

// newPruningLogPoller is never started: the test calls the prune entry points itself.
func newPruningLogPoller(t *testing.T, orm logpoller.ORM) logpoller.LogPoller {
	t.Helper()
	chainID := big.NewInt(pruneChainID)
	cfg, err := newChainlinkEVMConfig(evmconfig.Info{
		ChainID: chainID.String(),
		Nodes:   []evmconfig.Node{{HTTPUrl: "http://127.0.0.1:1"}},
	})
	require.NoError(t, err)
	opts, err := standaloneLogPollerOpts(logPollerInputs{chainID: chainID, config: cfg.EVM()})
	require.NoError(t, err)

	opts.KeepFinalizedBlocksDepth = pruneKeepDepth
	opts.LogPrunePageSize = 0
	events := &eventLog{}
	return logpoller.NewLogPoller(orm, &fakeChainClient{events: events}, logger.Test(t), &fakeHeadTracker{events: events}, opts)
}

func seedLog(chainID, index int64, address common.Address, topic common.Hash, at time.Time) logpoller.Log {
	return logpoller.Log{
		EVMChainID:     sqlutil.New(big.NewInt(chainID)),
		LogIndex:       index,
		BlockHash:      common.BigToHash(big.NewInt(index)),
		BlockNumber:    index,
		BlockTimestamp: at,
		Topics:         [][]byte{topic.Bytes()},
		EventSig:       topic,
		Address:        address,
		TxHash:         common.BigToHash(big.NewInt(100 + index)),
		Data:           []byte{},
	}
}
