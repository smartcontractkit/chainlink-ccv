package chainstatuses

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"

	chainselectors "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/chainstatus"
)

// finalizedHeightTransactor is implemented by stores that can run extra work in the same transaction as the
// finalized height update. It is optional so ChainStatusStore, which the Chainlink node also satisfies, stays unchanged.
type finalizedHeightTransactor interface {
	SetFinalizedBlockHeightWith(
		ctx context.Context,
		chainSelector protocol.ChainSelector,
		verifierID string,
		height *big.Int,
		also func(ctx context.Context, tx sqlutil.DataSource, txStore *chainstatus.PostgresChainStatusStore) error,
	) error
}

// The CCV store must keep satisfying the optional interface, or the rewind would silently stop running.
var _ finalizedHeightTransactor = (*chainstatus.PostgresChainStatusStore)(nil)

// logPollerRewindTarget holds what a LogPoller rewind needs once the chain and store have passed the gates.
type logPollerRewindTarget struct {
	store         finalizedHeightTransactor
	chainSelector protocol.ChainSelector
	chainID       *big.Int
	verifierID    string
	height        int64
}

// newLogPollerRewindTarget decides whether set-finalized-height can try a LogPoller rewind for the chain.
// When err is nil, exactly one of target and skipReason is set: a target to run the rewind with, or a reason
// for the operator when it cannot run, in which case the caller sets the height the plain way. The height is
// range-checked here, before any query, because the LogPoller stores block numbers as int64 and the rewind
// deletes from height+1.
func newLogPollerRewindTarget(store ChainStatusStore, chainSelector protocol.ChainSelector, verifierID string, height *big.Int) (target *logPollerRewindTarget, skipReason string, err error) {
	family, err := chainselectors.GetSelectorFamily(uint64(chainSelector))
	if err != nil {
		return nil, "LogPoller rewind skipped: chain family is unknown for this chain selector.", nil
	}
	if family != chainselectors.FamilyEVM {
		return nil, fmt.Sprintf("LogPoller rewind skipped: chain family %q is not EVM.", family), nil
	}
	transactor, ok := store.(finalizedHeightTransactor)
	if !ok {
		return nil, "LogPoller rewind skipped: the chain status store cannot run it in the same transaction.", nil
	}
	if height == nil || !height.IsInt64() || height.Int64() == math.MaxInt64 {
		return nil, "", fmt.Errorf("block height %s is out of range for the LogPoller; nothing was changed", height)
	}
	chainIDStr, err := chainselectors.GetChainIDFromSelector(uint64(chainSelector))
	if err != nil {
		return nil, "", fmt.Errorf("failed to get chain ID for chain selector %d: %w", chainSelector, err)
	}
	chainID, ok := new(big.Int).SetString(chainIDStr, 10)
	if !ok {
		return nil, "", fmt.Errorf("invalid EVM chain ID %q for chain selector %d", chainIDStr, chainSelector)
	}
	return &logPollerRewindTarget{
		store:         transactor,
		chainSelector: chainSelector,
		chainID:       chainID,
		verifierID:    verifierID,
		height:        height.Int64(),
	}, "", nil
}

// logPollerFilterPrefix is the part of the source reader's filter name before the on-ramp address,
// which it builds with logpoller.FilterName(verifierID, onRampAddress.Hex()).
func logPollerFilterPrefix(verifierID string) string {
	return logpoller.FilterName(verifierID, "")
}

// logPollerInUse reports whether this verifier has a LogPoller filter on the chain, which the source reader only
// registers when it is backed by the LogPoller. It matches on the "<verifierID> - " prefix because the CLI does not
// know the on-ramp address, and a node runs a single CCV verifier. to_regclass comes first because standalone CCV
// has no LogPoller tables, and querying a missing table would abort the transaction.
func logPollerInUse(ctx context.Context, tx sqlutil.DataSource, orm *logpoller.DSORM, verifierID string) (bool, error) {
	var tableExists bool
	if err := tx.GetContext(ctx, &tableExists, `SELECT to_regclass('evm.log_poller_filters') IS NOT NULL`); err != nil {
		return false, fmt.Errorf("failed to check for LogPoller filters table: %w", err)
	}
	if !tableExists {
		return false, nil
	}
	filters, err := orm.LoadFilters(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to load LogPoller filters for verifier %s: %w", verifierID, err)
	}
	prefix := logPollerFilterPrefix(verifierID)
	for name := range filters {
		if strings.HasPrefix(name, prefix) {
			return true, nil
		}
	}
	return false, nil
}

// lpBlockRange returns the oldest and latest blocks the LogPoller has stored for the chain.
// Both are nil when it has stored none.
func lpBlockRange(ctx context.Context, orm *logpoller.DSORM) (oldest, latest *logpoller.Block, err error) {
	oldest, err = orm.SelectOldestBlock(ctx, 0)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read the oldest LogPoller block: %w", err)
	}
	latest, err = orm.SelectLatestBlock(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read the latest LogPoller block: %w", err)
	}
	return oldest, latest, nil
}

// rewind deletes the LogPoller's blocks and logs from height+1 on, so on restart it resumes after its newest
// remaining block. The source reader resumes at height+1. Stored blocks are sparse (backfill saves only the end
// block of each batch), so the LogPoller may resume earlier than height+1; re-reading those blocks is harmless
// because log inserts are idempotent.
// It runs inside the chain status transaction and returns a message for the operator. An error rolls back the
// height update as well.
func (t *logPollerRewindTarget) rewind(ctx context.Context, tx sqlutil.DataSource, txStore *chainstatus.PostgresChainStatusStore, lggr logger.Logger) (string, error) {
	orm := logpoller.NewORM(t.chainID, tx, lggr)
	inUse, err := logPollerInUse(ctx, tx, orm, t.verifierID)
	if err != nil {
		return "", err
	}
	if !inUse {
		return "LogPoller rewind skipped: the LogPoller is not in use for this verifier on this chain.", nil
	}

	oldest, latest, err := lpBlockRange(ctx, orm)
	if err != nil {
		return "", err
	}
	start := t.height + 1
	// Without a stored block at or below the height, the LogPoller treats the chain as new and starts at the
	// current finalized block, which would skip every block between the height and that point.
	needsReplay := oldest == nil || oldest.BlockNumber > t.height
	if !needsReplay && latest.BlockNumber <= t.height {
		return fmt.Sprintf("LogPoller has no blocks after %d; nothing to rewind.", t.height), nil
	}

	// Blocks and logs above the height are removed in both cases so no stale LogPoller data survives the rewind.
	// Logged as well as printed because the delete is chain-wide and stdout is easily lost.
	logFields := []any{
		"chainSelector", t.chainSelector, "chainID", t.chainID, "verifierID", t.verifierID,
		"deleteFromBlock", start, "needsReplay", needsReplay,
	}
	if latest != nil {
		logFields = append(logFields, "highestStoredBlock", latest.BlockNumber)
	}
	lggr.Infow("Rewinding LogPoller for set-finalized-height", logFields...)
	if err := orm.DeleteLogsAndBlocksAfter(ctx, start); err != nil {
		return "", fmt.Errorf("failed to delete LogPoller blocks and logs from block %d: %w", start, err)
	}
	if !needsReplay {
		return fmt.Sprintf("LogPoller rewound: deleted its stored blocks and logs from block %d onward (highest stored block was %d). They are fetched again on the next start, so the verifier resumes at block %d.",
			start, latest.BlockNumber, start), nil
	}

	// A replay only runs on a live node and is asynchronous. Keeping the chain disabled until the operator
	// re-enables it after the replay stops the verifier from reading the gap before it is refilled.
	if err := txStore.SetDisabled(ctx, t.chainSelector, t.verifierID, true); err != nil {
		return "", fmt.Errorf("failed to disable the chain pending a LogPoller replay: %w", err)
	}
	lggr.Infow("Disabled chain pending a LogPoller replay", "chainSelector", t.chainSelector, "verifierID", t.verifierID,
		"replayFromBlock", start)
	return t.replayRunbook(oldest), nil
}

// replayRunbook tells the operator how to refill the LogPoller gap with the node's own replay and then resume.
// oldest is the LogPoller's oldest stored block, nil when it has none.
func (t *logPollerRewindTarget) replayRunbook(oldest *logpoller.Block) string {
	start := t.height + 1
	lowest := "none"
	if oldest != nil {
		lowest = strconv.FormatInt(oldest.BlockNumber, 10)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "LogPoller has no stored block at or below %d (lowest stored: %s), so it cannot resume at block %d by itself.\n", t.height, lowest, start)
	fmt.Fprintf(&b, "Deleted its stored blocks and logs from block %d onward and disabled the chain for verifier %s until the gap is refilled.\n", start, t.verifierID)
	b.WriteString("To refill the gap and resume:\n")
	fmt.Fprintf(&b, "  1. Start the node and wait for the LogPoller's first poll on chain ID %s.\n", t.chainID)
	fmt.Fprintf(&b, "  2. Run: chainlink blocks replay --family evm --chain-id %s --block-number %d\n", t.chainID, start)
	b.WriteString("     If it reports that there are no saved blocks yet, wait for the next poll and run it again.\n")
	fmt.Fprintf(&b, "     If it rejects block %d as above the chain's latest block, there is no gap to refill; skip to step 4.\n", start)
	b.WriteString("  3. Wait for the node logs to show that the replay has finished.\n")
	b.WriteString("  4. Stop the node.\n")
	fmt.Fprintf(&b, "  5. Run: chainlink node ccv chain-statuses enable --chain-selector %d --verifier-id %s\n", t.chainSelector, t.verifierID)
	b.WriteString("  6. Start the node.\n")
	b.WriteString("Logs older than the source reader's filter retention (30 days) may be pruned again before the verifier reads them.")
	return b.String()
}
