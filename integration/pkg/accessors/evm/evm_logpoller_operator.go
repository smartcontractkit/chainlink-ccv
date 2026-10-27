package evm

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"time"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/logpoller"

	evmdb "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm/db"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// The operator's view of the LogPoller's stored chain: where it still agrees with the RPC, and
// removing what it stored after that. These are the only callers of the ORM's delete and of FindLCA,
// and only the CLI calls them, so the running verifier never deletes.

// lcaPollPeriod only scales the latency monitor's slow-call warning. FindLCA never polls, and a zero
// period would make every RPC call look slow.
const lcaPollPeriod = 10 * time.Second

// LCA is the highest stored block whose hash the chain RPC also has.
type LCA struct {
	ChainID     string
	BlockHash   string
	BlockNumber int64
}

// SelectorFromChainID is the chain selector of a known EVM chain, which is how the standalone config
// names it.
func SelectorFromChainID(chainID int64) (protocol.ChainSelector, error) {
	details, err := chainsel.GetChainDetailsByChainIDAndFamily(strconv.FormatInt(chainID, 10), chainsel.FamilyEVM)
	if err != nil {
		return 0, fmt.Errorf("EVM chain ID %d is not a known EVM chain: %w", chainID, err)
	}
	return protocol.ChainSelector(details.ChainSelector), nil
}

// CheckLogPollerSchema fails with a clear message when the LogPoller tables are missing, which is the
// case before a verifier with the LogPoller enabled has started on the database.
func CheckLogPollerSchema(ctx context.Context, db *sql.DB) error {
	exists, err := logPollerSchemaExists(ctx, db)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("the LogPoller schema is missing (evm.log_poller_blocks or evm.logs): the EVM accessor migration creates it when a verifier with the LogPoller enabled starts")
	}
	var lease sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('evm.lease_lock')::text`).Scan(&lease); err != nil {
		return fmt.Errorf("failed to check for the lease table: %w", err)
	}
	// Without it, an older verifier that takes no lease may be writing: refuse rather than delete unguarded.
	if !lease.Valid {
		return errors.New("the lease table evm.lease_lock is missing: start a verifier on this version once so it migrates the EVM database")
	}
	return nil
}

func logPollerSchemaExists(ctx context.Context, db *sql.DB) (bool, error) {
	var blocks, logs sql.NullString
	if err := db.QueryRowContext(ctx,
		`SELECT to_regclass('evm.log_poller_blocks')::text, to_regclass('evm.logs')::text`).Scan(&blocks, &logs); err != nil {
		return false, fmt.Errorf("failed to check for the LogPoller schema: %w", err)
	}
	return blocks.Valid && logs.Valid, nil
}

// FindLCA finds the highest block stored for the chain whose hash the chain RPC also has. It builds
// the chain's client and closes it. It only reads, so it is safe with the verifier running.
func FindLCA(ctx context.Context, db *sql.DB, info Info, lggr logger.Logger) (LCA, error) {
	chainID, ok := new(big.Int).SetString(info.ChainID, 10)
	if !ok {
		return LCA{}, fmt.Errorf("EVM chain ID %q is not a number", info.ChainID)
	}
	chainClient, err := CreateMultiNodeClientFromInfo(ctx, info, lggr)
	if err != nil {
		return LCA{}, err
	}
	defer chainClient.Close()
	return findLCA(ctx, db, chainID, chainClient, lggr)
}

// findLCA runs the LogPoller's own search with a LogPoller that is never started: FindLCA needs only
// the ORM and the client, so there is no head tracker and nothing to stop. The ORM wraps the borrowed
// database, which is never closed.
func findLCA(ctx context.Context, db *sql.DB, chainID *big.Int, chainClient logpoller.Client, lggr logger.Logger) (LCA, error) {
	orm := logpoller.NewORM(chainID, evmdb.NewLogPollerDB(db), lggr)
	lp := logpoller.NewLogPoller(orm, chainClient, lggr, nil, logpoller.Opts{PollPeriod: lcaPollPeriod})
	block, err := lp.FindLCA(ctx)
	if err != nil {
		return LCA{}, fmt.Errorf("failed to find lca: %w", err)
	}
	return LCA{ChainID: chainID.String(), BlockHash: block.BlockHash.Hex(), BlockNumber: block.BlockNumber}, nil
}

// RemoveBlocksFrom deletes the chain's stored blocks and logs from start up, start included. Like the
// node's remove-blocks it first waits for the EVM database lease, so it never runs beside a verifier.
// Losing the lease mid-delete exits the process, as the node's command does.
func RemoveBlocksFrom(ctx context.Context, db *sql.DB, lggr logger.Logger, chainID *big.Int, start int64) error {
	lease := evmdb.NewLease(db, lggr)
	if err := lease.TakeAndHold(ctx, func(error) {
		logger.Sugared(lggr).Infow("Waiting for the running verifier to release the EVM database lease; stop the verifier to continue",
			"evmChainID", chainID.String())
	}); err != nil {
		return err
	}
	defer lease.Release()

	orm := logpoller.NewORM(chainID, evmdb.NewLogPollerDB(db), lggr)
	if err := orm.DeleteLogsAndBlocksAfter(ctx, start); err != nil {
		return fmt.Errorf("failed to delete log poller data after block %d for chain ID %s: %w", start, chainID, err)
	}
	return nil
}
