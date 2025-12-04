package chainstatus

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"math/big"
	"strconv"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite" // pure Go sqlite driver (no CGO required)

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

//go:embed migrations/*.sql
var embedMigrations embed.FS

var _ protocol.ChainStatusManager = (*SQLiteChainStatusManager)(nil)

type SQLiteChainStatusManager struct {
	db   *sql.DB
	lggr logger.Logger
}

func NewSQLiteChainStatusManager(dbPath string, lggr logger.Logger) (*SQLiteChainStatusManager, error) {
	if dbPath == "" {
		return nil, fmt.Errorf("database path cannot be empty")
	}

	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	db.SetMaxOpenConns(1)

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to ping sqlite database: %w", err)
	}

	mgr := &SQLiteChainStatusManager{
		db:   db,
		lggr: logger.With(lggr, "component", "SQLiteChainStatusManager"),
	}

	if err := mgr.runMigrations(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	mgr.lggr.Infow("SQLite chain status manager initialized", "dbPath", dbPath)
	return mgr, nil
}

func (m *SQLiteChainStatusManager) runMigrations() error {
	goose.SetBaseFS(embedMigrations)

	if err := goose.SetDialect("sqlite"); err != nil {
		return fmt.Errorf("failed to set goose dialect: %w", err)
	}

	if err := goose.Up(m.db, "migrations"); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	return nil
}

func (m *SQLiteChainStatusManager) WriteChainStatuses(ctx context.Context, statuses []protocol.ChainStatusInfo) error {
	if len(statuses) == 0 {
		return nil
	}

	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Statement for full upsert (when block height is provided)
	fullStmt, err := tx.PrepareContext(ctx, `
		INSERT INTO chain_statuses (chain_selector, finalized_block_height, disabled)
		VALUES (?, ?, ?)
		ON CONFLICT(chain_selector) DO UPDATE SET
			finalized_block_height = excluded.finalized_block_height,
			disabled = excluded.disabled,
			updated_at = strftime('%s', 'now')
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare full statement: %w", err)
	}
	defer func() { _ = fullStmt.Close() }()

	// Statement for disabled-only update (when block height is nil)
	disabledOnlyStmt, err := tx.PrepareContext(ctx, `
		UPDATE chain_statuses 
		SET disabled = ?, updated_at = strftime('%s', 'now')
		WHERE chain_selector = ?
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare disabled-only statement: %w", err)
	}
	defer func() { _ = disabledOnlyStmt.Close() }()

	for _, status := range statuses {
		chainSelectorStr := strconv.FormatUint(uint64(status.ChainSelector), 10)
		disabled := 0
		if status.Disabled {
			disabled = 1
		}

		if status.FinalizedBlockHeight != nil {
			blockHeight := status.FinalizedBlockHeight.String()
			_, err := fullStmt.ExecContext(ctx, chainSelectorStr, blockHeight, disabled)
			if err != nil {
				return fmt.Errorf("failed to upsert chain status for chain %s: %w", chainSelectorStr, err)
			}
		} else {
			// Only update disabled flag, preserve existing block height
			_, err := disabledOnlyStmt.ExecContext(ctx, disabled, chainSelectorStr)
			if err != nil {
				return fmt.Errorf("failed to update disabled flag for chain %s: %w", chainSelectorStr, err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	m.lggr.Debugw("Chain statuses written", "count", len(statuses))
	return nil
}

func (m *SQLiteChainStatusManager) ReadChainStatuses(ctx context.Context, chainSelectors []protocol.ChainSelector) (map[protocol.ChainSelector]*protocol.ChainStatusInfo, error) {
	result := make(map[protocol.ChainSelector]*protocol.ChainStatusInfo)

	if len(chainSelectors) == 0 {
		return result, nil
	}

	query := `SELECT chain_selector, finalized_block_height, disabled FROM chain_statuses WHERE chain_selector IN (`
	args := make([]any, len(chainSelectors))
	for i, sel := range chainSelectors {
		if i > 0 {
			query += ", "
		}
		query += "?"
		args[i] = strconv.FormatUint(uint64(sel), 10)
	}
	query += ")"

	rows, err := m.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query chain statuses: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var chainSelectorStr string
		var blockHeightStr string
		var disabled int

		if err := rows.Scan(&chainSelectorStr, &blockHeightStr, &disabled); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		chainSelectorUint, err := strconv.ParseUint(chainSelectorStr, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse chain selector %s: %w", chainSelectorStr, err)
		}
		chainSelector := protocol.ChainSelector(chainSelectorUint)

		blockHeight, ok := new(big.Int).SetString(blockHeightStr, 10)
		if !ok {
			return nil, fmt.Errorf("failed to parse block height %s", blockHeightStr)
		}

		result[chainSelector] = &protocol.ChainStatusInfo{
			ChainSelector:        chainSelector,
			FinalizedBlockHeight: blockHeight,
			Disabled:             disabled == 1,
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	m.lggr.Debugw("Chain statuses read", "requested", len(chainSelectors), "found", len(result))
	return result, nil
}

func (m *SQLiteChainStatusManager) Close() error {
	if m.db != nil {
		return m.db.Close()
	}
	return nil
}
