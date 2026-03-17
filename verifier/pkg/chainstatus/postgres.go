package chainstatus

import (
	"context"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
)

// Row represents a row from ccv_chain_statuses for CLI list output.
type Row struct {
	ChainSelector        protocol.ChainSelector
	VerifierID           string
	FinalizedBlockHeight *big.Int
	Disabled             bool
	UpdatedAt            time.Time
}

// PostgresChainStatusStore is the single store for ccv_chain_statuses. Used by CLI (list, set) and by
// PostgresChainStatusManager for verifier-scoped read/write.
type PostgresChainStatusStore struct {
	ds   sqlutil.DataSource
	lggr logger.Logger
}

// NewPostgresChainStatusStore returns the store for all chain status DB operations.
func NewPostgresChainStatusStore(ds sqlutil.DataSource, lggr logger.Logger) *PostgresChainStatusStore {
	return &PostgresChainStatusStore{
		ds:   ds,
		lggr: logger.With(lggr, "component", "PostgresChainStatusStore"),
	}
}

// WriteChainStatuses upserts chain statuses for the given verifierID.
func (s *PostgresChainStatusStore) WriteChainStatuses(ctx context.Context, verifierID string, statuses []protocol.ChainStatusInfo) error {
	if len(statuses) == 0 {
		return nil
	}
	return sqlutil.TransactDataSource(ctx, s.ds, nil, func(tx sqlutil.DataSource) error {
		for _, status := range statuses {
			chainSelectorStr := strconv.FormatUint(uint64(status.ChainSelector), 10)
			if status.FinalizedBlockHeight == nil {
				return fmt.Errorf("finalized block height cannot be nil for chain %s", chainSelectorStr)
			}
			stmt := `INSERT INTO ccv_chain_statuses (chain_selector, verifier_id, finalized_block_height, disabled)
				VALUES ($1, $2, $3, $4)
				ON CONFLICT (chain_selector, verifier_id) DO UPDATE SET
					finalized_block_height = EXCLUDED.finalized_block_height,
					disabled = EXCLUDED.disabled,
					updated_at = NOW()`
			blockHeightStr := status.FinalizedBlockHeight.String()
			_, err := tx.ExecContext(ctx, stmt, chainSelectorStr, verifierID, blockHeightStr, status.Disabled)
			if err != nil {
				return fmt.Errorf("failed to upsert chain status for chain %s: %w", chainSelectorStr, err)
			}
		}
		return nil
	})
}

// ReadChainStatuses returns statuses for the given verifierID and chain selectors.
func (s *PostgresChainStatusStore) ReadChainStatuses(ctx context.Context, verifierID string, chainSelectors []protocol.ChainSelector) (map[protocol.ChainSelector]*protocol.ChainStatusInfo, error) {
	result := make(map[protocol.ChainSelector]*protocol.ChainStatusInfo)
	if len(chainSelectors) == 0 {
		return result, nil
	}
	placeholders := make([]string, len(chainSelectors))
	args := make([]any, len(chainSelectors)+1)
	for i, sel := range chainSelectors {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args[i+1] = strconv.FormatUint(uint64(sel), 10)
	}
	args[0] = verifierID
	stmt := fmt.Sprintf(`SELECT chain_selector, finalized_block_height, disabled
		FROM ccv_chain_statuses
		WHERE verifier_id = $1 AND chain_selector IN (%s)`,
		strings.Join(placeholders, ","))
	type readRow struct {
		ChainSelector        string `db:"chain_selector"`
		FinalizedBlockHeight string `db:"finalized_block_height"`
		Disabled             bool   `db:"disabled"`
	}
	var rows []readRow
	if err := s.ds.SelectContext(ctx, &rows, stmt, args...); err != nil {
		return nil, fmt.Errorf("failed to query chain statuses: %w", err)
	}
	for _, row := range rows {
		chainSelectorUint, err := strconv.ParseUint(row.ChainSelector, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse chain selector %s: %w", row.ChainSelector, err)
		}
		chainSelector := protocol.ChainSelector(chainSelectorUint)
		blockHeight, ok := new(big.Int).SetString(row.FinalizedBlockHeight, 10)
		if !ok {
			return nil, fmt.Errorf("failed to parse block height %s", row.FinalizedBlockHeight)
		}
		result[chainSelector] = &protocol.ChainStatusInfo{
			ChainSelector:        chainSelector,
			FinalizedBlockHeight: blockHeight,
			Disabled:             row.Disabled,
		}
	}
	s.lggr.Debugw("Chain statuses read", "verifier_id", verifierID, "requested", len(chainSelectors), "found", len(result))
	return result, nil
}

// List returns all chain status rows.
func (s *PostgresChainStatusStore) List(ctx context.Context) ([]Row, error) {
	var rows []chainStatusListRow
	err := s.ds.SelectContext(ctx, &rows, `SELECT chain_selector, verifier_id, finalized_block_height, disabled, updated_at
		FROM ccv_chain_statuses ORDER BY chain_selector, verifier_id`)
	if err != nil {
		return nil, fmt.Errorf("failed to list chain statuses: %w", err)
	}
	result := make([]Row, 0, len(rows))
	for _, r := range rows {
		row, err := r.toRow()
		if err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, nil
}

type chainStatusListRow struct {
	ChainSelector        string    `db:"chain_selector"`
	VerifierID           string    `db:"verifier_id"`
	FinalizedBlockHeight string    `db:"finalized_block_height"`
	Disabled             bool      `db:"disabled"`
	UpdatedAt            time.Time `db:"updated_at"`
}

func (r chainStatusListRow) toRow() (Row, error) {
	sel, err := strconv.ParseUint(r.ChainSelector, 10, 64)
	if err != nil {
		return Row{}, fmt.Errorf("failed to parse chain_selector %s: %w", r.ChainSelector, err)
	}
	height, ok := new(big.Int).SetString(r.FinalizedBlockHeight, 10)
	if !ok {
		return Row{}, fmt.Errorf("failed to parse finalized_block_height %s", r.FinalizedBlockHeight)
	}
	return Row{
		ChainSelector:        protocol.ChainSelector(sel),
		VerifierID:           r.VerifierID,
		FinalizedBlockHeight: height,
		Disabled:             r.Disabled,
		UpdatedAt:            r.UpdatedAt,
	}, nil
}

// SetDisabled sets the disabled flag for the given (chain_selector, verifier_id).
func (s *PostgresChainStatusStore) SetDisabled(ctx context.Context, chainSelector protocol.ChainSelector, verifierID string, disabled bool) error {
	chainSelectorStr := strconv.FormatUint(uint64(chainSelector), 10)
	res, err := s.ds.ExecContext(ctx, `UPDATE ccv_chain_statuses SET disabled = $1, updated_at = NOW()
		WHERE chain_selector = $2 AND verifier_id = $3`, disabled, chainSelectorStr, verifierID)
	if err != nil {
		return fmt.Errorf("failed to set disabled for chain %s verifier %s: %w", chainSelectorStr, verifierID, err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("no row found for chain_selector=%s verifier_id=%s", chainSelectorStr, verifierID)
	}
	return nil
}

// SetFinalizedBlockHeight sets the finalized_block_height for the given (chain_selector, verifier_id).
func (s *PostgresChainStatusStore) SetFinalizedBlockHeight(ctx context.Context, chainSelector protocol.ChainSelector, verifierID string, height *big.Int) error {
	if height == nil {
		return fmt.Errorf("finalized block height cannot be nil")
	}
	chainSelectorStr := strconv.FormatUint(uint64(chainSelector), 10)
	heightStr := height.String()
	res, err := s.ds.ExecContext(ctx, `UPDATE ccv_chain_statuses SET finalized_block_height = $1, updated_at = NOW()
		WHERE chain_selector = $2 AND verifier_id = $3`, heightStr, chainSelectorStr, verifierID)
	if err != nil {
		return fmt.Errorf("failed to set finalized block height for chain %s verifier %s: %w", chainSelectorStr, verifierID, err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("no row found for chain_selector=%s verifier_id=%s", chainSelectorStr, verifierID)
	}
	return nil
}

var _ protocol.ChainStatusManager = (*PostgresChainStatusManager)(nil)

// PostgresChainStatusManager is a scoped adapter that implements protocol.ChainStatusManager by delegating to the store with a fixed verifierID.
type PostgresChainStatusManager struct {
	store      *PostgresChainStatusStore
	verifierID string
}

// NewPostgresChainStatusManager returns a manager that uses the given store for the given verifierID.
func NewPostgresChainStatusManager(store *PostgresChainStatusStore, verifierID string) *PostgresChainStatusManager {
	return &PostgresChainStatusManager{
		store:      store,
		verifierID: verifierID,
	}
}

func (m *PostgresChainStatusManager) WriteChainStatuses(ctx context.Context, statuses []protocol.ChainStatusInfo) error {
	return m.store.WriteChainStatuses(ctx, m.verifierID, statuses)
}

func (m *PostgresChainStatusManager) ReadChainStatuses(ctx context.Context, chainSelectors []protocol.ChainSelector) (map[protocol.ChainSelector]*protocol.ChainStatusInfo, error) {
	return m.store.ReadChainStatuses(ctx, m.verifierID, chainSelectors)
}
