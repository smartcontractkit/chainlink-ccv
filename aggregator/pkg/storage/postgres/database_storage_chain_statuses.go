package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/chainstatus"
)

var _ chainstatus.Store = (*DatabaseStorage)(nil)

type chainStatusRow struct {
	ChainSelector uint64    `db:"chain_selector"`
	LaneSide      string    `db:"lane_side"`
	Disabled      bool      `db:"disabled"`
	UpdatedAt     time.Time `db:"updated_at"`
}

func rowToChainStatus(r chainStatusRow) chainstatus.ChainStatus {
	return chainstatus.ChainStatus{
		ChainSelector: r.ChainSelector,
		Side:          chainstatus.LaneSide(r.LaneSide),
		Disabled:      r.Disabled,
		UpdatedAt:     r.UpdatedAt,
	}
}

// BatchSetStatus upserts the disabled flag for the given lane side and selectors.
func (d *DatabaseStorage) BatchSetStatus(ctx context.Context, side chainstatus.LaneSide, selectors []uint64, disabled bool) error {
	ctx, cancel := d.withTimeout(ctx)
	defer cancel()

	stmt := `INSERT INTO aggregator_chain_statuses (chain_selector, lane_side, disabled)
	         VALUES ($1, $2, $3)
	         ON CONFLICT (chain_selector, lane_side) DO UPDATE SET disabled = $3, updated_at = NOW()`

	for _, sel := range selectors {
		if _, err := d.ds.ExecContext(ctx, stmt, sel, string(side), disabled); err != nil {
			return fmt.Errorf("failed to set status disabled=%v for %s selector %d: %w", disabled, side, sel, err)
		}
	}
	return nil
}

// List returns all chain status rows (including re-enabled ones for audit trail).
func (d *DatabaseStorage) List(ctx context.Context) ([]chainstatus.ChainStatus, error) {
	ctx, cancel := d.withTimeout(ctx)
	defer cancel()

	stmt := `SELECT chain_selector, lane_side, disabled, updated_at
	         FROM aggregator_chain_statuses
	         ORDER BY lane_side, chain_selector`

	var rows []chainStatusRow
	if err := d.ds.SelectContext(ctx, &rows, stmt); err != nil {
		return nil, fmt.Errorf("failed to list chain statuses: %w", err)
	}

	statuses := make([]chainstatus.ChainStatus, len(rows))
	for i, r := range rows {
		statuses[i] = rowToChainStatus(r)
	}
	return statuses, nil
}

// ListDisabled returns only rows where disabled = true.
func (d *DatabaseStorage) ListDisabled(ctx context.Context) ([]chainstatus.ChainStatus, error) {
	ctx, cancel := d.withTimeout(ctx)
	defer cancel()

	stmt := `SELECT chain_selector, lane_side, disabled, updated_at
	         FROM aggregator_chain_statuses
	         WHERE disabled = true
	         ORDER BY lane_side, chain_selector`

	var rows []chainStatusRow
	if err := d.ds.SelectContext(ctx, &rows, stmt); err != nil {
		return nil, fmt.Errorf("failed to list disabled chain statuses: %w", err)
	}

	statuses := make([]chainstatus.ChainStatus, len(rows))
	for i, r := range rows {
		statuses[i] = rowToChainStatus(r)
	}
	return statuses, nil
}

// Get returns the status for a specific selector + lane side. Returns nil if no row exists (= enabled).
func (d *DatabaseStorage) Get(ctx context.Context, side chainstatus.LaneSide, selector uint64) (*chainstatus.ChainStatus, error) {
	ctx, cancel := d.withTimeout(ctx)
	defer cancel()

	stmt := `SELECT chain_selector, lane_side, disabled, updated_at
	         FROM aggregator_chain_statuses
	         WHERE chain_selector = $1 AND lane_side = $2`

	var row chainStatusRow
	if err := d.ds.GetContext(ctx, &row, stmt, selector, string(side)); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get chain status for %s selector %d: %w", side, selector, err)
	}
	status := rowToChainStatus(row)
	return &status, nil
}
