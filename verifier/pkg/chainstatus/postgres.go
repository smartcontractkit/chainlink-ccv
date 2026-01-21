package chainstatus

import (
	"context"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
)

var _ protocol.ChainStatusManager = (*PostgresChainStatusManager)(nil)

type PostgresChainStatusManager struct {
	ds   sqlutil.DataSource
	lggr logger.Logger
}

func NewPostgresChainStatusManager(ds sqlutil.DataSource, lggr logger.Logger) *PostgresChainStatusManager {
	return &PostgresChainStatusManager{
		ds:   ds,
		lggr: logger.With(lggr, "component", "PostgresChainStatusManager"),
	}
}

func (m *PostgresChainStatusManager) WriteChainStatuses(ctx context.Context, statuses []protocol.ChainStatusInfo) error {
	if len(statuses) == 0 {
		return nil
	}

	return sqlutil.TransactDataSource(ctx, m.ds, nil, func(tx sqlutil.DataSource) error {
		for _, status := range statuses {
			chainSelectorStr := strconv.FormatUint(uint64(status.ChainSelector), 10)

			if status.FinalizedBlockHeight == nil {
				return fmt.Errorf("finalized block height cannot be nil for chain %s", chainSelectorStr)
			}

			stmt := `INSERT INTO ccv_chain_statuses (chain_selector, finalized_block_height, disabled)
				VALUES ($1, $2, $3)
				ON CONFLICT (chain_selector) DO UPDATE SET
					finalized_block_height = EXCLUDED.finalized_block_height,
					disabled = EXCLUDED.disabled,
					updated_at = NOW()`

			blockHeightStr := status.FinalizedBlockHeight.String()
			_, err := tx.ExecContext(ctx, stmt, chainSelectorStr, blockHeightStr, status.Disabled)
			if err != nil {
				return fmt.Errorf("failed to upsert chain status for chain %s: %w", chainSelectorStr, err)
			}
		}
		return nil
	})
}

func (m *PostgresChainStatusManager) ReadChainStatuses(ctx context.Context, chainSelectors []protocol.ChainSelector) (map[protocol.ChainSelector]*protocol.ChainStatusInfo, error) {
	result := make(map[protocol.ChainSelector]*protocol.ChainStatusInfo)

	if len(chainSelectors) == 0 {
		return result, nil
	}

	placeholders := make([]string, len(chainSelectors))
	args := make([]any, len(chainSelectors))
	for i, sel := range chainSelectors {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = strconv.FormatUint(uint64(sel), 10)
	}

	stmt := fmt.Sprintf(`SELECT chain_selector, finalized_block_height, disabled 
		FROM ccv_chain_statuses 
		WHERE chain_selector IN (%s)`,
		strings.Join(placeholders, ","))

	type chainStatusRow struct {
		ChainSelector        string `db:"chain_selector"`
		FinalizedBlockHeight string `db:"finalized_block_height"`
		Disabled             bool   `db:"disabled"`
	}

	var rows []chainStatusRow
	err := m.ds.SelectContext(ctx, &rows, stmt, args...)
	if err != nil {
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

	m.lggr.Debugw("Chain statuses read", "requested", len(chainSelectors), "found", len(result))
	return result, nil
}
