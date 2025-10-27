package postgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
)

// DatabaseChainStatusStorage implements CheckpointStorageInterface using a database backend.
type DatabaseChainStatusStorage struct {
	ds         sqlutil.DataSource
	driverName string
}

// Ensure DatabaseChainStatusStorage implements the interface.
var _ common.ChainStatusStorageInterface = (*DatabaseChainStatusStorage)(nil)

// NewDatabaseChainStatusStorage creates a new database-backed chain status storage instance.
func NewDatabaseChainStatusStorage(ds sqlutil.DataSource) *DatabaseChainStatusStorage {
	return &DatabaseChainStatusStorage{
		ds:         ds,
		driverName: ds.DriverName(),
	}
}

func (d *DatabaseChainStatusStorage) HealthCheck(ctx context.Context) *common.ComponentHealth {
	result := &common.ComponentHealth{
		Name:      "postgres_chain_status_storage",
		Timestamp: time.Now(),
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var count int
	err := d.ds.GetContext(ctx, &count, "SELECT 1")
	if err != nil {
		result.Status = common.HealthStatusUnhealthy
		result.Message = fmt.Sprintf("query failed: %v", err)
		return result
	}

	result.Status = common.HealthStatusHealthy
	result.Message = "connected and responsive"
	return result
}

// validateStoreChainStatusInput validates the input parameters for StoreChainStatus.
func validateStoreChainStatusInput(clientID string, statuses map[uint64]uint64) error {
	if strings.TrimSpace(clientID) == "" {
		return errors.New("client ID cannot be empty")
	}

	if statuses == nil {
		return errors.New("statuses cannot be nil")
	}

	// Validate each checkpoint
	for chainSelector, blockHeight := range statuses {
		if chainSelector == 0 {
			return errors.New("chain_selector must be greater than 0")
		}
		if blockHeight == 0 {
			return errors.New("finalized_block_height must be greater than 0")
		}
	}

	return nil
}

// StoreChainStatus stores a batch of statuses for a client atomically.
// If the client doesn't exist, it will be created.
// Existing statuses for the same chain_selector will be overridden.
func (d *DatabaseChainStatusStorage) StoreChainStatus(ctx context.Context, clientID string, statuses map[uint64]uint64) error {
	if err := validateStoreChainStatusInput(clientID, statuses); err != nil {
		return err
	}

	return sqlutil.TransactDataSource(ctx, d.ds, nil, func(tx sqlutil.DataSource) error {
		for chainSelector, blockHeight := range statuses {
			stmt := `INSERT INTO block_statuses 
				(client_id, chain_selector, finalized_block_height) 
				VALUES ($1, $2, $3)
				ON CONFLICT (client_id, chain_selector) 
				DO UPDATE SET 
					finalized_block_height = EXCLUDED.finalized_block_height`

			chainSelectorStr := strconv.FormatUint(chainSelector, 10)
			blockHeightStr := strconv.FormatUint(blockHeight, 10)

			_, err := tx.ExecContext(ctx, stmt, clientID, chainSelectorStr, blockHeightStr)
			if err != nil {
				return fmt.Errorf("failed to store checkpoint for chain %d: %w", chainSelector, err)
			}
		}
		return nil
	})
}

// GetClientCheckpoints retrieves all statuses for a client.
// Returns an empty map if the client has no statuses.
func (d *DatabaseChainStatusStorage) GetClientChainStatus(ctx context.Context, clientID string) (map[uint64]uint64, error) {
	stmt := `SELECT chain_selector, finalized_block_height 
		FROM block_statuses 
		WHERE client_id = $1`

	type checkpoint struct {
		ChainSelector        string `db:"chain_selector"`
		FinalizedBlockHeight string `db:"finalized_block_height"`
	}

	var statuses []checkpoint
	err := d.ds.SelectContext(ctx, &statuses, stmt, clientID)
	if err != nil {
		return nil, err
	}

	result := make(map[uint64]uint64, len(statuses))
	for _, cp := range statuses {
		chainSelector, err := strconv.ParseUint(cp.ChainSelector, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse chain_selector %s: %w", cp.ChainSelector, err)
		}

		blockHeight, err := strconv.ParseUint(cp.FinalizedBlockHeight, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse finalized_block_height %s: %w", cp.FinalizedBlockHeight, err)
		}

		result[chainSelector] = blockHeight
	}

	return result, nil
}

// GetAllClients returns a list of all client IDs that have stored statuses.
func (d *DatabaseChainStatusStorage) GetAllClients(ctx context.Context) ([]string, error) {
	stmt := `SELECT DISTINCT client_id FROM block_statuses ORDER BY client_id`

	var clients []string
	err := d.ds.SelectContext(ctx, &clients, stmt)
	if err != nil {
		return nil, err
	}

	return clients, nil
}
