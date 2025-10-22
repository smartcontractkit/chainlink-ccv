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

// DatabaseCheckpointStorage implements CheckpointStorageInterface using a database backend.
type DatabaseCheckpointStorage struct {
	ds         sqlutil.DataSource
	driverName string
}

// Ensure DatabaseCheckpointStorage implements the interface.
var _ common.CheckpointStorageInterface = (*DatabaseCheckpointStorage)(nil)

// NewDatabaseCheckpointStorage creates a new database-backed checkpoint storage instance.
func NewDatabaseCheckpointStorage(ds sqlutil.DataSource) *DatabaseCheckpointStorage {
	return &DatabaseCheckpointStorage{
		ds:         ds,
		driverName: ds.DriverName(),
	}
}

func (d *DatabaseCheckpointStorage) HealthCheck(ctx context.Context) *common.ComponentHealth {
	result := &common.ComponentHealth{
		Name:      "postgres_checkpoint_storage",
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

// validateStoreCheckpointsInput validates the input parameters for StoreCheckpoints.
func validateStoreCheckpointsInput(clientID string, checkpoints map[uint64]uint64) error {
	if strings.TrimSpace(clientID) == "" {
		return errors.New("client ID cannot be empty")
	}

	if checkpoints == nil {
		return errors.New("checkpoints cannot be nil")
	}

	// Validate each checkpoint
	for chainSelector, blockHeight := range checkpoints {
		if chainSelector == 0 {
			return errors.New("chain_selector must be greater than 0")
		}
		if blockHeight == 0 {
			return errors.New("finalized_block_height must be greater than 0")
		}
	}

	return nil
}

// StoreCheckpoints stores a batch of checkpoints for a client atomically.
// If the client doesn't exist, it will be created.
// Existing checkpoints for the same chain_selector will be overridden.
func (d *DatabaseCheckpointStorage) StoreCheckpoints(ctx context.Context, clientID string, checkpoints map[uint64]uint64) error {
	if err := validateStoreCheckpointsInput(clientID, checkpoints); err != nil {
		return err
	}

	return sqlutil.TransactDataSource(ctx, d.ds, nil, func(tx sqlutil.DataSource) error {
		for chainSelector, blockHeight := range checkpoints {
			stmt := `INSERT INTO block_checkpoints 
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

// GetClientCheckpoints retrieves all checkpoints for a client.
// Returns an empty map if the client has no checkpoints.
func (d *DatabaseCheckpointStorage) GetClientCheckpoints(ctx context.Context, clientID string) (map[uint64]uint64, error) {
	stmt := `SELECT chain_selector, finalized_block_height 
		FROM block_checkpoints 
		WHERE client_id = $1`

	type checkpoint struct {
		ChainSelector        string `db:"chain_selector"`
		FinalizedBlockHeight string `db:"finalized_block_height"`
	}

	var checkpoints []checkpoint
	err := d.ds.SelectContext(ctx, &checkpoints, stmt, clientID)
	if err != nil {
		return nil, err
	}

	result := make(map[uint64]uint64, len(checkpoints))
	for _, cp := range checkpoints {
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

// GetAllClients returns a list of all client IDs that have stored checkpoints.
func (d *DatabaseCheckpointStorage) GetAllClients(ctx context.Context) ([]string, error) {
	stmt := `SELECT DISTINCT client_id FROM block_checkpoints ORDER BY client_id`

	var clients []string
	err := d.ds.SelectContext(ctx, &clients, stmt)
	if err != nil {
		return nil, err
	}

	return clients, nil
}
