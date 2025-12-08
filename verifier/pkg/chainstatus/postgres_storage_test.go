package chainstatus

import (
	"context"
	"database/sql"
	"math/big"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func setupTestDB(t *testing.T) *sqlx.DB {
	t.Helper()
	ctx := context.Background()

	postgresContainer, err := postgres.Run(ctx,
		"postgres:15-alpine",
		postgres.WithDatabase("test_chainstatus_db"),
		postgres.WithUsername("test_user"),
		postgres.WithPassword("test_password"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second)),
	)
	require.NoError(t, err)

	connectionString, err := postgresContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	db, err := sql.Open("postgres", connectionString)
	require.NoError(t, err)

	sqlxDB := sqlx.NewDb(db, "postgres")

	err = RunPostgresMigrations(sqlxDB)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = sqlxDB.Close()
		if err := postgresContainer.Terminate(context.Background()); err != nil {
			t.Logf("failed to terminate postgres container: %v", err)
		}
	})

	return sqlxDB
}

func TestPostgresChainStatusManager_WriteAndReadChainStatuses(t *testing.T) {
	db := setupTestDB(t)
	lggr, err := logger.New()
	require.NoError(t, err)

	manager := NewPostgresChainStatusManager(db, lggr)
	ctx := context.Background()

	tests := []struct {
		name           string
		statuses       []protocol.ChainStatusInfo
		chainSelectors []protocol.ChainSelector
		expected       map[protocol.ChainSelector]*protocol.ChainStatusInfo
	}{
		{
			name: "write and read single chain status",
			statuses: []protocol.ChainStatusInfo{
				{
					ChainSelector:        1,
					FinalizedBlockHeight: big.NewInt(100),
					Disabled:             false,
				},
			},
			chainSelectors: []protocol.ChainSelector{1},
			expected: map[protocol.ChainSelector]*protocol.ChainStatusInfo{
				1: {
					ChainSelector:        1,
					FinalizedBlockHeight: big.NewInt(100),
					Disabled:             false,
				},
			},
		},
		{
			name: "write and read multiple chain statuses",
			statuses: []protocol.ChainStatusInfo{
				{
					ChainSelector:        1,
					FinalizedBlockHeight: big.NewInt(100),
					Disabled:             false,
				},
				{
					ChainSelector:        2,
					FinalizedBlockHeight: big.NewInt(200),
					Disabled:             true,
				},
			},
			chainSelectors: []protocol.ChainSelector{1, 2},
			expected: map[protocol.ChainSelector]*protocol.ChainStatusInfo{
				1: {
					ChainSelector:        1,
					FinalizedBlockHeight: big.NewInt(100),
					Disabled:             false,
				},
				2: {
					ChainSelector:        2,
					FinalizedBlockHeight: big.NewInt(200),
					Disabled:             true,
				},
			},
		},
		{
			name: "read only requested chain selectors",
			statuses: []protocol.ChainStatusInfo{
				{
					ChainSelector:        1,
					FinalizedBlockHeight: big.NewInt(100),
					Disabled:             false,
				},
				{
					ChainSelector:        2,
					FinalizedBlockHeight: big.NewInt(200),
					Disabled:             true,
				},
			},
			chainSelectors: []protocol.ChainSelector{1},
			expected: map[protocol.ChainSelector]*protocol.ChainStatusInfo{
				1: {
					ChainSelector:        1,
					FinalizedBlockHeight: big.NewInt(100),
					Disabled:             false,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up before each test.
			_, _ = db.Exec("DELETE FROM ccv_chain_statuses")

			err := manager.WriteChainStatuses(ctx, tt.statuses)
			require.NoError(t, err)

			result, err := manager.ReadChainStatuses(ctx, tt.chainSelectors)
			require.NoError(t, err)
			require.Len(t, result, len(tt.expected))

			for selector, expected := range tt.expected {
				actual, ok := result[selector]
				require.True(t, ok, "expected chain selector %d to be in result", selector)
				assert.Equal(t, expected.ChainSelector, actual.ChainSelector)
				assert.Equal(t, 0, expected.FinalizedBlockHeight.Cmp(actual.FinalizedBlockHeight))
				assert.Equal(t, expected.Disabled, actual.Disabled)
			}
		})
	}
}

func TestPostgresChainStatusManager_UpsertChainStatus(t *testing.T) {
	db := setupTestDB(t)
	lggr, err := logger.New()
	require.NoError(t, err)

	manager := NewPostgresChainStatusManager(db, lggr)
	ctx := context.Background()

	// Write initial status.
	err = manager.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
		{
			ChainSelector:        1,
			FinalizedBlockHeight: big.NewInt(100),
			Disabled:             false,
		},
	})
	require.NoError(t, err)

	// Update the status.
	err = manager.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
		{
			ChainSelector:        1,
			FinalizedBlockHeight: big.NewInt(200),
			Disabled:             true,
		},
	})
	require.NoError(t, err)

	// Read and verify updated status.
	result, err := manager.ReadChainStatuses(ctx, []protocol.ChainSelector{1})
	require.NoError(t, err)
	require.Len(t, result, 1)

	status := result[1]
	assert.Equal(t, protocol.ChainSelector(1), status.ChainSelector)
	assert.Equal(t, 0, big.NewInt(200).Cmp(status.FinalizedBlockHeight))
	assert.True(t, status.Disabled)
}

func TestPostgresChainStatusManager_ReadEmptyResult(t *testing.T) {
	db := setupTestDB(t)
	lggr, err := logger.New()
	require.NoError(t, err)

	manager := NewPostgresChainStatusManager(db, lggr)
	ctx := context.Background()

	// Read non-existent chain selectors.
	result, err := manager.ReadChainStatuses(ctx, []protocol.ChainSelector{999})
	require.NoError(t, err)
	require.Empty(t, result)
}

func TestPostgresChainStatusManager_WriteEmptyStatuses(t *testing.T) {
	db := setupTestDB(t)
	lggr, err := logger.New()
	require.NoError(t, err)

	manager := NewPostgresChainStatusManager(db, lggr)
	ctx := context.Background()

	// Write empty statuses should not error.
	err = manager.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{})
	require.NoError(t, err)
}

func TestPostgresChainStatusManager_ReadEmptySelectors(t *testing.T) {
	db := setupTestDB(t)
	lggr, err := logger.New()
	require.NoError(t, err)

	manager := NewPostgresChainStatusManager(db, lggr)
	ctx := context.Background()

	// Read with empty selectors should return empty map.
	result, err := manager.ReadChainStatuses(ctx, []protocol.ChainSelector{})
	require.NoError(t, err)
	require.Empty(t, result)
}

func TestPostgresChainStatusManager_WriteNilBlockHeight(t *testing.T) {
	db := setupTestDB(t)
	lggr, err := logger.New()
	require.NoError(t, err)

	manager := NewPostgresChainStatusManager(db, lggr)
	ctx := context.Background()

	// Write with nil block height should error.
	err = manager.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
		{
			ChainSelector:        1,
			FinalizedBlockHeight: nil,
			Disabled:             false,
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "finalized block height cannot be nil")
}
