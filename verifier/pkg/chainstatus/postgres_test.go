package chainstatus

import (
	"context"
	"database/sql"
	"math/big"
	"testing"
	"time"

	db2 "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/db"

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
	if testing.Short() {
		t.Skip("skipping docker test in short mode")
	}
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

	err = db2.RunPostgresMigrations(sqlxDB)
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

	manager := NewPostgresChainStatusManager(db, lggr, "test-verifier-1")
	ctx := context.Background()

	tests := []struct {
		name           string
		initialState   []protocol.ChainStatusInfo
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
		{
			name: "upsert updates existing chain status",
			initialState: []protocol.ChainStatusInfo{
				{
					ChainSelector:        1,
					FinalizedBlockHeight: big.NewInt(100),
					Disabled:             false,
				},
			},
			statuses: []protocol.ChainStatusInfo{
				{
					ChainSelector:        1,
					FinalizedBlockHeight: big.NewInt(200),
					Disabled:             true,
				},
			},
			chainSelectors: []protocol.ChainSelector{1},
			expected: map[protocol.ChainSelector]*protocol.ChainStatusInfo{
				1: {
					ChainSelector:        1,
					FinalizedBlockHeight: big.NewInt(200),
					Disabled:             true,
				},
			},
		},
		{
			name:           "read non-existent chain selectors returns empty map",
			statuses:       []protocol.ChainStatusInfo{},
			chainSelectors: []protocol.ChainSelector{999},
			expected:       map[protocol.ChainSelector]*protocol.ChainStatusInfo{},
		},
		{
			name:           "read with empty selectors returns empty map",
			statuses:       []protocol.ChainStatusInfo{},
			chainSelectors: []protocol.ChainSelector{},
			expected:       map[protocol.ChainSelector]*protocol.ChainStatusInfo{},
		},
		{
			name:           "write empty statuses does not error",
			statuses:       []protocol.ChainStatusInfo{},
			chainSelectors: []protocol.ChainSelector{},
			expected:       map[protocol.ChainSelector]*protocol.ChainStatusInfo{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _ = db.Exec("DELETE FROM ccv_chain_statuses")

			if len(tt.initialState) > 0 {
				err := manager.WriteChainStatuses(ctx, tt.initialState)
				require.NoError(t, err)
			}

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

func TestPostgresChainStatusManager_WriteChainStatuses_Errors(t *testing.T) {
	db := setupTestDB(t)
	lggr, err := logger.New()
	require.NoError(t, err)

	manager := NewPostgresChainStatusManager(db, lggr, "test-verifier-errors")
	ctx := context.Background()

	tests := []struct {
		name            string
		statuses        []protocol.ChainStatusInfo
		expectedErrText string
	}{
		{
			name: "nil block height returns error",
			statuses: []protocol.ChainStatusInfo{
				{
					ChainSelector:        1,
					FinalizedBlockHeight: nil,
					Disabled:             false,
				},
			},
			expectedErrText: "finalized block height cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _ = db.Exec("DELETE FROM ccv_chain_statuses")

			err := manager.WriteChainStatuses(ctx, tt.statuses)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErrText)
		})
	}
}

func TestPostgresChainStatusManager_MultipleVerifiers_Isolation(t *testing.T) {
	db := setupTestDB(t)
	lggr, err := logger.New()
	require.NoError(t, err)

	// Create two different verifier IDs
	verifierID1 := "verifier-1"
	verifierID2 := "verifier-2"

	manager1 := NewPostgresChainStatusManager(db, lggr, verifierID1)
	manager2 := NewPostgresChainStatusManager(db, lggr, verifierID2)
	ctx := context.Background()

	chainSelector := protocol.ChainSelector(1337)

	// Write status for verifier 1
	err = manager1.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
		{
			ChainSelector:        chainSelector,
			FinalizedBlockHeight: big.NewInt(100),
			Disabled:             false,
		},
	})
	require.NoError(t, err)

	// Write different status for verifier 2 on same chain
	err = manager2.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
		{
			ChainSelector:        chainSelector,
			FinalizedBlockHeight: big.NewInt(200),
			Disabled:             true,
		},
	})
	require.NoError(t, err)

	// Read from verifier 1
	result1, err := manager1.ReadChainStatuses(ctx, []protocol.ChainSelector{chainSelector})
	require.NoError(t, err)
	require.Len(t, result1, 1)
	assert.Equal(t, big.NewInt(100), result1[chainSelector].FinalizedBlockHeight)
	assert.False(t, result1[chainSelector].Disabled)

	// Read from verifier 2
	result2, err := manager2.ReadChainStatuses(ctx, []protocol.ChainSelector{chainSelector})
	require.NoError(t, err)
	require.Len(t, result2, 1)
	assert.Equal(t, big.NewInt(200), result2[chainSelector].FinalizedBlockHeight)
	assert.True(t, result2[chainSelector].Disabled)

	// Verify they don't interfere with each other
	assert.NotEqual(t, result1[chainSelector].FinalizedBlockHeight, result2[chainSelector].FinalizedBlockHeight)
	assert.NotEqual(t, result1[chainSelector].Disabled, result2[chainSelector].Disabled)
}
