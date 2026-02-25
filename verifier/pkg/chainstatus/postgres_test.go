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

func TestPostgresChainStatusManager_DisabledFlagAndMonotonicity(t *testing.T) {
	db := setupTestDB(t)
	lggr, err := logger.New()
	require.NoError(t, err)
	ctx := context.Background()

	t.Run("disabled flag persists when writing with disabled=false", func(t *testing.T) {
		manager := NewPostgresChainStatusManager(db, lggr, "test-disabled-persistence")
		_, _ = db.Exec("DELETE FROM ccv_chain_statuses WHERE verifier_id = 'test-disabled-persistence'")
		chainSelector := protocol.ChainSelector(1)

		// Initial write: chain is enabled
		err := manager.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
			{
				ChainSelector:        chainSelector,
				FinalizedBlockHeight: big.NewInt(100),
				Disabled:             false,
			},
		})
		require.NoError(t, err)

		// Verify initial state
		result, err := manager.ReadChainStatuses(ctx, []protocol.ChainSelector{chainSelector})
		require.NoError(t, err)
		assert.False(t, result[chainSelector].Disabled)
		assert.Equal(t, big.NewInt(100), result[chainSelector].FinalizedBlockHeight)

		// Finality violation detected - disable the chain
		err = manager.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
			{
				ChainSelector:        chainSelector,
				FinalizedBlockHeight: big.NewInt(150),
				Disabled:             true,
			},
		})
		require.NoError(t, err)

		// Verify chain is disabled
		result, err = manager.ReadChainStatuses(ctx, []protocol.ChainSelector{chainSelector})
		require.NoError(t, err)
		assert.True(t, result[chainSelector].Disabled, "chain should be disabled after finality violation")
		assert.Equal(t, big.NewInt(150), result[chainSelector].FinalizedBlockHeight)

		// StorageWriterProcessor writes checkpoint with Disabled=false (zero value)
		// This should NOT re-enable the chain
		err = manager.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
			{
				ChainSelector:        chainSelector,
				FinalizedBlockHeight: big.NewInt(200),
				Disabled:             false, // Zero value from StorageWriterProcessor
			},
		})
		require.NoError(t, err)

		// Verify chain remains disabled (bug fix verification)
		result, err = manager.ReadChainStatuses(ctx, []protocol.ChainSelector{chainSelector})
		require.NoError(t, err)
		assert.True(t, result[chainSelector].Disabled, "chain should remain disabled despite subsequent write with disabled=false")
		assert.Equal(t, big.NewInt(200), result[chainSelector].FinalizedBlockHeight)
	})

	t.Run("block height increases normally", func(t *testing.T) {
		manager := NewPostgresChainStatusManager(db, lggr, "test-monotonicity-increase")
		_, _ = db.Exec("DELETE FROM ccv_chain_statuses WHERE verifier_id = 'test-monotonicity-increase'")
		chainSelector := protocol.ChainSelector(2)

		// Write initial height
		err := manager.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
			{
				ChainSelector:        chainSelector,
				FinalizedBlockHeight: big.NewInt(100),
				Disabled:             false,
			},
		})
		require.NoError(t, err)

		// Write higher height
		err = manager.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
			{
				ChainSelector:        chainSelector,
				FinalizedBlockHeight: big.NewInt(200),
				Disabled:             false,
			},
		})
		require.NoError(t, err)

		result, err := manager.ReadChainStatuses(ctx, []protocol.ChainSelector{chainSelector})
		require.NoError(t, err)
		assert.Equal(t, big.NewInt(200), result[chainSelector].FinalizedBlockHeight)
	})

	t.Run("block height does not decrease when chain is enabled", func(t *testing.T) {
		manager := NewPostgresChainStatusManager(db, lggr, "test-monotonicity-no-decrease")
		_, _ = db.Exec("DELETE FROM ccv_chain_statuses WHERE verifier_id = 'test-monotonicity-no-decrease'")
		chainSelector := protocol.ChainSelector(3)

		// Write initial height
		err := manager.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
			{
				ChainSelector:        chainSelector,
				FinalizedBlockHeight: big.NewInt(200),
				Disabled:             false,
			},
		})
		require.NoError(t, err)

		// Try to write lower height with disabled=false
		err = manager.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
			{
				ChainSelector:        chainSelector,
				FinalizedBlockHeight: big.NewInt(150),
				Disabled:             false,
			},
		})
		require.NoError(t, err)

		// Verify height did NOT decrease
		result, err := manager.ReadChainStatuses(ctx, []protocol.ChainSelector{chainSelector})
		require.NoError(t, err)
		assert.Equal(t, big.NewInt(200), result[chainSelector].FinalizedBlockHeight, "height should not decrease")
		assert.False(t, result[chainSelector].Disabled)
	})

	t.Run("block height can be set to any value when disabling chain", func(t *testing.T) {
		manager := NewPostgresChainStatusManager(db, lggr, "test-monotonicity-disable")
		_, _ = db.Exec("DELETE FROM ccv_chain_statuses WHERE verifier_id = 'test-monotonicity-disable'")
		chainSelector := protocol.ChainSelector(4)

		// Write initial height
		err := manager.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
			{
				ChainSelector:        chainSelector,
				FinalizedBlockHeight: big.NewInt(200),
				Disabled:             false,
			},
		})
		require.NoError(t, err)

		// When disabling chain (finality violation), we should be able to set any height
		err = manager.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
			{
				ChainSelector:        chainSelector,
				FinalizedBlockHeight: big.NewInt(50), // Lower than current 200
				Disabled:             true,
			},
		})
		require.NoError(t, err)

		// Verify height was updated because disabled=true
		result, err := manager.ReadChainStatuses(ctx, []protocol.ChainSelector{chainSelector})
		require.NoError(t, err)
		assert.Equal(t, big.NewInt(50), result[chainSelector].FinalizedBlockHeight, "height should be updatable when disabling")
		assert.True(t, result[chainSelector].Disabled)
	})

	t.Run("coordinator respects disabled flag after restart", func(t *testing.T) {
		verifierID := "verifier-restart"
		_, _ = db.Exec("DELETE FROM ccv_chain_statuses WHERE verifier_id = $1", verifierID)
		chainSelector := protocol.ChainSelector(5)

		manager1 := NewPostgresChainStatusManager(db, lggr, verifierID)

		// Initial state: chain is enabled
		err := manager1.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
			{
				ChainSelector:        chainSelector,
				FinalizedBlockHeight: big.NewInt(100),
				Disabled:             false,
			},
		})
		require.NoError(t, err)

		// SourceReaderService detects finality violation
		err = manager1.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
			{
				ChainSelector:        chainSelector,
				FinalizedBlockHeight: big.NewInt(100),
				Disabled:             true,
			},
		})
		require.NoError(t, err)

		// Simulate multiple checkpoint writes from StorageWriterProcessor
		// (with zero-value Disabled=false)
		for i := range 5 {
			err = manager1.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
				{
					ChainSelector:        chainSelector,
					FinalizedBlockHeight: big.NewInt(int64(110 + i*10)),
					Disabled:             false, // Zero value
				},
			})
			require.NoError(t, err)
		}

		// Simulate restart: create new manager instance with same verifier_id
		// (in real scenario, this is the same verifier process restarting)
		manager2 := NewPostgresChainStatusManager(db, lggr, verifierID)

		// Coordinator reads chain status on startup
		result, err := manager2.ReadChainStatuses(ctx, []protocol.ChainSelector{chainSelector})
		require.NoError(t, err)
		require.NotEmpty(t, result, "should find chain status after restart")

		// Critical assertion: chain should still be disabled
		assert.True(t, result[chainSelector].Disabled,
			"chain must remain disabled after restart despite checkpoint writes")
		assert.Equal(t, big.NewInt(150), result[chainSelector].FinalizedBlockHeight,
			"height should have increased from checkpoint writes")
	})

	t.Run("multiple chains have independent disabled flags", func(t *testing.T) {
		manager := NewPostgresChainStatusManager(db, lggr, "test-multi-chain-disabled")
		_, _ = db.Exec("DELETE FROM ccv_chain_statuses WHERE verifier_id = 'test-multi-chain-disabled'")

		chain1 := protocol.ChainSelector(6)
		chain2 := protocol.ChainSelector(7)

		// Write initial state for both chains
		err = manager.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
			{
				ChainSelector:        chain1,
				FinalizedBlockHeight: big.NewInt(100),
				Disabled:             false,
			},
			{
				ChainSelector:        chain2,
				FinalizedBlockHeight: big.NewInt(200),
				Disabled:             false,
			},
		})
		require.NoError(t, err)

		// Disable chain 1 due to finality violation
		err = manager.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
			{
				ChainSelector:        chain1,
				FinalizedBlockHeight: big.NewInt(150),
				Disabled:             true,
			},
		})
		require.NoError(t, err)

		// Write checkpoint for both chains with disabled=false
		err = manager.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
			{
				ChainSelector:        chain1,
				FinalizedBlockHeight: big.NewInt(180),
				Disabled:             false,
			},
			{
				ChainSelector:        chain2,
				FinalizedBlockHeight: big.NewInt(250),
				Disabled:             false,
			},
		})
		require.NoError(t, err)

		// Read both chains
		result, err := manager.ReadChainStatuses(ctx, []protocol.ChainSelector{chain1, chain2})
		require.NoError(t, err)

		// Chain 1 should remain disabled
		assert.True(t, result[chain1].Disabled, "chain 1 should remain disabled")
		assert.Equal(t, big.NewInt(180), result[chain1].FinalizedBlockHeight)

		// Chain 2 should remain enabled
		assert.False(t, result[chain2].Disabled, "chain 2 should remain enabled")
		assert.Equal(t, big.NewInt(250), result[chain2].FinalizedBlockHeight)
	})
}
