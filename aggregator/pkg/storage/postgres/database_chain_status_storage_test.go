package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"

	_ "github.com/lib/pq"
)

var testClient = "test-client-2"

func setupTestChainStatusDB(t *testing.T) (*DatabaseChainStatusStorage, func()) {
	ctx := context.Background()

	postgresContainer, err := postgres.Run(ctx,
		"postgres:15-alpine",
		postgres.WithDatabase("test_status_db"),
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

	ds := sqlx.NewDb(db, "postgres")

	err = RunMigrations(ds, "postgres")
	require.NoError(t, err)

	storage := NewDatabaseChainStatusStorage(ds)

	cleanup := func() {
		ds.Close()
		if err := postgresContainer.Terminate(context.Background()); err != nil {
			t.Logf("failed to terminate postgres container: %v", err)
		}
	}

	return storage, cleanup
}

func TestStoreChainStatus_HappyPath_SingleChainStatus(t *testing.T) {
	storage, cleanup := setupTestChainStatusDB(t)
	defer cleanup()

	ctx := context.Background()
	clientID := "test-client-1"
	statuses := map[uint64]*common.ChainStatus{
		1: {FinalizedBlockHeight: 100, Disabled: false},
	}

	err := storage.StoreChainStatus(ctx, clientID, statuses)
	require.NoError(t, err)

	retrieved, err := storage.GetClientChainStatus(ctx, clientID, nil)
	require.NoError(t, err)
	require.Equal(t, statuses, retrieved)
}

func TestStoreChainStatus_HappyPath_MultipleChainStatuses(t *testing.T) {
	storage, cleanup := setupTestChainStatusDB(t)
	defer cleanup()

	ctx := context.Background()
	statuses := map[uint64]*common.ChainStatus{
		1: {FinalizedBlockHeight: 100, Disabled: false},
		2: {FinalizedBlockHeight: 200, Disabled: false},
		3: {FinalizedBlockHeight: 300, Disabled: false},
	}

	err := storage.StoreChainStatus(ctx, testClient, statuses)
	require.NoError(t, err)

	retrieved, err := storage.GetClientChainStatus(ctx, testClient, nil)
	require.NoError(t, err)
	require.Equal(t, statuses, retrieved)
}

func TestStoreChainStatus_HappyPath_MultipleChainStatuses_EmptyArray(t *testing.T) {
	storage, cleanup := setupTestChainStatusDB(t)
	defer cleanup()

	ctx := context.Background()
	statuses := map[uint64]*common.ChainStatus{
		1: {FinalizedBlockHeight: 100, Disabled: false},
		2: {FinalizedBlockHeight: 200, Disabled: false},
		3: {FinalizedBlockHeight: 300, Disabled: false},
	}

	err := storage.StoreChainStatus(ctx, testClient, statuses)
	require.NoError(t, err)

	retrieved, err := storage.GetClientChainStatus(ctx, testClient, []uint64{})
	require.NoError(t, err)
	require.Equal(t, statuses, retrieved)
}

func TestStoreChainStatus_HappyPath_MultipleChainStatuses_MissingStatus(t *testing.T) {
	storage, cleanup := setupTestChainStatusDB(t)
	defer cleanup()

	ctx := context.Background()
	statuses := map[uint64]*common.ChainStatus{
		1: {FinalizedBlockHeight: 100, Disabled: false},
		2: {FinalizedBlockHeight: 200, Disabled: false},
		3: {FinalizedBlockHeight: 300, Disabled: false},
	}

	err := storage.StoreChainStatus(ctx, testClient, statuses)
	require.NoError(t, err)

	retrieved, err := storage.GetClientChainStatus(ctx, testClient, []uint64{100})
	require.NoError(t, err)
	require.Empty(t, retrieved)
}

func TestStoreChainStatus_HappyPath_MultipleChainStatuses_RetrieveSingle(t *testing.T) {
	storage, cleanup := setupTestChainStatusDB(t)
	defer cleanup()

	ctx := context.Background()
	statuses := map[uint64]*common.ChainStatus{
		1: {FinalizedBlockHeight: 100, Disabled: false},
		2: {FinalizedBlockHeight: 200, Disabled: false},
		3: {FinalizedBlockHeight: 300, Disabled: false},
	}

	err := storage.StoreChainStatus(ctx, testClient, statuses)
	require.NoError(t, err)

	retrieved, err := storage.GetClientChainStatus(ctx, testClient, []uint64{1})
	require.NoError(t, err)
	require.Len(t, retrieved, 1)
	require.Equal(t, statuses[1], retrieved[1], "returning only the status queried for")
}

func TestStoreChainStatus_ValidationErrors(t *testing.T) {
	storage, cleanup := setupTestChainStatusDB(t)
	defer cleanup()

	ctx := context.Background()

	tests := []struct {
		name        string
		clientID    string
		statuses    map[uint64]*common.ChainStatus
		expectedErr string
	}{
		{
			name:     "empty client ID",
			clientID: "",
			statuses: map[uint64]*common.ChainStatus{
				1: {FinalizedBlockHeight: 100, Disabled: false},
			},
			expectedErr: "client ID cannot be empty",
		},
		{
			name:     "whitespace client ID",
			clientID: "   ",
			statuses: map[uint64]*common.ChainStatus{
				1: {FinalizedBlockHeight: 100, Disabled: false},
			},
			expectedErr: "client ID cannot be empty",
		},
		{
			name:        "nil statuses",
			clientID:    "test-client",
			statuses:    nil,
			expectedErr: "statuses cannot be nil",
		},
		{
			name:     "zero chain selector",
			clientID: "test-client",
			statuses: map[uint64]*common.ChainStatus{
				0: {FinalizedBlockHeight: 100, Disabled: false},
			},
			expectedErr: "chain_selector must be greater than 0",
		},
		{
			name:     "zero block height",
			clientID: "test-client",
			statuses: map[uint64]*common.ChainStatus{
				1: {FinalizedBlockHeight: 0, Disabled: false},
			},
			expectedErr: "finalized_block_height must be greater than 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := storage.StoreChainStatus(ctx, tt.clientID, tt.statuses)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestStoreChainStatus_OverrideExisting(t *testing.T) {
	storage, cleanup := setupTestChainStatusDB(t)
	defer cleanup()

	ctx := context.Background()
	clientID := "test-client-override"

	initialChainStatuses := map[uint64]*common.ChainStatus{
		1: {FinalizedBlockHeight: 100, Disabled: false},
		2: {FinalizedBlockHeight: 200, Disabled: false},
	}
	err := storage.StoreChainStatus(ctx, clientID, initialChainStatuses)
	require.NoError(t, err)

	updatedChainStatuses := map[uint64]*common.ChainStatus{
		1: {FinalizedBlockHeight: 150, Disabled: false},
		2: {FinalizedBlockHeight: 200, Disabled: false},
	}
	err = storage.StoreChainStatus(ctx, clientID, updatedChainStatuses)
	require.NoError(t, err)

	retrieved, err := storage.GetClientChainStatus(ctx, clientID, nil)
	require.NoError(t, err)
	require.Equal(t, uint64(150), retrieved[1].FinalizedBlockHeight, "chain selector 1 should be updated")
	require.Equal(t, uint64(200), retrieved[2].FinalizedBlockHeight, "chain selector 2 should remain unchanged")
}

func TestStoreChainStatus_PartialOverride(t *testing.T) {
	storage, cleanup := setupTestChainStatusDB(t)
	defer cleanup()

	ctx := context.Background()
	clientID := "test-client-partial"

	initialChainStatuses := map[uint64]*common.ChainStatus{
		1: {FinalizedBlockHeight: 100, Disabled: false},
		2: {FinalizedBlockHeight: 200, Disabled: false},
		3: {FinalizedBlockHeight: 300, Disabled: false},
	}
	err := storage.StoreChainStatus(ctx, clientID, initialChainStatuses)
	require.NoError(t, err)

	partialUpdate := map[uint64]*common.ChainStatus{
		2: {FinalizedBlockHeight: 250, Disabled: false},
	}
	err = storage.StoreChainStatus(ctx, clientID, partialUpdate)
	require.NoError(t, err)

	retrieved, err := storage.GetClientChainStatus(ctx, clientID, nil)
	require.NoError(t, err)
	require.Equal(t, uint64(100), retrieved[1].FinalizedBlockHeight)
	require.Equal(t, uint64(250), retrieved[2].FinalizedBlockHeight)
	require.Equal(t, uint64(300), retrieved[3].FinalizedBlockHeight)
}

func TestGetClientChainStatuses_NotFound(t *testing.T) {
	storage, cleanup := setupTestChainStatusDB(t)
	defer cleanup()

	ctx := context.Background()

	retrieved, err := storage.GetClientChainStatus(ctx, "non-existent-client", nil)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	require.Empty(t, retrieved)
}

func TestGetAllClients_Empty(t *testing.T) {
	storage, cleanup := setupTestChainStatusDB(t)
	defer cleanup()

	ctx := context.Background()

	clients, err := storage.GetAllClients(ctx)
	require.NoError(t, err)
	require.Empty(t, clients)
}

func TestGetAllClients_MultipleClients(t *testing.T) {
	storage, cleanup := setupTestChainStatusDB(t)
	defer cleanup()

	ctx := context.Background()

	clientIDs := []string{"client-a", "client-b", "client-c"}
	for i, clientID := range clientIDs {
		chainStatuses := map[uint64]*common.ChainStatus{
			uint64(i + 1): {FinalizedBlockHeight: uint64((i + 1) * 100), Disabled: false},
		}
		err := storage.StoreChainStatus(ctx, clientID, chainStatuses)
		require.NoError(t, err)
	}

	clients, err := storage.GetAllClients(ctx)
	require.NoError(t, err)
	require.Len(t, clients, 3)
	require.ElementsMatch(t, clientIDs, clients)
}

func TestGetAllClients_Sorted(t *testing.T) {
	storage, cleanup := setupTestChainStatusDB(t)
	defer cleanup()

	ctx := context.Background()

	clientIDs := []string{"zebra", "alpha", "beta"}
	for i, clientID := range clientIDs {
		chainStatuses := map[uint64]*common.ChainStatus{
			uint64(i + 1): {FinalizedBlockHeight: uint64((i + 1) * 100), Disabled: false},
		}
		err := storage.StoreChainStatus(ctx, clientID, chainStatuses)
		require.NoError(t, err)
	}

	clients, err := storage.GetAllClients(ctx)
	require.NoError(t, err)
	require.Equal(t, []string{"alpha", "beta", "zebra"}, clients)
}

func TestConcurrentAccess(t *testing.T) {
	storage, cleanup := setupTestChainStatusDB(t)
	defer cleanup()

	ctx := context.Background()
	numGoroutines := 10
	statusesPerGoroutine := 5

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		clientID := fmt.Sprintf("concurrent-client-%d", i)
		go func(cID string, index int) {
			defer wg.Done()

			chainStatuses := make(map[uint64]*common.ChainStatus)
			for j := 0; j < statusesPerGoroutine; j++ {
				chainSelector := uint64(index*statusesPerGoroutine + j + 1)
				chainStatuses[chainSelector] = &common.ChainStatus{
					FinalizedBlockHeight: uint64((index + 1) * 1000),
					Disabled:             false,
				}
			}

			err := storage.StoreChainStatus(ctx, cID, chainStatuses)
			require.NoError(t, err)

			retrieved, err := storage.GetClientChainStatus(ctx, cID, nil)
			require.NoError(t, err)
			require.Equal(t, chainStatuses, retrieved)
		}(clientID, i)
	}

	wg.Wait()

	clients, err := storage.GetAllClients(ctx)
	require.NoError(t, err)
	require.Len(t, clients, numGoroutines)
}

func TestConcurrentUpdates_SameClient(t *testing.T) {
	storage, cleanup := setupTestChainStatusDB(t)
	defer cleanup()

	ctx := context.Background()
	clientID := "shared-client"
	numGoroutines := 10

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(index int) {
			defer wg.Done()

			chainStatuses := map[uint64]*common.ChainStatus{
				uint64(index + 1): {FinalizedBlockHeight: uint64((index + 1) * 100), Disabled: false},
			}

			err := storage.StoreChainStatus(ctx, clientID, chainStatuses)
			require.NoError(t, err)
		}(i)
	}

	wg.Wait()

	retrieved, err := storage.GetClientChainStatus(ctx, clientID, nil)
	require.NoError(t, err)
	require.Len(t, retrieved, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		chainSelector := uint64(i + 1)
		expectedHeight := uint64((i + 1) * 100)
		require.Equal(t, expectedHeight, retrieved[chainSelector].FinalizedBlockHeight)
	}
}

func TestStoreChainStatus_LargeValues(t *testing.T) {
	storage, cleanup := setupTestChainStatusDB(t)
	defer cleanup()

	ctx := context.Background()
	clientID := "large-values-client"

	chainStatuses := map[uint64]*common.ChainStatus{
		999999999999999: {FinalizedBlockHeight: 999999999999999, Disabled: false},
		1:               {FinalizedBlockHeight: 1, Disabled: false},
	}

	err := storage.StoreChainStatus(ctx, clientID, chainStatuses)
	require.NoError(t, err)

	retrieved, err := storage.GetClientChainStatus(ctx, clientID, nil)
	require.NoError(t, err)
	require.Equal(t, chainStatuses, retrieved)
}

func TestStoreChainStatus_HighBitSetValues(t *testing.T) {
	storage, cleanup := setupTestChainStatusDB(t)
	defer cleanup()

	ctx := context.Background()
	clientID := "high-bit-client"

	chainStatuses := map[uint64]*common.ChainStatus{
		11344663052800119908: {FinalizedBlockHeight: 12345678901234567890, Disabled: false},
		18446744073709551615: {FinalizedBlockHeight: 18446744073709551615, Disabled: false},
	}

	err := storage.StoreChainStatus(ctx, clientID, chainStatuses)
	require.NoError(t, err)

	retrieved, err := storage.GetClientChainStatus(ctx, clientID, nil)
	require.NoError(t, err)
	require.Equal(t, chainStatuses, retrieved)
}
