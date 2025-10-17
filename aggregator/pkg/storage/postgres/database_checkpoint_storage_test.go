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

	_ "github.com/lib/pq"
)

func setupTestCheckpointDB(t *testing.T) (*DatabaseCheckpointStorage, func()) {
	ctx := context.Background()

	postgresContainer, err := postgres.Run(ctx,
		"postgres:15-alpine",
		postgres.WithDatabase("test_checkpoint_db"),
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

	storage := NewDatabaseCheckpointStorage(ds)

	cleanup := func() {
		ds.Close()
		if err := postgresContainer.Terminate(context.Background()); err != nil {
			t.Logf("failed to terminate postgres container: %v", err)
		}
	}

	return storage, cleanup
}

func TestStoreCheckpoints_HappyPath_SingleCheckpoint(t *testing.T) {
	storage, cleanup := setupTestCheckpointDB(t)
	defer cleanup()

	ctx := context.Background()
	clientID := "test-client-1"
	checkpoints := map[uint64]uint64{
		1: 100,
	}

	err := storage.StoreCheckpoints(ctx, clientID, checkpoints)
	require.NoError(t, err)

	retrieved, err := storage.GetClientCheckpoints(ctx, clientID)
	require.NoError(t, err)
	require.Equal(t, checkpoints, retrieved)
}

func TestStoreCheckpoints_HappyPath_MultipleCheckpoints(t *testing.T) {
	storage, cleanup := setupTestCheckpointDB(t)
	defer cleanup()

	ctx := context.Background()
	clientID := "test-client-2"
	checkpoints := map[uint64]uint64{
		1: 100,
		2: 200,
		3: 300,
	}

	err := storage.StoreCheckpoints(ctx, clientID, checkpoints)
	require.NoError(t, err)

	retrieved, err := storage.GetClientCheckpoints(ctx, clientID)
	require.NoError(t, err)
	require.Equal(t, checkpoints, retrieved)
}

func TestStoreCheckpoints_ValidationErrors(t *testing.T) {
	storage, cleanup := setupTestCheckpointDB(t)
	defer cleanup()

	ctx := context.Background()

	tests := []struct {
		name        string
		clientID    string
		checkpoints map[uint64]uint64
		expectedErr string
	}{
		{
			name:        "empty client ID",
			clientID:    "",
			checkpoints: map[uint64]uint64{1: 100},
			expectedErr: "client ID cannot be empty",
		},
		{
			name:        "whitespace client ID",
			clientID:    "   ",
			checkpoints: map[uint64]uint64{1: 100},
			expectedErr: "client ID cannot be empty",
		},
		{
			name:        "nil checkpoints",
			clientID:    "test-client",
			checkpoints: nil,
			expectedErr: "checkpoints cannot be nil",
		},
		{
			name:     "zero chain selector",
			clientID: "test-client",
			checkpoints: map[uint64]uint64{
				0: 100,
			},
			expectedErr: "chain_selector must be greater than 0",
		},
		{
			name:     "zero block height",
			clientID: "test-client",
			checkpoints: map[uint64]uint64{
				1: 0,
			},
			expectedErr: "finalized_block_height must be greater than 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := storage.StoreCheckpoints(ctx, tt.clientID, tt.checkpoints)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestStoreCheckpoints_OverrideExisting(t *testing.T) {
	storage, cleanup := setupTestCheckpointDB(t)
	defer cleanup()

	ctx := context.Background()
	clientID := "test-client-override"

	initialCheckpoints := map[uint64]uint64{
		1: 100,
		2: 200,
	}
	err := storage.StoreCheckpoints(ctx, clientID, initialCheckpoints)
	require.NoError(t, err)

	updatedCheckpoints := map[uint64]uint64{
		1: 150,
		2: 200,
	}
	err = storage.StoreCheckpoints(ctx, clientID, updatedCheckpoints)
	require.NoError(t, err)

	retrieved, err := storage.GetClientCheckpoints(ctx, clientID)
	require.NoError(t, err)
	require.Equal(t, uint64(150), retrieved[1], "chain selector 1 should be updated")
	require.Equal(t, uint64(200), retrieved[2], "chain selector 2 should remain unchanged")
}

func TestStoreCheckpoints_PartialOverride(t *testing.T) {
	storage, cleanup := setupTestCheckpointDB(t)
	defer cleanup()

	ctx := context.Background()
	clientID := "test-client-partial"

	initialCheckpoints := map[uint64]uint64{
		1: 100,
		2: 200,
		3: 300,
	}
	err := storage.StoreCheckpoints(ctx, clientID, initialCheckpoints)
	require.NoError(t, err)

	partialUpdate := map[uint64]uint64{
		2: 250,
	}
	err = storage.StoreCheckpoints(ctx, clientID, partialUpdate)
	require.NoError(t, err)

	retrieved, err := storage.GetClientCheckpoints(ctx, clientID)
	require.NoError(t, err)
	require.Equal(t, uint64(100), retrieved[1])
	require.Equal(t, uint64(250), retrieved[2])
	require.Equal(t, uint64(300), retrieved[3])
}

func TestGetClientCheckpoints_NotFound(t *testing.T) {
	storage, cleanup := setupTestCheckpointDB(t)
	defer cleanup()

	ctx := context.Background()

	retrieved, err := storage.GetClientCheckpoints(ctx, "non-existent-client")
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	require.Empty(t, retrieved)
}

func TestGetAllClients_Empty(t *testing.T) {
	storage, cleanup := setupTestCheckpointDB(t)
	defer cleanup()

	ctx := context.Background()

	clients, err := storage.GetAllClients(ctx)
	require.NoError(t, err)
	require.Empty(t, clients)
}

func TestGetAllClients_MultipleClients(t *testing.T) {
	storage, cleanup := setupTestCheckpointDB(t)
	defer cleanup()

	ctx := context.Background()

	clientIDs := []string{"client-a", "client-b", "client-c"}
	for i, clientID := range clientIDs {
		checkpoints := map[uint64]uint64{
			uint64(i + 1): uint64((i + 1) * 100),
		}
		err := storage.StoreCheckpoints(ctx, clientID, checkpoints)
		require.NoError(t, err)
	}

	clients, err := storage.GetAllClients(ctx)
	require.NoError(t, err)
	require.Len(t, clients, 3)
	require.ElementsMatch(t, clientIDs, clients)
}

func TestGetAllClients_Sorted(t *testing.T) {
	storage, cleanup := setupTestCheckpointDB(t)
	defer cleanup()

	ctx := context.Background()

	clientIDs := []string{"zebra", "alpha", "beta"}
	for i, clientID := range clientIDs {
		checkpoints := map[uint64]uint64{
			uint64(i + 1): uint64((i + 1) * 100),
		}
		err := storage.StoreCheckpoints(ctx, clientID, checkpoints)
		require.NoError(t, err)
	}

	clients, err := storage.GetAllClients(ctx)
	require.NoError(t, err)
	require.Equal(t, []string{"alpha", "beta", "zebra"}, clients)
}

func TestConcurrentAccess(t *testing.T) {
	storage, cleanup := setupTestCheckpointDB(t)
	defer cleanup()

	ctx := context.Background()
	numGoroutines := 10
	checkpointsPerGoroutine := 5

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		clientID := fmt.Sprintf("concurrent-client-%d", i)
		go func(cID string, index int) {
			defer wg.Done()

			checkpoints := make(map[uint64]uint64)
			for j := 0; j < checkpointsPerGoroutine; j++ {
				chainSelector := uint64(index*checkpointsPerGoroutine + j + 1)
				checkpoints[chainSelector] = uint64((index + 1) * 1000)
			}

			err := storage.StoreCheckpoints(ctx, cID, checkpoints)
			require.NoError(t, err)

			retrieved, err := storage.GetClientCheckpoints(ctx, cID)
			require.NoError(t, err)
			require.Equal(t, checkpoints, retrieved)
		}(clientID, i)
	}

	wg.Wait()

	clients, err := storage.GetAllClients(ctx)
	require.NoError(t, err)
	require.Len(t, clients, numGoroutines)
}

func TestConcurrentUpdates_SameClient(t *testing.T) {
	storage, cleanup := setupTestCheckpointDB(t)
	defer cleanup()

	ctx := context.Background()
	clientID := "shared-client"
	numGoroutines := 10

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(index int) {
			defer wg.Done()

			checkpoints := map[uint64]uint64{
				uint64(index + 1): uint64((index + 1) * 100),
			}

			err := storage.StoreCheckpoints(ctx, clientID, checkpoints)
			require.NoError(t, err)
		}(i)
	}

	wg.Wait()

	retrieved, err := storage.GetClientCheckpoints(ctx, clientID)
	require.NoError(t, err)
	require.Len(t, retrieved, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		chainSelector := uint64(i + 1)
		expectedHeight := uint64((i + 1) * 100)
		require.Equal(t, expectedHeight, retrieved[chainSelector])
	}
}

func TestStoreCheckpoints_LargeValues(t *testing.T) {
	storage, cleanup := setupTestCheckpointDB(t)
	defer cleanup()

	ctx := context.Background()
	clientID := "large-values-client"

	checkpoints := map[uint64]uint64{
		999999999999999: 999999999999999,
		1:               1,
	}

	err := storage.StoreCheckpoints(ctx, clientID, checkpoints)
	require.NoError(t, err)

	retrieved, err := storage.GetClientCheckpoints(ctx, clientID)
	require.NoError(t, err)
	require.Equal(t, checkpoints, retrieved)
}

func TestStoreCheckpoints_HighBitSetValues(t *testing.T) {
	storage, cleanup := setupTestCheckpointDB(t)
	defer cleanup()

	ctx := context.Background()
	clientID := "high-bit-client"

	checkpoints := map[uint64]uint64{
		11344663052800119908: 12345678901234567890,
		18446744073709551615: 18446744073709551615,
	}

	err := storage.StoreCheckpoints(ctx, clientID, checkpoints)
	require.NoError(t, err)

	retrieved, err := storage.GetClientCheckpoints(ctx, clientID)
	require.NoError(t, err)
	require.Equal(t, checkpoints, retrieved)
}
