package ddb

import (
	"context"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/monitoring"
)

// TestChainStatusStorage tests all checkpoint storage operations with shared DynamoDB infrastructure.
func TestChainStatusStorage(t *testing.T) {
	client, _, cleanup := SetupTestDynamoDB(t)
	defer cleanup()

	storage := NewChainStatusStorage(client, TestChainStatusTableName, monitoring.NewNoopAggregatorMonitoring())
	ctx := context.Background()

	t.Run("Basic", func(t *testing.T) {
		t.Run("new_storage_has_no_clients", func(t *testing.T) {
			clients, err := storage.GetAllClients(ctx)
			require.NoError(t, err)
			require.Empty(t, clients)
		})

		t.Run("non_existent_client_returns_empty", func(t *testing.T) {
			statuses, err := storage.GetClientChainStatus(ctx, "basic-non-existent-client")
			require.NoError(t, err)
			require.Empty(t, statuses)
		})
	})

	t.Run("StoreAndRetrieve", func(t *testing.T) {
		t.Run("store_single_checkpoint", func(t *testing.T) {
			clientID := "store-client-1"
			statuses := map[uint64]uint64{
				1: 100, // chain_selector -> block_height
			}

			err := storage.StoreChainStatus(ctx, clientID, statuses)
			require.NoError(t, err)

			// Retrieve and verify
			result, err := storage.GetClientChainStatus(ctx, clientID)
			require.NoError(t, err)
			require.Equal(t, statuses, result)

			// Verify client appears in all clients list
			clients, err := storage.GetAllClients(ctx)
			require.NoError(t, err)
			require.Contains(t, clients, clientID)
		})

		t.Run("store_multiple_statuses", func(t *testing.T) {
			clientID := "store-client-2"
			statuses := map[uint64]uint64{
				1: 100,
				2: 200,
				5: 500,
			}

			err := storage.StoreChainStatus(ctx, clientID, statuses)
			require.NoError(t, err)

			// Retrieve and verify
			result, err := storage.GetClientChainStatus(ctx, clientID)
			require.NoError(t, err)
			require.Equal(t, statuses, result)
		})

		t.Run("override_existing_checkpoint", func(t *testing.T) {
			clientID := "store-client-3"

			// Store initial checkpoint
			initial := map[uint64]uint64{1: 100}
			err := storage.StoreChainStatus(ctx, clientID, initial)
			require.NoError(t, err)

			// Override with new value
			updated := map[uint64]uint64{1: 200}
			err = storage.StoreChainStatus(ctx, clientID, updated)
			require.NoError(t, err)

			// Verify the new value
			result, err := storage.GetClientChainStatus(ctx, clientID)
			require.NoError(t, err)
			require.Equal(t, updated, result)
		})

		t.Run("add_to_existing_statuses", func(t *testing.T) {
			clientID := "store-client-4"

			// Store initial statuses
			initial := map[uint64]uint64{1: 100, 2: 200}
			err := storage.StoreChainStatus(ctx, clientID, initial)
			require.NoError(t, err)

			// Add new checkpoint
			additional := map[uint64]uint64{3: 300}
			err = storage.StoreChainStatus(ctx, clientID, additional)
			require.NoError(t, err)

			// Verify all statuses exist
			result, err := storage.GetClientChainStatus(ctx, clientID)
			require.NoError(t, err)
			expected := map[uint64]uint64{1: 100, 2: 200, 3: 300}
			require.Equal(t, expected, result)
		})
	})

	t.Run("ClientIsolation", func(t *testing.T) {
		client1 := "isolation-client-1"
		client2 := "isolation-client-2"

		// Store different statuses for each client
		statuses1 := map[uint64]uint64{1: 1000, 2: 2000}
		statuses2 := map[uint64]uint64{1: 1500, 3: 3000} // Same chain 1, different value

		err := storage.StoreChainStatus(ctx, client1, statuses1)
		require.NoError(t, err)

		err = storage.StoreChainStatus(ctx, client2, statuses2)
		require.NoError(t, err)

		// Verify client 1 sees only their data
		result1, err := storage.GetClientChainStatus(ctx, client1)
		require.NoError(t, err)
		require.Equal(t, statuses1, result1)

		// Verify client 2 sees only their data
		result2, err := storage.GetClientChainStatus(ctx, client2)
		require.NoError(t, err)
		require.Equal(t, statuses2, result2)

		// Verify both clients appear in all clients list
		clients, err := storage.GetAllClients(ctx)
		require.NoError(t, err)
		require.Contains(t, clients, client1)
		require.Contains(t, clients, client2)
		require.GreaterOrEqual(t, len(clients), 2) // At least these 2, may have more from other tests
	})

	t.Run("Validation", func(t *testing.T) {
		t.Run("empty_client_id_fails", func(t *testing.T) {
			statuses := map[uint64]uint64{1: 100}
			err := storage.StoreChainStatus(ctx, "", statuses)
			require.Error(t, err)
			require.Contains(t, err.Error(), "client ID cannot be empty")

			_, err = storage.GetClientChainStatus(ctx, "")
			require.Error(t, err)
			require.Contains(t, err.Error(), "client ID cannot be empty")
		})

		t.Run("nil_statuses_fails", func(t *testing.T) {
			err := storage.StoreChainStatus(ctx, "validation-client", nil)
			require.Error(t, err)
			require.Contains(t, err.Error(), "statuses cannot be nil")
		})

		t.Run("zero_chain_selector_fails", func(t *testing.T) {
			statuses := map[uint64]uint64{0: 100}
			err := storage.StoreChainStatus(ctx, "validation-client", statuses)
			require.Error(t, err)
			require.Contains(t, err.Error(), "chain_selector must be greater than 0")
		})

		t.Run("zero_block_height_fails", func(t *testing.T) {
			statuses := map[uint64]uint64{1: 0}
			err := storage.StoreChainStatus(ctx, "validation-client", statuses)
			require.Error(t, err)
			require.Contains(t, err.Error(), "finalized_block_height must be greater than 0")
		})
	})

	t.Run("ManyClients", func(t *testing.T) {
		numClients := 50
		chainSelector := uint64(42)

		// Store statuses for many clients
		for i := 0; i < numClients; i++ {
			clientID := "many-client-" + strconv.Itoa(i)
			statuses := map[uint64]uint64{
				chainSelector: uint64((i + 1) * 100),
			}

			err := storage.StoreChainStatus(ctx, clientID, statuses)
			require.NoError(t, err, "failed to store statuses for client %d", i)
		}

		// Verify each client has their own data
		for i := 0; i < numClients; i++ {
			clientID := "many-client-" + strconv.Itoa(i)
			result, err := storage.GetClientChainStatus(ctx, clientID)
			require.NoError(t, err, "failed to get statuses for client %d", i)

			expected := map[uint64]uint64{chainSelector: uint64((i + 1) * 100)}
			require.Equal(t, expected, result, "client %d should have correct statuses", i)
		}

		// Verify all clients appear in the clients list
		clients, err := storage.GetAllClients(ctx)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(clients), numClients) // At least these clients, may have more from other tests

		// Verify all expected client IDs are present
		clientSet := make(map[string]bool)
		for _, clientID := range clients {
			clientSet[clientID] = true
		}

		for i := 0; i < numClients; i++ {
			expectedClientID := "many-client-" + strconv.Itoa(i)
			require.True(t, clientSet[expectedClientID], "client %s should be in clients list", expectedClientID)
		}
	})

	t.Run("EmptyBatch", func(t *testing.T) {
		// Empty map should succeed (no-op)
		err := storage.StoreChainStatus(ctx, "empty-client", map[uint64]uint64{})
		require.NoError(t, err)

		// Client should not appear in all clients list
		clients, err := storage.GetAllClients(ctx)
		require.NoError(t, err)
		require.NotContains(t, clients, "empty-client")

		// Getting statuses should return empty map
		result, err := storage.GetClientChainStatus(ctx, "empty-client")
		require.NoError(t, err)
		require.Empty(t, result)
	})

	t.Run("LargeValues", func(t *testing.T) {
		clientID := "large-values-client"
		statuses := map[uint64]uint64{
			18446744073709551615: 18446744073709551615, // Max uint64 values
			1000000000000:        1000000000000,        // Large but realistic values
		}

		err := storage.StoreChainStatus(ctx, clientID, statuses)
		require.NoError(t, err)

		result, err := storage.GetClientChainStatus(ctx, clientID)
		require.NoError(t, err)
		require.Equal(t, statuses, result)
	})
}
