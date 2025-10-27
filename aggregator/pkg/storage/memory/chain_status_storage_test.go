package memory

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestChainStatusStorage tests the ChainStatusStorage implementation.
func TestChainStatusStorage(t *testing.T) {
	t.Run("new_storage_is_empty", func(t *testing.T) {
		storage := NewChainStatusStorage()
		require.NotNil(t, storage, "storage should not be nil")

		statuses, _ := storage.GetClientChainStatus(t.Context(), "test-client")
		require.Empty(t, statuses, "new storage should be empty")
	})

	t.Run("store_single_checkpoint", func(t *testing.T) {
		storage := NewChainStatusStorage()

		statuses := map[uint64]uint64{
			1: 100, // chain_selector -> block_height
		}

		err := storage.StoreChainStatus(t.Context(), "test-client", statuses)
		require.NoError(t, err, "storing statuses should not error")

		result, _ := storage.GetClientChainStatus(t.Context(), "test-client")
		require.Equal(t, statuses, result, "stored statuses should match retrieved")
	})

	t.Run("store_multiple_statuses", func(t *testing.T) {
		storage := NewChainStatusStorage()

		statuses := map[uint64]uint64{
			1: 100,
			2: 200,
			5: 500,
		}

		err := storage.StoreChainStatus(t.Context(), "test-client", statuses)
		require.NoError(t, err, "storing multiple statuses should not error")

		result, _ := storage.GetClientChainStatus(t.Context(), "test-client")
		require.Equal(t, statuses, result, "all statuses should be stored")
	})

	t.Run("override_existing_checkpoint", func(t *testing.T) {
		storage := NewChainStatusStorage()

		// Store initial checkpoint
		initial := map[uint64]uint64{1: 100}
		err := storage.StoreChainStatus(t.Context(), "test-client", initial)
		require.NoError(t, err, "initial storage should not error")

		// Override with new value
		override := map[uint64]uint64{1: 200}
		err = storage.StoreChainStatus(t.Context(), "test-client", override)
		require.NoError(t, err, "override should not error")

		result, _ := storage.GetClientChainStatus(t.Context(), "test-client")
		require.Equal(t, uint64(200), result[1], "checkpoint should be overridden")
	})

	t.Run("client_isolation", func(t *testing.T) {
		storage := NewChainStatusStorage()

		// Store data for client 1
		client1Data := map[uint64]uint64{1: 100}
		err := storage.StoreChainStatus(t.Context(), "client-1", client1Data)
		require.NoError(t, err, "client 1 storage should not error")

		// Store data for client 2
		client2Data := map[uint64]uint64{1: 200}
		err = storage.StoreChainStatus(t.Context(), "client-2", client2Data)
		require.NoError(t, err, "client 2 storage should not error")

		// Verify isolation
		result1, _ := storage.GetClientChainStatus(t.Context(), "client-1")
		result2, _ := storage.GetClientChainStatus(t.Context(), "client-2")

		require.Equal(t, client1Data, result1, "client 1 should only see their data")
		require.Equal(t, client2Data, result2, "client 2 should only see their data")
	})

	t.Run("concurrent_access_same_client", func(t *testing.T) {
		storage := NewChainStatusStorage()

		var wg sync.WaitGroup
		numGoroutines := 100

		// Multiple goroutines updating same client concurrently
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				statuses := map[uint64]uint64{
					uint64(index + 1): uint64((index + 1) * 100),
				}
				err := storage.StoreChainStatus(t.Context(), "concurrent-client", statuses)
				require.NoError(t, err, "concurrent storage should not error")
			}(i)
		}

		wg.Wait()

		result, _ := storage.GetClientChainStatus(t.Context(), "concurrent-client")
		require.Len(t, result, numGoroutines, "all concurrent updates should be present")
	})

	t.Run("concurrent_access_different_clients", func(t *testing.T) {
		storage := NewChainStatusStorage()

		var wg sync.WaitGroup
		numClients := 50

		// Multiple clients storing data concurrently
		for i := 0; i < numClients; i++ {
			wg.Add(1)
			go func(clientIndex int) {
				defer wg.Done()
				clientID := "client-" + string(rune('A'+clientIndex))
				statuses := map[uint64]uint64{
					1: uint64((clientIndex + 1) * 100),
				}
				err := storage.StoreChainStatus(t.Context(), clientID, statuses)
				require.NoError(t, err, "concurrent client storage should not error")
			}(i)
		}

		wg.Wait()

		// Verify each client has their data
		for i := 0; i < numClients; i++ {
			clientID := "client-" + string(rune('A'+i))
			result, _ := storage.GetClientChainStatus(t.Context(), clientID)
			expected := uint64((i + 1) * 100)
			require.Equal(t, expected, result[1], "each client should have their own data")
		}
	})

	t.Run("concurrent_read_write", func(t *testing.T) {
		storage := NewChainStatusStorage()

		// Pre-populate some data
		initial := map[uint64]uint64{1: 100}
		err := storage.StoreChainStatus(t.Context(), "rw-client", initial)
		require.NoError(t, err, "initial data should store")

		var wg sync.WaitGroup
		numReaders := 50
		numWriters := 10

		// Concurrent readers
		for i := 0; i < numReaders; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 100; j++ {
					result, _ := storage.GetClientChainStatus(t.Context(), "rw-client")
					require.NotNil(t, result, "read should not return nil")
				}
			}()
		}

		// Concurrent writers
		for i := 0; i < numWriters; i++ {
			wg.Add(1)
			go func(writerIndex int) {
				defer wg.Done()
				for j := 0; j < 10; j++ {
					statuses := map[uint64]uint64{
						uint64(writerIndex + 1): uint64((j + 1) * 10),
					}
					err := storage.StoreChainStatus(t.Context(), "rw-client", statuses)
					require.NoError(t, err, "concurrent write should not error")
				}
			}(i)
		}

		wg.Wait()

		// Final state should be consistent
		result, _ := storage.GetClientChainStatus(t.Context(), "rw-client")
		require.NotEmpty(t, result, "final state should not be empty")
	})

	t.Run("empty_client_id", func(t *testing.T) {
		storage := NewChainStatusStorage()

		statuses := map[uint64]uint64{1: 100}
		err := storage.StoreChainStatus(t.Context(), "", statuses)
		require.Error(t, err, "empty client ID should return error")
		require.Contains(t, err.Error(), "client ID cannot be empty")
	})

	t.Run("nil_statuses", func(t *testing.T) {
		storage := NewChainStatusStorage()

		err := storage.StoreChainStatus(t.Context(), "test-client", nil)
		require.Error(t, err, "nil statuses should return error")
		require.Contains(t, err.Error(), "statuses cannot be nil")
	})

	t.Run("zero_chain_selector_validation", func(t *testing.T) {
		storage := NewChainStatusStorage()

		invalidCheckpoints := map[uint64]uint64{
			0: 100, // Invalid chain selector
		}

		err := storage.StoreChainStatus(t.Context(), "test-client", invalidCheckpoints)
		require.Error(t, err, "zero chain selector should return error")
		require.Contains(t, err.Error(), "chain_selector must be greater than 0")
	})

	t.Run("zero_block_height_validation", func(t *testing.T) {
		storage := NewChainStatusStorage()

		invalidCheckpoints := map[uint64]uint64{
			1: 0, // Invalid block height
		}

		err := storage.StoreChainStatus(t.Context(), "test-client", invalidCheckpoints)
		require.Error(t, err, "zero block height should return error")
		require.Contains(t, err.Error(), "finalized_block_height must be greater than 0")
	})
}

// TestClientCheckpoints tests the ClientCheckpoints struct.
func TestClientCheckpoints(t *testing.T) {
	t.Run("new_client_statuses", func(t *testing.T) {
		client := NewClientChainStatus()
		require.NotNil(t, client, "client statuses should not be nil")
		require.Empty(t, client.GetChainStatus(t.Context()), "new client should have empty statuses")
		require.True(t, client.GetLastUpdated().IsZero(), "last updated should be zero time")
	})

	t.Run("store_and_retrieve", func(t *testing.T) {
		client := NewClientChainStatus()

		statuses := map[uint64]uint64{1: 100, 2: 200}
		client.StoreChainStatus(t.Context(), statuses)

		result := client.GetChainStatus(t.Context())
		require.Equal(t, statuses, result, "stored statuses should match retrieved")
		require.False(t, client.GetLastUpdated().IsZero(), "last updated should be set")
	})

	t.Run("last_updated_changes", func(t *testing.T) {
		client := NewClientChainStatus()

		// Initial store
		client.StoreChainStatus(t.Context(), map[uint64]uint64{1: 100})
		firstUpdate := client.GetLastUpdated()

		// Wait a bit and store again
		time.Sleep(time.Millisecond)
		client.StoreChainStatus(t.Context(), map[uint64]uint64{2: 200})
		secondUpdate := client.GetLastUpdated()

		require.True(t, secondUpdate.After(firstUpdate), "last updated should change")
	})

	t.Run("concurrent_access", func(t *testing.T) {
		client := NewClientChainStatus()

		var wg sync.WaitGroup
		numGoroutines := 100

		// Concurrent store operations
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				statuses := map[uint64]uint64{
					uint64(index): uint64(index * 100),
				}
				client.StoreChainStatus(t.Context(), statuses)
			}(i)
		}

		wg.Wait()

		result := client.GetChainStatus(t.Context())
		require.Len(t, result, numGoroutines, "all concurrent stores should be present")
	})
}
