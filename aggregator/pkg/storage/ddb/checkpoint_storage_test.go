package ddb

import (
	"context"
	"strconv"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/stretchr/testify/require"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/testcontainers/testcontainers-go"
	dynamodbcontainer "github.com/testcontainers/testcontainers-go/modules/dynamodb"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	testCheckpointTableName = "checkpoint_test_table"
)

// setupTestDynamoDB creates a test DynamoDB container and client for checkpoint tests.
func setupTestDynamoDB(t *testing.T) (*dynamodb.Client, func()) {
	ctx := context.Background()

	// Start DynamoDB Local container
	dynamoContainer, err := dynamodbcontainer.Run(ctx, "amazon/dynamodb-local:2.2.1", testcontainers.WithWaitStrategy(wait.ForHTTP("/").WithStatusCodeMatcher(func(status int) bool {
		return status == 400
	})))
	require.NoError(t, err, "failed to start DynamoDB container")

	// Get connection string
	connectionString, err := dynamoContainer.ConnectionString(ctx)
	require.NoError(t, err, "failed to get connection string")

	// Create AWS config for testing
	awsConfig, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "test")),
	)
	require.NoError(t, err, "failed to load AWS config")

	// Create DynamoDB client
	client := dynamodb.NewFromConfig(awsConfig, func(o *dynamodb.Options) {
		o.BaseEndpoint = aws.String("http://" + connectionString)
	})

	// Create the checkpoint table
	err = CreateCheckpointTable(ctx, client, testCheckpointTableName)
	require.NoError(t, err, "failed to create checkpoint table")

	// Return client and cleanup function
	cleanup := func() {
		if err := dynamoContainer.Terminate(context.Background()); err != nil {
			t.Errorf("failed to terminate DynamoDB container: %v", err)
		}
	}

	return client, cleanup
}

// TestCheckpointStorage tests all checkpoint storage operations with shared DynamoDB infrastructure.
func TestCheckpointStorage(t *testing.T) {
	client, cleanup := setupTestDynamoDB(t)
	defer cleanup()

	storage := NewCheckpointStorage(client, testCheckpointTableName)
	ctx := context.Background()

	t.Run("Basic", func(t *testing.T) {
		t.Run("new_storage_has_no_clients", func(t *testing.T) {
			clients, err := storage.GetAllClients(ctx)
			require.NoError(t, err)
			require.Empty(t, clients)
		})

		t.Run("non_existent_client_returns_empty", func(t *testing.T) {
			checkpoints, err := storage.GetClientCheckpoints(ctx, "basic-non-existent-client")
			require.NoError(t, err)
			require.Empty(t, checkpoints)
		})
	})

	t.Run("StoreAndRetrieve", func(t *testing.T) {
		t.Run("store_single_checkpoint", func(t *testing.T) {
			clientID := "store-client-1"
			checkpoints := map[uint64]uint64{
				1: 100, // chain_selector -> block_height
			}

			err := storage.StoreCheckpoints(ctx, clientID, checkpoints)
			require.NoError(t, err)

			// Retrieve and verify
			result, err := storage.GetClientCheckpoints(ctx, clientID)
			require.NoError(t, err)
			require.Equal(t, checkpoints, result)

			// Verify client appears in all clients list
			clients, err := storage.GetAllClients(ctx)
			require.NoError(t, err)
			require.Contains(t, clients, clientID)
		})

		t.Run("store_multiple_checkpoints", func(t *testing.T) {
			clientID := "store-client-2"
			checkpoints := map[uint64]uint64{
				1: 100,
				2: 200,
				5: 500,
			}

			err := storage.StoreCheckpoints(ctx, clientID, checkpoints)
			require.NoError(t, err)

			// Retrieve and verify
			result, err := storage.GetClientCheckpoints(ctx, clientID)
			require.NoError(t, err)
			require.Equal(t, checkpoints, result)
		})

		t.Run("override_existing_checkpoint", func(t *testing.T) {
			clientID := "store-client-3"

			// Store initial checkpoint
			initial := map[uint64]uint64{1: 100}
			err := storage.StoreCheckpoints(ctx, clientID, initial)
			require.NoError(t, err)

			// Override with new value
			updated := map[uint64]uint64{1: 200}
			err = storage.StoreCheckpoints(ctx, clientID, updated)
			require.NoError(t, err)

			// Verify the new value
			result, err := storage.GetClientCheckpoints(ctx, clientID)
			require.NoError(t, err)
			require.Equal(t, updated, result)
		})

		t.Run("add_to_existing_checkpoints", func(t *testing.T) {
			clientID := "store-client-4"

			// Store initial checkpoints
			initial := map[uint64]uint64{1: 100, 2: 200}
			err := storage.StoreCheckpoints(ctx, clientID, initial)
			require.NoError(t, err)

			// Add new checkpoint
			additional := map[uint64]uint64{3: 300}
			err = storage.StoreCheckpoints(ctx, clientID, additional)
			require.NoError(t, err)

			// Verify all checkpoints exist
			result, err := storage.GetClientCheckpoints(ctx, clientID)
			require.NoError(t, err)
			expected := map[uint64]uint64{1: 100, 2: 200, 3: 300}
			require.Equal(t, expected, result)
		})
	})

	t.Run("ClientIsolation", func(t *testing.T) {
		client1 := "isolation-client-1"
		client2 := "isolation-client-2"

		// Store different checkpoints for each client
		checkpoints1 := map[uint64]uint64{1: 1000, 2: 2000}
		checkpoints2 := map[uint64]uint64{1: 1500, 3: 3000} // Same chain 1, different value

		err := storage.StoreCheckpoints(ctx, client1, checkpoints1)
		require.NoError(t, err)

		err = storage.StoreCheckpoints(ctx, client2, checkpoints2)
		require.NoError(t, err)

		// Verify client 1 sees only their data
		result1, err := storage.GetClientCheckpoints(ctx, client1)
		require.NoError(t, err)
		require.Equal(t, checkpoints1, result1)

		// Verify client 2 sees only their data
		result2, err := storage.GetClientCheckpoints(ctx, client2)
		require.NoError(t, err)
		require.Equal(t, checkpoints2, result2)

		// Verify both clients appear in all clients list
		clients, err := storage.GetAllClients(ctx)
		require.NoError(t, err)
		require.Contains(t, clients, client1)
		require.Contains(t, clients, client2)
		require.GreaterOrEqual(t, len(clients), 2) // At least these 2, may have more from other tests
	})

	t.Run("Validation", func(t *testing.T) {
		t.Run("empty_client_id_fails", func(t *testing.T) {
			checkpoints := map[uint64]uint64{1: 100}
			err := storage.StoreCheckpoints(ctx, "", checkpoints)
			require.Error(t, err)
			require.Contains(t, err.Error(), "client ID cannot be empty")

			_, err = storage.GetClientCheckpoints(ctx, "")
			require.Error(t, err)
			require.Contains(t, err.Error(), "client ID cannot be empty")
		})

		t.Run("nil_checkpoints_fails", func(t *testing.T) {
			err := storage.StoreCheckpoints(ctx, "validation-client", nil)
			require.Error(t, err)
			require.Contains(t, err.Error(), "checkpoints cannot be nil")
		})

		t.Run("zero_chain_selector_fails", func(t *testing.T) {
			checkpoints := map[uint64]uint64{0: 100}
			err := storage.StoreCheckpoints(ctx, "validation-client", checkpoints)
			require.Error(t, err)
			require.Contains(t, err.Error(), "chain_selector must be greater than 0")
		})

		t.Run("zero_block_height_fails", func(t *testing.T) {
			checkpoints := map[uint64]uint64{1: 0}
			err := storage.StoreCheckpoints(ctx, "validation-client", checkpoints)
			require.Error(t, err)
			require.Contains(t, err.Error(), "finalized_block_height must be greater than 0")
		})
	})

	t.Run("ManyClients", func(t *testing.T) {
		numClients := 50
		chainSelector := uint64(42)

		// Store checkpoints for many clients
		for i := 0; i < numClients; i++ {
			clientID := "many-client-" + strconv.Itoa(i)
			checkpoints := map[uint64]uint64{
				chainSelector: uint64((i + 1) * 100),
			}

			err := storage.StoreCheckpoints(ctx, clientID, checkpoints)
			require.NoError(t, err, "failed to store checkpoints for client %d", i)
		}

		// Verify each client has their own data
		for i := 0; i < numClients; i++ {
			clientID := "many-client-" + strconv.Itoa(i)
			result, err := storage.GetClientCheckpoints(ctx, clientID)
			require.NoError(t, err, "failed to get checkpoints for client %d", i)

			expected := map[uint64]uint64{chainSelector: uint64((i + 1) * 100)}
			require.Equal(t, expected, result, "client %d should have correct checkpoints", i)
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
		err := storage.StoreCheckpoints(ctx, "empty-client", map[uint64]uint64{})
		require.NoError(t, err)

		// Client should not appear in all clients list
		clients, err := storage.GetAllClients(ctx)
		require.NoError(t, err)
		require.NotContains(t, clients, "empty-client")

		// Getting checkpoints should return empty map
		result, err := storage.GetClientCheckpoints(ctx, "empty-client")
		require.NoError(t, err)
		require.Empty(t, result)
	})

	t.Run("LargeValues", func(t *testing.T) {
		clientID := "large-values-client"
		checkpoints := map[uint64]uint64{
			18446744073709551615: 18446744073709551615, // Max uint64 values
			1000000000000:        1000000000000,        // Large but realistic values
		}

		err := storage.StoreCheckpoints(ctx, clientID, checkpoints)
		require.NoError(t, err)

		result, err := storage.GetClientCheckpoints(ctx, clientID)
		require.NoError(t, err)
		require.Equal(t, checkpoints, result)
	})
}
