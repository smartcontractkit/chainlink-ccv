// Package tests contains integration tests for the aggregator service.
package tests

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

func WithChainStatusTestClients() ConfigOption {
	return func(cfg *model.AggregatorConfig, clientCfg *ClientConfig) (*model.AggregatorConfig, *ClientConfig) {
		testClients := []string{
			"isolation-client-1", "isolation-client-2", "isolation-client-3",
			"update-client-A", "update-client-B",
			"concurrent-client",
			"ddb-isolation-client-1", "ddb-isolation-client-2",
			"ddb-concurrent-client",
			"read-write-client",
			"high-freq-client",
		}

		// Add admin test clients
		adminClients := []string{
			"admin-client-1", "admin-client-2",
		}

		// Add regular verifier clients for admin tests
		verifierClients := []string{
			"verifier-client-1", "verifier-client-2", "verifier-client-3",
		}

		// Add clients for "same_chain_different_clients" test (10 clients A-J)
		for i := 0; i < 10; i++ {
			clientID := "same-chain-client-" + string(rune('A'+i))
			testClients = append(testClients, clientID)
		}

		// Add clients for "concurrent_writes_different_clients" test (50 clients with AA, AB, etc. pattern)
		for i := 0; i < 50; i++ {
			clientID := "concurrent-client-" + string(rune('A'+i%26)) + string(rune('A'+i/26))
			testClients = append(testClients, clientID)
		}

		// Add clients for "concurrent_access" test (100 clients)
		for i := 0; i < 100; i++ {
			clientID := fmt.Sprintf("concurrent-stress-client-%d", i)
			testClients = append(testClients, clientID)
		}

		// Initialize APIClients metadata map
		if cfg.APIClients == nil {
			cfg.APIClients = make(map[string]*model.APIClientMetadata)
		}

		// Configure metadata for regular test clients
		for _, clientID := range testClients {
			cfg.APIClients[clientID] = &model.APIClientMetadata{
				Description: "Test client for " + clientID,
				Groups:      []string{},
				Enabled:     true,
				Admin:       false,
			}
		}

		// Configure metadata for admin clients
		for _, clientID := range adminClients {
			cfg.APIClients[clientID] = &model.APIClientMetadata{
				Description: "Admin test client for " + clientID,
				Groups:      []string{},
				Enabled:     true,
				Admin:       true,
			}
		}

		// Configure metadata for verifier clients
		for _, clientID := range verifierClients {
			cfg.APIClients[clientID] = &model.APIClientMetadata{
				Description: "Verifier test client for " + clientID,
				Groups:      []string{"verifiers"},
				Enabled:     true,
				Admin:       false,
			}
		}

		// Configure regular test clients
		for _, clientID := range testClients {
			apiKey := "key-" + clientID
			secret := "secret-" + clientID
			cfg.APIKeys.Clients[clientID] = &model.APIClient{
				ClientID:    clientID,
				Description: "Test client for " + clientID,
				Enabled:     true,
				IsAdmin:     false,
				APIKeys: map[string]string{
					apiKey: secret,
				},
			}
		}

		// Configure admin clients
		for _, clientID := range adminClients {
			apiKey := "key-" + clientID
			secret := "secret-" + clientID
			cfg.APIKeys.Clients[clientID] = &model.APIClient{
				ClientID:    clientID,
				Description: "Admin test client for " + clientID,
				Enabled:     true,
				IsAdmin:     true,
				APIKeys: map[string]string{
					apiKey: secret,
				},
			}
		}

		// Configure verifier clients for admin tests
		for _, clientID := range verifierClients {
			apiKey := "key-" + clientID
			secret := "secret-" + clientID
			cfg.APIKeys.Clients[clientID] = &model.APIClient{
				ClientID:    clientID,
				Description: "Verifier test client for " + clientID,
				Enabled:     true,
				IsAdmin:     false,
				APIKeys: map[string]string{
					apiKey: secret,
				},
			}
		}

		return cfg, clientCfg
	}
}

// TestChainStatusClientIsolation tests that clients can't access each other's data.
func TestChainStatusClientIsolation(t *testing.T) {
	t.Run("different_clients_isolated_data", func(t *testing.T) {
		// Setup server
		listener, cleanup, err := CreateServerOnly(t, WithChainStatusTestClients())
		require.NoError(t, err, "failed to create test server")
		defer cleanup()

		// Create separate clients with different credentials
		client1, _, cleanup1 := CreateAuthenticatedClient(t, listener, WithClientAuth("isolation-client-1", "secret-isolation-client-1"))
		defer cleanup1()

		client2, _, cleanup2 := CreateAuthenticatedClient(t, listener, WithClientAuth("isolation-client-2", "secret-isolation-client-2"))
		defer cleanup2()

		client3, _, cleanup3 := CreateAuthenticatedClient(t, listener, WithClientAuth("isolation-client-3", "secret-isolation-client-3"))
		defer cleanup3()

		// Client 1 stores chain status
		writeReq1 := &pb.WriteChainStatusRequest{
			Statuses: []*pb.ChainStatus{
				{ChainSelector: 1, FinalizedBlockHeight: 1000, Disabled: false},
				{ChainSelector: 2, FinalizedBlockHeight: 2000, Disabled: false},
			},
		}
		_, err = client1.WriteChainStatus(context.Background(), writeReq1)
		require.NoError(t, err, "client 1 write should succeed")

		// Client 2 stores different statuses
		writeReq2 := &pb.WriteChainStatusRequest{
			Statuses: []*pb.ChainStatus{
				{ChainSelector: 1, FinalizedBlockHeight: 1500, Disabled: false}, // Same chain, different value
				{ChainSelector: 3, FinalizedBlockHeight: 3000, Disabled: false},
			},
		}
		_, err = client2.WriteChainStatus(context.Background(), writeReq2)
		require.NoError(t, err, "client 2 write should succeed")

		// Client 3 has no data stored

		// Verify client 1 sees only their data
		resp1, err := client1.ReadChainStatus(context.Background(), &pb.ReadChainStatusRequest{})
		require.NoError(t, err, "client 1 read should succeed")
		require.Len(t, resp1.Statuses, 2, "client 1 should see 2 chain statuses")

		client1Data := make(map[uint64]uint64)
		for _, cp := range resp1.Statuses {
			client1Data[cp.ChainSelector] = cp.FinalizedBlockHeight
		}
		require.Equal(t, uint64(1000), client1Data[1], "client 1 should see their chain 1 value")
		require.Equal(t, uint64(2000), client1Data[2], "client 1 should see their chain 2 value")

		// Verify client 2 sees only their data
		resp2, err := client2.ReadChainStatus(context.Background(), &pb.ReadChainStatusRequest{})
		require.NoError(t, err, "client 2 read should succeed")
		require.Len(t, resp2.Statuses, 2, "client 2 should see 2 chain statuses")

		client2Data := make(map[uint64]uint64)
		for _, cp := range resp2.Statuses {
			client2Data[cp.ChainSelector] = cp.FinalizedBlockHeight
		}
		require.Equal(t, uint64(1500), client2Data[1], "client 2 should see their chain 1 value")
		require.Equal(t, uint64(3000), client2Data[3], "client 2 should see their chain 3 value")

		// Verify client 3 sees no data
		resp3, err := client3.ReadChainStatus(context.Background(), &pb.ReadChainStatusRequest{})
		require.NoError(t, err, "client 3 read should succeed")
		require.Empty(t, resp3.Statuses, "client 3 should see no chain status")
	})

	t.Run("same_chain_different_clients", func(t *testing.T) {
		// Setup server only
		listener, cleanup, err := CreateServerOnly(t, WithChainStatusTestClients())
		require.NoError(t, err, "failed to create test server")
		defer cleanup()

		numClients := 10
		chainSelector := uint64(42) // All clients use same chain selector

		// Create all clients upfront
		type clientInfo struct {
			client   pb.AggregatorClient
			clientID string
			cleanup  func()
		}
		clients := make([]*clientInfo, numClients)
		for i := 0; i < numClients; i++ {
			clientID := "same-chain-client-" + string(rune('A'+i))
			aggClient, _, clientCleanup := CreateAuthenticatedClient(t, listener, WithClientAuth(clientID, "secret-"+clientID))
			clients[i] = &clientInfo{
				client:   aggClient,
				clientID: clientID,
				cleanup:  clientCleanup,
			}
		}
		// Cleanup all clients at the end
		defer func() {
			for _, c := range clients {
				c.cleanup()
			}
		}()

		// Each client stores their own value for the same chain
		for i := 0; i < numClients; i++ {
			writeReq := &pb.WriteChainStatusRequest{
				Statuses: []*pb.ChainStatus{
					{ChainSelector: chainSelector, FinalizedBlockHeight: uint64((i + 1) * 100)},
				},
			}
			_, err = clients[i].client.WriteChainStatus(context.Background(), writeReq)
			require.NoError(t, err, "client %d write should succeed", i)
		}

		// Verify each client sees only their own value
		for i := 0; i < numClients; i++ {
			resp, err := clients[i].client.ReadChainStatus(context.Background(), &pb.ReadChainStatusRequest{})
			require.NoError(t, err, "client %d read should succeed", i)
			require.Len(t, resp.Statuses, 1, "client %d should see 1 chain status", i)

			chainStatus := resp.Statuses[0]
			require.Equal(t, chainSelector, chainStatus.ChainSelector, "client %d should see correct chain", i)
			require.Equal(t, uint64((i+1)*100), chainStatus.FinalizedBlockHeight, "client %d should see their own value", i)
		}
	})

	t.Run("client_updates_dont_affect_others", func(t *testing.T) {
		// Setup server only
		listener, cleanup, err := CreateServerOnly(t, WithChainStatusTestClients())
		require.NoError(t, err, "failed to create test server")
		defer cleanup()

		// Create two separate clients
		clientA, _, cleanupA := CreateAuthenticatedClient(t, listener, WithClientAuth("update-client-A", "secret-update-client-A"))
		defer cleanupA()
		clientB, _, cleanupB := CreateAuthenticatedClient(t, listener, WithClientAuth("update-client-B", "secret-update-client-B"))
		defer cleanupB()

		// Both clients store initial data
		initialReq := &pb.WriteChainStatusRequest{
			Statuses: []*pb.ChainStatus{
				{ChainSelector: 1, FinalizedBlockHeight: 100, Disabled: false},
			},
		}
		_, err = clientA.WriteChainStatus(context.Background(), initialReq)
		require.NoError(t, err, "client A initial write should succeed")
		_, err = clientB.WriteChainStatus(context.Background(), initialReq)
		require.NoError(t, err, "client B initial write should succeed")

		// Client A updates their data
		updateReq := &pb.WriteChainStatusRequest{
			Statuses: []*pb.ChainStatus{
				{ChainSelector: 1, FinalizedBlockHeight: 200, Disabled: false},
			},
		}
		_, err = clientA.WriteChainStatus(context.Background(), updateReq)
		require.NoError(t, err, "client A update should succeed")

		// Verify client A sees updated data
		respA, err := clientA.ReadChainStatus(context.Background(), &pb.ReadChainStatusRequest{})
		require.NoError(t, err, "client A read should succeed")
		require.Equal(t, uint64(200), respA.Statuses[0].FinalizedBlockHeight, "client A should see updated value")

		// Verify client B still sees original data
		respB, err := clientB.ReadChainStatus(context.Background(), &pb.ReadChainStatusRequest{})
		require.NoError(t, err, "client B read should succeed")
		require.Equal(t, uint64(100), respB.Statuses[0].FinalizedBlockHeight, "client B should see original value")
	})
}

// TestChainStatusConcurrency tests concurrent access to chain status operations.
func TestChainStatusConcurrency(t *testing.T) {
	t.Run("concurrent_writes_same_client", func(t *testing.T) {
		// Setup
		client, _, cleanup, err := CreateServerAndClient(t, WithChainStatusTestClients())
		require.NoError(t, err, "failed to create test server and client")
		defer cleanup()

		ctx := context.Background()
		numGoroutines := 50
		var wg sync.WaitGroup

		// Concurrent writes to same client, different chains
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()

				writeReq := &pb.WriteChainStatusRequest{
					Statuses: []*pb.ChainStatus{
						{
							ChainSelector:        uint64(index + 1),
							FinalizedBlockHeight: uint64((index + 1) * 100),
						},
					},
				}

				_, err := client.WriteChainStatus(ctx, writeReq)
				require.NoError(t, err, "concurrent write %d should succeed", index)
			}(i)
		}

		wg.Wait()

		// Verify all writes succeeded
		resp, err := client.ReadChainStatus(ctx, &pb.ReadChainStatusRequest{})
		require.NoError(t, err, "read after concurrent writes should succeed")
		require.Len(t, resp.Statuses, numGoroutines, "should have all concurrent chain statuses")

		// Verify data integrity
		resultMap := make(map[uint64]uint64)
		for _, cp := range resp.Statuses {
			resultMap[cp.ChainSelector] = cp.FinalizedBlockHeight
		}

		for i := 0; i < numGoroutines; i++ {
			expectedChain := uint64(i + 1)
			expectedHeight := uint64((i + 1) * 100)
			require.Equal(t, expectedHeight, resultMap[expectedChain], "chain %d should have correct value", expectedChain)
		}
	})

	t.Run("concurrent_writes_different_clients", func(t *testing.T) {
		// Setup server only
		listener, cleanup, err := CreateServerOnly(t, WithChainStatusTestClients())
		require.NoError(t, err, "failed to create test server")
		defer cleanup()

		numClients := 50

		// Create all clients upfront
		type clientInfo struct {
			client   pb.AggregatorClient
			clientID string
			cleanup  func()
		}
		clients := make([]*clientInfo, numClients)
		for i := 0; i < numClients; i++ {
			clientID := "concurrent-client-" + string(rune('A'+i%26)) + string(rune('A'+i/26))
			aggClient, _, clientCleanup := CreateAuthenticatedClient(t, listener, WithClientAuth(clientID, "secret-"+clientID))
			clients[i] = &clientInfo{
				client:   aggClient,
				clientID: clientID,
				cleanup:  clientCleanup,
			}
		}
		// Cleanup all clients at the end
		defer func() {
			for _, c := range clients {
				c.cleanup()
			}
		}()

		var wg sync.WaitGroup

		// Concurrent writes from different clients
		for i := 0; i < numClients; i++ {
			wg.Add(1)
			go func(clientIndex int) {
				defer wg.Done()

				writeReq := &pb.WriteChainStatusRequest{
					Statuses: []*pb.ChainStatus{
						{
							ChainSelector:        1, // All clients use same chain
							FinalizedBlockHeight: uint64((clientIndex + 1) * 100),
							Disabled:             true,
						},
						{
							ChainSelector:        2,
							FinalizedBlockHeight: uint64((clientIndex + 1) * 200),
							Disabled:             false,
						},
					},
				}

				_, err := clients[clientIndex].client.WriteChainStatus(context.Background(), writeReq)
				require.NoError(t, err, "concurrent client %d write should succeed", clientIndex)
			}(i)
		}

		wg.Wait()

		// Verify each client has their own data
		for i := 0; i < numClients; i++ {
			resp, err := clients[i].client.ReadChainStatus(context.Background(), &pb.ReadChainStatusRequest{})
			require.NoError(t, err, "concurrent client %d read should succeed", i)
			require.Len(t, resp.Statuses, 2, "client %d should have 2 chain statuses", i)

			// Create a map to look up statuses by chain selector (order independent)
			statusMap := make(map[uint64]*pb.ChainStatus)
			for _, status := range resp.Statuses {
				statusMap[status.ChainSelector] = status
			}

			// Verify chain 1 (disabled chain)
			chain1Status, exists := statusMap[1]
			require.True(t, exists, "client %d should have chain selector 1", i)
			expectedHeight1 := uint64((i + 1) * 100)
			require.Equal(t, expectedHeight1, chain1Status.FinalizedBlockHeight, "client %d should have correct value for chain 1", i)
			require.True(t, chain1Status.Disabled, "client %d chain 1 status should be disabled", i)

			// Verify chain 2 (enabled chain)
			chain2Status, exists := statusMap[2]
			require.True(t, exists, "client %d should have chain selector 2", i)
			expectedHeight2 := uint64((i + 1) * 200)
			require.Equal(t, expectedHeight2, chain2Status.FinalizedBlockHeight, "client %d should have correct value for chain 2", i)
			require.False(t, chain2Status.Disabled, "client %d chain 2 status should be enabled", i)
		}
	})

	t.Run("concurrent_read_write_operations", func(t *testing.T) {
		// Setup
		client, _, cleanup, err := CreateServerAndClient(t, WithChainStatusTestClients())
		require.NoError(t, err, "failed to create test server and client")
		defer cleanup()

		ctx := context.Background()

		// Pre-populate some data
		initialReq := &pb.WriteChainStatusRequest{
			Statuses: []*pb.ChainStatus{
				{ChainSelector: 1, FinalizedBlockHeight: 100, Disabled: false},
				{ChainSelector: 2, FinalizedBlockHeight: 200, Disabled: false},
			},
		}
		_, err = client.WriteChainStatus(ctx, initialReq)
		require.NoError(t, err, "initial write should succeed")

		var wg sync.WaitGroup
		numReaders := 20
		numWriters := 10
		duration := 100 * time.Millisecond

		// Start concurrent readers
		for i := 0; i < numReaders; i++ {
			wg.Add(1)
			go func(readerIndex int) {
				defer wg.Done()

				start := time.Now()
				reads := 0

				for time.Since(start) < duration {
					resp, err := client.ReadChainStatus(ctx, &pb.ReadChainStatusRequest{})
					require.NoError(t, err, "reader %d should succeed", readerIndex)
					require.GreaterOrEqual(t, len(resp.Statuses), 2, "should always have at least initial data")
					reads++
				}

				require.Greater(t, reads, 0, "reader %d should have performed at least one read", readerIndex)
			}(i)
		}

		// Start concurrent writers
		for i := 0; i < numWriters; i++ {
			wg.Add(1)
			go func(writerIndex int) {
				defer wg.Done()

				start := time.Now()
				writes := 0

				for time.Since(start) < duration {
					writeReq := &pb.WriteChainStatusRequest{
						Statuses: []*pb.ChainStatus{
							{
								ChainSelector:        uint64(writerIndex + 10), // Avoid conflicts with initial data
								FinalizedBlockHeight: uint64(time.Now().UnixNano()%10000) + 1,
							},
						},
					}

					_, err := client.WriteChainStatus(ctx, writeReq)
					require.NoError(t, err, "writer %d should succeed", writerIndex)
					writes++

					time.Sleep(time.Millisecond) // Small delay between writes
				}

				require.Greater(t, writes, 0, "writer %d should have performed at least one write", writerIndex)
			}(i)
		}

		wg.Wait()

		// Final consistency check
		resp, err := client.ReadChainStatus(ctx, &pb.ReadChainStatusRequest{})
		require.NoError(t, err, "final read should succeed")
		require.GreaterOrEqual(t, len(resp.Statuses), 2, "should have at least initial chain statuses")
	})

	t.Run("high_frequency_updates_same_chain", func(t *testing.T) {
		// Setup
		client, _, cleanup, err := CreateServerAndClient(t, WithChainStatusTestClients())
		require.NoError(t, err, "failed to create test server and client")
		defer cleanup()

		ctx := context.Background()
		chainSelector := uint64(1)
		numUpdates := 100
		var wg sync.WaitGroup

		// Rapid updates to same chain
		for i := 0; i < numUpdates; i++ {
			wg.Add(1)
			go func(updateIndex int) {
				defer wg.Done()

				writeReq := &pb.WriteChainStatusRequest{
					Statuses: []*pb.ChainStatus{
						{
							ChainSelector:        chainSelector,
							FinalizedBlockHeight: uint64(updateIndex + 1000),
						},
					},
				}

				_, err := client.WriteChainStatus(ctx, writeReq)
				require.NoError(t, err, "update %d should succeed", updateIndex)
			}(i)
		}

		wg.Wait()

		// Verify final state is consistent (one of the values)
		resp, err := client.ReadChainStatus(ctx, &pb.ReadChainStatusRequest{})
		require.NoError(t, err, "final read should succeed")
		require.Len(t, resp.Statuses, 1, "should have exactly 1 chain status")

		finalValue := resp.Statuses[0].FinalizedBlockHeight
		require.GreaterOrEqual(t, finalValue, uint64(1000), "final value should be from one of the updates")
		require.LessOrEqual(t, finalValue, uint64(1000+numUpdates-1), "final value should be within expected range")
	})
}

// TestChainStatusClientIsolation_DynamoDB tests client isolation with DynamoDB storage.
func TestChainStatusClientIsolation_DynamoDB(t *testing.T) {
	t.Run("dynamodb_client_isolation", func(t *testing.T) {
		// Setup with DynamoDB storage
		listener, cleanup, err := CreateServerOnly(t, WithStorageType("dynamodb"), WithChainStatusTestClients())
		require.NoError(t, err, "failed to create test server with DynamoDB")
		defer cleanup()

		// Create two separate clients
		client1, _, cleanup1 := CreateAuthenticatedClient(t, listener, WithClientAuth("ddb-isolation-client-1", "secret-ddb-isolation-client-1"))
		defer cleanup1()
		client2, _, cleanup2 := CreateAuthenticatedClient(t, listener, WithClientAuth("ddb-isolation-client-2", "secret-ddb-isolation-client-2"))
		defer cleanup2()

		// Client 1 stores chain status
		writeReq1 := &pb.WriteChainStatusRequest{
			Statuses: []*pb.ChainStatus{
				{ChainSelector: 1, FinalizedBlockHeight: 1000, Disabled: false},
				{ChainSelector: 2, FinalizedBlockHeight: 2000, Disabled: false},
			},
		}
		_, err = client1.WriteChainStatus(context.Background(), writeReq1)
		require.NoError(t, err, "client 1 write should succeed")

		// Client 2 stores different statuses
		writeReq2 := &pb.WriteChainStatusRequest{
			Statuses: []*pb.ChainStatus{
				{ChainSelector: 1, FinalizedBlockHeight: 1500, Disabled: false}, // Same chain, different value
				{ChainSelector: 3, FinalizedBlockHeight: 3000, Disabled: false},
			},
		}
		_, err = client2.WriteChainStatus(context.Background(), writeReq2)
		require.NoError(t, err, "client 2 write should succeed")

		// Verify client 1 sees only their data
		resp1, err := client1.ReadChainStatus(context.Background(), &pb.ReadChainStatusRequest{})
		require.NoError(t, err, "client 1 read should succeed")
		require.Len(t, resp1.Statuses, 2, "client 1 should see 2 chain statuses")

		client1Data := make(map[uint64]uint64)
		for _, cp := range resp1.Statuses {
			client1Data[cp.ChainSelector] = cp.FinalizedBlockHeight
		}
		require.Equal(t, uint64(1000), client1Data[1], "client 1 should see their chain 1 value")
		require.Equal(t, uint64(2000), client1Data[2], "client 1 should see their chain 2 value")

		// Verify client 2 sees only their data
		resp2, err := client2.ReadChainStatus(context.Background(), &pb.ReadChainStatusRequest{})
		require.NoError(t, err, "client 2 read should succeed")
		require.Len(t, resp2.Statuses, 2, "client 2 should see 2 chain statuses")

		client2Data := make(map[uint64]uint64)
		for _, cp := range resp2.Statuses {
			client2Data[cp.ChainSelector] = cp.FinalizedBlockHeight
		}
		require.Equal(t, uint64(1500), client2Data[1], "client 2 should see their chain 1 value")
		require.Equal(t, uint64(3000), client2Data[3], "client 2 should see their chain 3 value")
	})
}

// TestChainStatusConcurrency_DynamoDB tests concurrent chain status operations with DynamoDB.
func TestChainStatusConcurrency_DynamoDB(t *testing.T) {
	t.Run("dynamodb_concurrent_writes", func(t *testing.T) {
		// Setup with DynamoDB storage
		client, _, cleanup, err := CreateServerAndClient(t, WithStorageType("dynamodb"), WithChainStatusTestClients())
		require.NoError(t, err, "failed to create test server and client with DynamoDB")
		defer cleanup()

		ctx := context.Background()
		numGoroutines := 20
		var wg sync.WaitGroup

		// Concurrent writes to same client, different chains
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()

				writeReq := &pb.WriteChainStatusRequest{
					Statuses: []*pb.ChainStatus{
						{
							ChainSelector:        uint64(index + 10), // Start from 10 to avoid conflicts
							FinalizedBlockHeight: uint64((index + 1) * 100),
						},
					},
				}

				_, err := client.WriteChainStatus(ctx, writeReq)
				require.NoError(t, err, "concurrent write %d should succeed", index)
			}(i)
		}

		wg.Wait()

		// Verify all writes succeeded
		resp, err := client.ReadChainStatus(ctx, &pb.ReadChainStatusRequest{})
		require.NoError(t, err, "read after concurrent writes should succeed")
		require.Len(t, resp.Statuses, numGoroutines, "should have all concurrent chain statuses")

		// Verify data integrity
		resultMap := make(map[uint64]uint64)
		for _, cp := range resp.Statuses {
			resultMap[cp.ChainSelector] = cp.FinalizedBlockHeight
		}

		for i := 0; i < numGoroutines; i++ {
			expectedChain := uint64(i + 10)
			expectedHeight := uint64((i + 1) * 100)
			require.Equal(t, expectedHeight, resultMap[expectedChain], "chain %d should have correct value", expectedChain)
		}
	})
}

// TestChainStatusAdminAPI tests admin functionality for chain status operations.
func TestChainStatusAdminAPI(t *testing.T) {
	t.Run("admin_can_override_verifier_data", func(t *testing.T) {
		// Setup server
		listener, cleanup, err := CreateServerOnly(t, WithChainStatusTestClients())
		require.NoError(t, err, "failed to create test server")
		defer cleanup()

		// Create verifier client
		verifierClient, _, verifierCleanup := CreateAuthenticatedClient(t, listener, WithClientAuth("verifier-client-1", "secret-verifier-client-1"))
		defer verifierCleanup()

		// Create admin client
		adminClient, _, adminCleanup := CreateAdminAuthenticatedClient(t, listener, "admin-client-1", "secret-admin-client-1", "")
		defer adminCleanup()

		// Verifier stores initial chain status
		initialReq := &pb.WriteChainStatusRequest{
			Statuses: []*pb.ChainStatus{
				{ChainSelector: 1, FinalizedBlockHeight: 1000, Disabled: false},
				{ChainSelector: 2, FinalizedBlockHeight: 2000, Disabled: true},
			},
		}
		_, err = verifierClient.WriteChainStatus(context.Background(), initialReq)
		require.NoError(t, err, "verifier initial write should succeed")

		// Verify verifier can read their data
		verifierResp, err := verifierClient.ReadChainStatus(context.Background(), &pb.ReadChainStatusRequest{})
		require.NoError(t, err, "verifier read should succeed")
		require.Len(t, verifierResp.Statuses, 2, "verifier should see their data")

		// Admin overrides verifier data using on-behalf-of
		adminOverrideClient, _, adminOverrideCleanup := CreateAdminAuthenticatedClient(t, listener, "admin-client-1", "secret-admin-client-1", "verifier-client-1")
		defer adminOverrideCleanup()

		overrideReq := &pb.WriteChainStatusRequest{
			Statuses: []*pb.ChainStatus{
				{ChainSelector: 1, FinalizedBlockHeight: 5000, Disabled: true},  // Changed height and disabled status
				{ChainSelector: 2, FinalizedBlockHeight: 6000, Disabled: false}, // Changed height and enabled
				{ChainSelector: 3, FinalizedBlockHeight: 7000, Disabled: false}, // New chain
			},
		}
		_, err = adminOverrideClient.WriteChainStatus(context.Background(), overrideReq)
		require.NoError(t, err, "admin override should succeed")

		// Verify verifier now sees the admin-set data
		verifierRespAfter, err := verifierClient.ReadChainStatus(context.Background(), &pb.ReadChainStatusRequest{})
		require.NoError(t, err, "verifier read after admin override should succeed")
		require.Len(t, verifierRespAfter.Statuses, 3, "verifier should see admin-modified data")

		statusMap := make(map[uint64]*pb.ChainStatus)
		for _, status := range verifierRespAfter.Statuses {
			statusMap[status.ChainSelector] = status
		}

		require.Equal(t, uint64(5000), statusMap[1].FinalizedBlockHeight, "admin should have overridden chain 1 height")
		require.True(t, statusMap[1].Disabled, "admin should have changed chain 1 to disabled")
		require.Equal(t, uint64(6000), statusMap[2].FinalizedBlockHeight, "admin should have overridden chain 2 height")
		require.False(t, statusMap[2].Disabled, "admin should have changed chain 2 to enabled")
		require.Equal(t, uint64(7000), statusMap[3].FinalizedBlockHeight, "admin should have added new chain 3")
		require.False(t, statusMap[3].Disabled, "admin should have set chain 3 as enabled")

		// Verify admin's own data is unaffected
		adminResp, err := adminClient.ReadChainStatus(context.Background(), &pb.ReadChainStatusRequest{})
		require.NoError(t, err, "admin read should succeed")
		require.Empty(t, adminResp.Statuses, "admin should have no data in their own scope")
	})

	t.Run("regular_verifier_cannot_override_another_verifier", func(t *testing.T) {
		// Setup server
		listener, cleanup, err := CreateServerOnly(t, WithChainStatusTestClients())
		require.NoError(t, err, "failed to create test server")
		defer cleanup()

		// Create two verifier clients
		verifier1Client, _, verifier1Cleanup := CreateAuthenticatedClient(t, listener, WithClientAuth("verifier-client-1", "secret-verifier-client-1"))
		defer verifier1Cleanup()

		// We don't need to create verifier2Client, we only need to test the attack attempt

		// Verifier 1 stores data
		initialReq := &pb.WriteChainStatusRequest{
			Statuses: []*pb.ChainStatus{
				{ChainSelector: 1, FinalizedBlockHeight: 1000, Disabled: false},
			},
		}
		_, err = verifier1Client.WriteChainStatus(context.Background(), initialReq)
		require.NoError(t, err, "verifier 1 write should succeed")

		// Try to create a "fake admin" client using verifier 2 credentials with admin header
		// This should fail because verifier 2 is not an admin
		fakeAdminClient, _, fakeAdminCleanup := CreateAdminAuthenticatedClient(t, listener, "verifier-client-2", "secret-verifier-client-2", "verifier-client-1")
		defer fakeAdminCleanup()

		attackReq := &pb.WriteChainStatusRequest{
			Statuses: []*pb.ChainStatus{
				{ChainSelector: 1, FinalizedBlockHeight: 9999, Disabled: true},
			},
		}
		_, err = fakeAdminClient.WriteChainStatus(context.Background(), attackReq)
		require.Error(t, err, "non-admin client should not be able to use on-behalf-of")
		require.Contains(t, err.Error(), "only admin clients can perform operations on behalf of other clients", "should get permission denied error")

		// Verify verifier 1's data is unchanged
		verifier1Resp, err := verifier1Client.ReadChainStatus(context.Background(), &pb.ReadChainStatusRequest{})
		require.NoError(t, err, "verifier 1 read should succeed")
		require.Len(t, verifier1Resp.Statuses, 1, "verifier 1 should still have their data")
		require.Equal(t, uint64(1000), verifier1Resp.Statuses[0].FinalizedBlockHeight, "verifier 1 data should be unchanged")
		require.False(t, verifier1Resp.Statuses[0].Disabled, "verifier 1 data should be unchanged")
	})

	t.Run("admin_can_set_any_configuration", func(t *testing.T) {
		// Setup server
		listener, cleanup, err := CreateServerOnly(t, WithChainStatusTestClients())
		require.NoError(t, err, "failed to create test server")
		defer cleanup()

		// Create verifier client
		verifierClient, _, verifierCleanup := CreateAuthenticatedClient(t, listener, WithClientAuth("verifier-client-1", "secret-verifier-client-1"))
		defer verifierCleanup()

		// Admin sets extreme configuration values on behalf of verifier
		adminOverrideClient, _, adminOverrideCleanup := CreateAdminAuthenticatedClient(t, listener, "admin-client-1", "secret-admin-client-1", "verifier-client-1")
		defer adminOverrideCleanup()

		extremeReq := &pb.WriteChainStatusRequest{
			Statuses: []*pb.ChainStatus{
				{ChainSelector: 1, FinalizedBlockHeight: 0xFFFFFFFFFFFFFFFF, Disabled: true}, // Max uint64, disabled
				{ChainSelector: 2, FinalizedBlockHeight: 1, Disabled: false},                 // Min valid height, enabled
				{ChainSelector: 999999, FinalizedBlockHeight: 12345678, Disabled: true},      // Unusual chain selector
			},
		}
		_, err = adminOverrideClient.WriteChainStatus(context.Background(), extremeReq)
		require.NoError(t, err, "admin should be able to set any valid configuration")

		// Verify verifier sees the extreme configuration
		verifierResp, err := verifierClient.ReadChainStatus(context.Background(), &pb.ReadChainStatusRequest{})
		require.NoError(t, err, "verifier read should succeed")
		require.Len(t, verifierResp.Statuses, 3, "verifier should see all admin-set data")

		statusMap := make(map[uint64]*pb.ChainStatus)
		for _, status := range verifierResp.Statuses {
			statusMap[status.ChainSelector] = status
		}

		require.Equal(t, uint64(0xFFFFFFFFFFFFFFFF), statusMap[1].FinalizedBlockHeight, "admin should be able to set max values")
		require.True(t, statusMap[1].Disabled, "admin should be able to disable chains")
		require.Equal(t, uint64(1), statusMap[2].FinalizedBlockHeight, "admin should be able to set min values")
		require.False(t, statusMap[2].Disabled, "admin should be able to enable chains")
		require.Equal(t, uint64(12345678), statusMap[999999].FinalizedBlockHeight, "admin should be able to set any chain selector")
		require.True(t, statusMap[999999].Disabled, "admin should be able to set any configuration")
	})

	t.Run("admin_operations_maintain_client_isolation", func(t *testing.T) {
		// Setup server
		listener, cleanup, err := CreateServerOnly(t, WithChainStatusTestClients())
		require.NoError(t, err, "failed to create test server")
		defer cleanup()

		// Create multiple verifier clients
		verifier1Client, _, verifier1Cleanup := CreateAuthenticatedClient(t, listener, WithClientAuth("verifier-client-1", "secret-verifier-client-1"))
		defer verifier1Cleanup()
		verifier2Client, _, verifier2Cleanup := CreateAuthenticatedClient(t, listener, WithClientAuth("verifier-client-2", "secret-verifier-client-2"))
		defer verifier2Cleanup()
		verifier3Client, _, verifier3Cleanup := CreateAuthenticatedClient(t, listener, WithClientAuth("verifier-client-3", "secret-verifier-client-3"))
		defer verifier3Cleanup()

		// Each verifier stores initial data
		for i, client := range []pb.AggregatorClient{verifier1Client, verifier2Client, verifier3Client} {
			initialReq := &pb.WriteChainStatusRequest{
				Statuses: []*pb.ChainStatus{
					{ChainSelector: 1, FinalizedBlockHeight: uint64((i + 1) * 1000), Disabled: false},
				},
			}
			_, err = client.WriteChainStatus(context.Background(), initialReq)
			require.NoError(t, err, "verifier %d initial write should succeed", i+1)
		}

		// Admin overrides only verifier 2's data
		adminOverrideClient, _, adminOverrideCleanup := CreateAdminAuthenticatedClient(t, listener, "admin-client-1", "secret-admin-client-1", "verifier-client-2")
		defer adminOverrideCleanup()

		overrideReq := &pb.WriteChainStatusRequest{
			Statuses: []*pb.ChainStatus{
				{ChainSelector: 1, FinalizedBlockHeight: 9999, Disabled: true},
			},
		}
		_, err = adminOverrideClient.WriteChainStatus(context.Background(), overrideReq)
		require.NoError(t, err, "admin override should succeed")

		// Verify verifier 1's data is unchanged
		verifier1Resp, err := verifier1Client.ReadChainStatus(context.Background(), &pb.ReadChainStatusRequest{})
		require.NoError(t, err, "verifier 1 read should succeed")
		require.Len(t, verifier1Resp.Statuses, 1, "verifier 1 should have their data")
		require.Equal(t, uint64(1000), verifier1Resp.Statuses[0].FinalizedBlockHeight, "verifier 1 data should be unchanged")

		// Verify verifier 2's data is overridden
		verifier2Resp, err := verifier2Client.ReadChainStatus(context.Background(), &pb.ReadChainStatusRequest{})
		require.NoError(t, err, "verifier 2 read should succeed")
		require.Len(t, verifier2Resp.Statuses, 1, "verifier 2 should have admin data")
		require.Equal(t, uint64(9999), verifier2Resp.Statuses[0].FinalizedBlockHeight, "verifier 2 data should be overridden")
		require.True(t, verifier2Resp.Statuses[0].Disabled, "verifier 2 data should be overridden")

		// Verify verifier 3's data is unchanged
		verifier3Resp, err := verifier3Client.ReadChainStatus(context.Background(), &pb.ReadChainStatusRequest{})
		require.NoError(t, err, "verifier 3 read should succeed")
		require.Len(t, verifier3Resp.Statuses, 1, "verifier 3 should have their data")
		require.Equal(t, uint64(3000), verifier3Resp.Statuses[0].FinalizedBlockHeight, "verifier 3 data should be unchanged")
	})

	t.Run("admin_without_on_behalf_of_header_acts_normally", func(t *testing.T) {
		// Setup server
		listener, cleanup, err := CreateServerOnly(t, WithChainStatusTestClients())
		require.NoError(t, err, "failed to create test server")
		defer cleanup()

		// Create admin client without on-behalf-of header
		adminClient, _, adminCleanup := CreateAdminAuthenticatedClient(t, listener, "admin-client-1", "secret-admin-client-1", "")
		defer adminCleanup()

		// Create verifier client
		verifierClient, _, verifierCleanup := CreateAuthenticatedClient(t, listener, WithClientAuth("verifier-client-1", "secret-verifier-client-1"))
		defer verifierCleanup()

		// Verifier stores data
		verifierReq := &pb.WriteChainStatusRequest{
			Statuses: []*pb.ChainStatus{
				{ChainSelector: 1, FinalizedBlockHeight: 1000, Disabled: false},
			},
		}
		_, err = verifierClient.WriteChainStatus(context.Background(), verifierReq)
		require.NoError(t, err, "verifier write should succeed")

		// Admin stores data in their own scope (without on-behalf-of header)
		adminReq := &pb.WriteChainStatusRequest{
			Statuses: []*pb.ChainStatus{
				{ChainSelector: 1, FinalizedBlockHeight: 2000, Disabled: true},
			},
		}
		_, err = adminClient.WriteChainStatus(context.Background(), adminReq)
		require.NoError(t, err, "admin write should succeed")

		// Verify admin and verifier have separate data
		adminResp, err := adminClient.ReadChainStatus(context.Background(), &pb.ReadChainStatusRequest{})
		require.NoError(t, err, "admin read should succeed")
		require.Len(t, adminResp.Statuses, 1, "admin should have their own data")
		require.Equal(t, uint64(2000), adminResp.Statuses[0].FinalizedBlockHeight, "admin should see their data")
		require.True(t, adminResp.Statuses[0].Disabled, "admin should see their data")

		verifierResp, err := verifierClient.ReadChainStatus(context.Background(), &pb.ReadChainStatusRequest{})
		require.NoError(t, err, "verifier read should succeed")
		require.Len(t, verifierResp.Statuses, 1, "verifier should have their own data")
		require.Equal(t, uint64(1000), verifierResp.Statuses[0].FinalizedBlockHeight, "verifier should see their data")
		require.False(t, verifierResp.Statuses[0].Disabled, "verifier should see their data")
	})

	t.Run("chain_status_updates_work_as_patch_operations", func(t *testing.T) {
		// Setup server
		listener, cleanup, err := CreateServerOnly(t, WithChainStatusTestClients())
		require.NoError(t, err, "failed to create test server")
		defer cleanup()

		// Create verifier client
		verifierClient, _, verifierCleanup := CreateAuthenticatedClient(t, listener, WithClientAuth("verifier-client-1", "secret-verifier-client-1"))
		defer verifierCleanup()

		// Create admin client
		adminOverrideClient, _, adminOverrideCleanup := CreateAdminAuthenticatedClient(t, listener, "admin-client-1", "secret-admin-client-1", "verifier-client-1")
		defer adminOverrideCleanup()

		// Verifier stores initial data with 10 chain selectors
		initialReq := &pb.WriteChainStatusRequest{
			Statuses: []*pb.ChainStatus{
				{ChainSelector: 1, FinalizedBlockHeight: 1000, Disabled: false},
				{ChainSelector: 2, FinalizedBlockHeight: 2000, Disabled: false},
				{ChainSelector: 3, FinalizedBlockHeight: 3000, Disabled: true},
				{ChainSelector: 4, FinalizedBlockHeight: 4000, Disabled: false},
				{ChainSelector: 5, FinalizedBlockHeight: 5000, Disabled: true},
				{ChainSelector: 6, FinalizedBlockHeight: 6000, Disabled: false},
				{ChainSelector: 7, FinalizedBlockHeight: 7000, Disabled: false},
				{ChainSelector: 8, FinalizedBlockHeight: 8000, Disabled: true},
				{ChainSelector: 9, FinalizedBlockHeight: 9000, Disabled: false},
				{ChainSelector: 10, FinalizedBlockHeight: 10000, Disabled: false},
			},
		}
		_, err = verifierClient.WriteChainStatus(context.Background(), initialReq)
		require.NoError(t, err, "verifier initial write should succeed")

		// Verify all 10 chains are stored
		verifierResp, err := verifierClient.ReadChainStatus(context.Background(), &pb.ReadChainStatusRequest{})
		require.NoError(t, err, "verifier read should succeed")
		require.Len(t, verifierResp.Statuses, 10, "verifier should see all 10 chain statuses")

		// Admin updates only 1 chain selector (partial update/patch)
		patchReq := &pb.WriteChainStatusRequest{
			Statuses: []*pb.ChainStatus{
				{ChainSelector: 5, FinalizedBlockHeight: 55555, Disabled: false}, // Only update chain 5
			},
		}
		_, err = adminOverrideClient.WriteChainStatus(context.Background(), patchReq)
		require.NoError(t, err, "admin patch update should succeed")

		// Verify that all 10 chains are still present, but only chain 5 is modified
		verifierRespAfter, err := verifierClient.ReadChainStatus(context.Background(), &pb.ReadChainStatusRequest{})
		require.NoError(t, err, "verifier read after patch should succeed")
		require.Len(t, verifierRespAfter.Statuses, 10, "verifier should still see all 10 chain statuses after patch")

		statusMap := make(map[uint64]*pb.ChainStatus)
		for _, status := range verifierRespAfter.Statuses {
			statusMap[status.ChainSelector] = status
		}

		// Verify unchanged chains (1-4, 6-10) have original values
		require.Equal(t, uint64(1000), statusMap[1].FinalizedBlockHeight, "chain 1 should be unchanged")
		require.False(t, statusMap[1].Disabled, "chain 1 disabled status should be unchanged")
		require.Equal(t, uint64(2000), statusMap[2].FinalizedBlockHeight, "chain 2 should be unchanged")
		require.False(t, statusMap[2].Disabled, "chain 2 disabled status should be unchanged")
		require.Equal(t, uint64(3000), statusMap[3].FinalizedBlockHeight, "chain 3 should be unchanged")
		require.True(t, statusMap[3].Disabled, "chain 3 disabled status should be unchanged")
		require.Equal(t, uint64(4000), statusMap[4].FinalizedBlockHeight, "chain 4 should be unchanged")
		require.False(t, statusMap[4].Disabled, "chain 4 disabled status should be unchanged")
		require.Equal(t, uint64(6000), statusMap[6].FinalizedBlockHeight, "chain 6 should be unchanged")
		require.False(t, statusMap[6].Disabled, "chain 6 disabled status should be unchanged")
		require.Equal(t, uint64(7000), statusMap[7].FinalizedBlockHeight, "chain 7 should be unchanged")
		require.False(t, statusMap[7].Disabled, "chain 7 disabled status should be unchanged")
		require.Equal(t, uint64(8000), statusMap[8].FinalizedBlockHeight, "chain 8 should be unchanged")
		require.True(t, statusMap[8].Disabled, "chain 8 disabled status should be unchanged")
		require.Equal(t, uint64(9000), statusMap[9].FinalizedBlockHeight, "chain 9 should be unchanged")
		require.False(t, statusMap[9].Disabled, "chain 9 disabled status should be unchanged")
		require.Equal(t, uint64(10000), statusMap[10].FinalizedBlockHeight, "chain 10 should be unchanged")
		require.False(t, statusMap[10].Disabled, "chain 10 disabled status should be unchanged")

		// Verify only chain 5 was updated
		require.Equal(t, uint64(55555), statusMap[5].FinalizedBlockHeight, "chain 5 should be updated by admin patch")
		require.False(t, statusMap[5].Disabled, "chain 5 disabled status should be updated by admin patch")

		// Test that regular verifier updates also work as patches
		verifierPatchReq := &pb.WriteChainStatusRequest{
			Statuses: []*pb.ChainStatus{
				{ChainSelector: 1, FinalizedBlockHeight: 11111, Disabled: true},  // Update chain 1
				{ChainSelector: 10, FinalizedBlockHeight: 99999, Disabled: true}, // Update chain 10
			},
		}
		_, err = verifierClient.WriteChainStatus(context.Background(), verifierPatchReq)
		require.NoError(t, err, "verifier patch update should succeed")

		// Verify that all 10 chains are still present, with chains 1 and 10 modified
		verifierRespFinal, err := verifierClient.ReadChainStatus(context.Background(), &pb.ReadChainStatusRequest{})
		require.NoError(t, err, "verifier final read should succeed")
		require.Len(t, verifierRespFinal.Statuses, 10, "verifier should still see all 10 chain statuses after verifier patch")

		statusMapFinal := make(map[uint64]*pb.ChainStatus)
		for _, status := range verifierRespFinal.Statuses {
			statusMapFinal[status.ChainSelector] = status
		}

		// Verify chains 1 and 10 were updated by verifier
		require.Equal(t, uint64(11111), statusMapFinal[1].FinalizedBlockHeight, "chain 1 should be updated by verifier patch")
		require.True(t, statusMapFinal[1].Disabled, "chain 1 disabled status should be updated by verifier patch")
		require.Equal(t, uint64(99999), statusMapFinal[10].FinalizedBlockHeight, "chain 10 should be updated by verifier patch")
		require.True(t, statusMapFinal[10].Disabled, "chain 10 disabled status should be updated by verifier patch")

		// Verify other chains remain unchanged from the admin patch state
		require.Equal(t, uint64(2000), statusMapFinal[2].FinalizedBlockHeight, "chain 2 should remain unchanged")
		require.Equal(t, uint64(3000), statusMapFinal[3].FinalizedBlockHeight, "chain 3 should remain unchanged")
		require.Equal(t, uint64(4000), statusMapFinal[4].FinalizedBlockHeight, "chain 4 should remain unchanged")
		require.Equal(t, uint64(55555), statusMapFinal[5].FinalizedBlockHeight, "chain 5 should retain admin patch value")
		require.False(t, statusMapFinal[5].Disabled, "chain 5 should retain admin patch disabled status")
		require.Equal(t, uint64(6000), statusMapFinal[6].FinalizedBlockHeight, "chain 6 should remain unchanged")
		require.Equal(t, uint64(7000), statusMapFinal[7].FinalizedBlockHeight, "chain 7 should remain unchanged")
		require.Equal(t, uint64(8000), statusMapFinal[8].FinalizedBlockHeight, "chain 8 should remain unchanged")
		require.Equal(t, uint64(9000), statusMapFinal[9].FinalizedBlockHeight, "chain 9 should remain unchanged")
	})
}
