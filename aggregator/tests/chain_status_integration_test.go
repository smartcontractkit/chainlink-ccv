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

		for _, clientID := range testClients {
			secret := "secret-" + clientID
			cfg.APIKeys.Clients[clientID] = &model.APIClient{
				ClientID:    clientID,
				Description: "Test client for " + clientID,
				Enabled:     true,
				Secrets: map[string]string{
					"current": secret,
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

		// Client 2 stores different checkpoints
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
			require.Len(t, resp.Statuses, 1, "client %d should have 1 chain status", i)

			expectedHeight := uint64((i + 1) * 100)
			require.Equal(t, expectedHeight, resp.Statuses[0].FinalizedBlockHeight, "client %d should have correct value", i)
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

		// Client 2 stores different checkpoints
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
