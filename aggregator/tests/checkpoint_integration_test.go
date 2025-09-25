// Package tests contains integration tests for the aggregator service.
package tests

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

// TestCheckpointClientIsolation tests that clients can't access each other's data.
func TestCheckpointClientIsolation(t *testing.T) {
	t.Run("different_clients_isolated_data", func(t *testing.T) {
		// Setup
		client, _, cleanup, err := CreateServerAndClient(t)
		require.NoError(t, err, "failed to create test server and client")
		defer cleanup()

		client1Ctx := contextWithAPIKey("isolation-client-1")
		client2Ctx := contextWithAPIKey("isolation-client-2")
		client3Ctx := contextWithAPIKey("isolation-client-3")

		// Client 1 stores checkpoints
		writeReq1 := &pb.WriteBlockCheckpointRequest{
			Checkpoints: []*pb.BlockCheckpoint{
				{ChainSelector: 1, FinalizedBlockHeight: 1000},
				{ChainSelector: 2, FinalizedBlockHeight: 2000},
			},
		}
		_, err = client.WriteBlockCheckpoint(client1Ctx, writeReq1)
		require.NoError(t, err, "client 1 write should succeed")

		// Client 2 stores different checkpoints
		writeReq2 := &pb.WriteBlockCheckpointRequest{
			Checkpoints: []*pb.BlockCheckpoint{
				{ChainSelector: 1, FinalizedBlockHeight: 1500}, // Same chain, different value
				{ChainSelector: 3, FinalizedBlockHeight: 3000},
			},
		}
		_, err = client.WriteBlockCheckpoint(client2Ctx, writeReq2)
		require.NoError(t, err, "client 2 write should succeed")

		// Client 3 has no data stored

		// Verify client 1 sees only their data
		resp1, err := client.ReadBlockCheckpoint(client1Ctx, &pb.ReadBlockCheckpointRequest{})
		require.NoError(t, err, "client 1 read should succeed")
		require.Len(t, resp1.Checkpoints, 2, "client 1 should see 2 checkpoints")

		client1Data := make(map[uint64]uint64)
		for _, cp := range resp1.Checkpoints {
			client1Data[cp.ChainSelector] = cp.FinalizedBlockHeight
		}
		require.Equal(t, uint64(1000), client1Data[1], "client 1 should see their chain 1 value")
		require.Equal(t, uint64(2000), client1Data[2], "client 1 should see their chain 2 value")

		// Verify client 2 sees only their data
		resp2, err := client.ReadBlockCheckpoint(client2Ctx, &pb.ReadBlockCheckpointRequest{})
		require.NoError(t, err, "client 2 read should succeed")
		require.Len(t, resp2.Checkpoints, 2, "client 2 should see 2 checkpoints")

		client2Data := make(map[uint64]uint64)
		for _, cp := range resp2.Checkpoints {
			client2Data[cp.ChainSelector] = cp.FinalizedBlockHeight
		}
		require.Equal(t, uint64(1500), client2Data[1], "client 2 should see their chain 1 value")
		require.Equal(t, uint64(3000), client2Data[3], "client 2 should see their chain 3 value")

		// Verify client 3 sees no data
		resp3, err := client.ReadBlockCheckpoint(client3Ctx, &pb.ReadBlockCheckpointRequest{})
		require.NoError(t, err, "client 3 read should succeed")
		require.Empty(t, resp3.Checkpoints, "client 3 should see no checkpoints")
	})

	t.Run("same_chain_different_clients", func(t *testing.T) {
		// Setup
		client, _, cleanup, err := CreateServerAndClient(t)
		require.NoError(t, err, "failed to create test server and client")
		defer cleanup()

		numClients := 10
		chainSelector := uint64(42) // All clients use same chain selector

		// Each client stores their own value for the same chain
		for i := 0; i < numClients; i++ {
			clientID := "same-chain-client-" + string(rune('A'+i))
			ctx := contextWithAPIKey(clientID)

			writeReq := &pb.WriteBlockCheckpointRequest{
				Checkpoints: []*pb.BlockCheckpoint{
					{ChainSelector: chainSelector, FinalizedBlockHeight: uint64((i + 1) * 100)},
				},
			}
			_, err = client.WriteBlockCheckpoint(ctx, writeReq)
			require.NoError(t, err, "client %d write should succeed", i)
		}

		// Verify each client sees only their own value
		for i := 0; i < numClients; i++ {
			clientID := "same-chain-client-" + string(rune('A'+i))
			ctx := contextWithAPIKey(clientID)

			resp, err := client.ReadBlockCheckpoint(ctx, &pb.ReadBlockCheckpointRequest{})
			require.NoError(t, err, "client %d read should succeed", i)
			require.Len(t, resp.Checkpoints, 1, "client %d should see 1 checkpoint", i)

			checkpoint := resp.Checkpoints[0]
			require.Equal(t, chainSelector, checkpoint.ChainSelector, "client %d should see correct chain", i)
			require.Equal(t, uint64((i+1)*100), checkpoint.FinalizedBlockHeight, "client %d should see their own value", i)
		}
	})

	t.Run("client_updates_dont_affect_others", func(t *testing.T) {
		// Setup
		client, _, cleanup, err := CreateServerAndClient(t)
		require.NoError(t, err, "failed to create test server and client")
		defer cleanup()

		clientACtx := contextWithAPIKey("update-client-A")
		clientBCtx := contextWithAPIKey("update-client-B")

		// Both clients store initial data
		initialReq := &pb.WriteBlockCheckpointRequest{
			Checkpoints: []*pb.BlockCheckpoint{
				{ChainSelector: 1, FinalizedBlockHeight: 100},
			},
		}
		_, err = client.WriteBlockCheckpoint(clientACtx, initialReq)
		require.NoError(t, err, "client A initial write should succeed")
		_, err = client.WriteBlockCheckpoint(clientBCtx, initialReq)
		require.NoError(t, err, "client B initial write should succeed")

		// Client A updates their data
		updateReq := &pb.WriteBlockCheckpointRequest{
			Checkpoints: []*pb.BlockCheckpoint{
				{ChainSelector: 1, FinalizedBlockHeight: 200},
			},
		}
		_, err = client.WriteBlockCheckpoint(clientACtx, updateReq)
		require.NoError(t, err, "client A update should succeed")

		// Verify client A sees updated data
		respA, err := client.ReadBlockCheckpoint(clientACtx, &pb.ReadBlockCheckpointRequest{})
		require.NoError(t, err, "client A read should succeed")
		require.Equal(t, uint64(200), respA.Checkpoints[0].FinalizedBlockHeight, "client A should see updated value")

		// Verify client B still sees original data
		respB, err := client.ReadBlockCheckpoint(clientBCtx, &pb.ReadBlockCheckpointRequest{})
		require.NoError(t, err, "client B read should succeed")
		require.Equal(t, uint64(100), respB.Checkpoints[0].FinalizedBlockHeight, "client B should see original value")
	})
}

// TestCheckpointConcurrency tests concurrent access to checkpoint operations.
func TestCheckpointConcurrency(t *testing.T) {
	t.Run("concurrent_writes_same_client", func(t *testing.T) {
		// Setup
		client, _, cleanup, err := CreateServerAndClient(t)
		require.NoError(t, err, "failed to create test server and client")
		defer cleanup()

		ctx := contextWithAPIKey("concurrent-client")
		numGoroutines := 50
		var wg sync.WaitGroup

		// Concurrent writes to same client, different chains
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()

				writeReq := &pb.WriteBlockCheckpointRequest{
					Checkpoints: []*pb.BlockCheckpoint{
						{
							ChainSelector:        uint64(index + 1),
							FinalizedBlockHeight: uint64((index + 1) * 100),
						},
					},
				}

				_, err := client.WriteBlockCheckpoint(ctx, writeReq)
				require.NoError(t, err, "concurrent write %d should succeed", index)
			}(i)
		}

		wg.Wait()

		// Verify all writes succeeded
		resp, err := client.ReadBlockCheckpoint(ctx, &pb.ReadBlockCheckpointRequest{})
		require.NoError(t, err, "read after concurrent writes should succeed")
		require.Len(t, resp.Checkpoints, numGoroutines, "should have all concurrent checkpoints")

		// Verify data integrity
		resultMap := make(map[uint64]uint64)
		for _, cp := range resp.Checkpoints {
			resultMap[cp.ChainSelector] = cp.FinalizedBlockHeight
		}

		for i := 0; i < numGoroutines; i++ {
			expectedChain := uint64(i + 1)
			expectedHeight := uint64((i + 1) * 100)
			require.Equal(t, expectedHeight, resultMap[expectedChain], "chain %d should have correct value", expectedChain)
		}
	})

	t.Run("concurrent_writes_different_clients", func(t *testing.T) {
		// Setup
		client, _, cleanup, err := CreateServerAndClient(t)
		require.NoError(t, err, "failed to create test server and client")
		defer cleanup()

		numClients := 50
		var wg sync.WaitGroup

		// Concurrent writes from different clients
		for i := 0; i < numClients; i++ {
			wg.Add(1)
			go func(clientIndex int) {
				defer wg.Done()

				clientID := "concurrent-client-" + string(rune('A'+clientIndex%26)) + string(rune('A'+clientIndex/26))
				ctx := contextWithAPIKey(clientID)

				writeReq := &pb.WriteBlockCheckpointRequest{
					Checkpoints: []*pb.BlockCheckpoint{
						{
							ChainSelector:        1, // All clients use same chain
							FinalizedBlockHeight: uint64((clientIndex + 1) * 100),
						},
					},
				}

				_, err := client.WriteBlockCheckpoint(ctx, writeReq)
				require.NoError(t, err, "concurrent client %d write should succeed", clientIndex)
			}(i)
		}

		wg.Wait()

		// Verify each client has their own data
		for i := 0; i < numClients; i++ {
			clientID := "concurrent-client-" + string(rune('A'+i%26)) + string(rune('A'+i/26))
			ctx := contextWithAPIKey(clientID)

			resp, err := client.ReadBlockCheckpoint(ctx, &pb.ReadBlockCheckpointRequest{})
			require.NoError(t, err, "concurrent client %d read should succeed", i)
			require.Len(t, resp.Checkpoints, 1, "client %d should have 1 checkpoint", i)

			expectedHeight := uint64((i + 1) * 100)
			require.Equal(t, expectedHeight, resp.Checkpoints[0].FinalizedBlockHeight, "client %d should have correct value", i)
		}
	})

	t.Run("concurrent_read_write_operations", func(t *testing.T) {
		// Setup
		client, _, cleanup, err := CreateServerAndClient(t)
		require.NoError(t, err, "failed to create test server and client")
		defer cleanup()

		ctx := contextWithAPIKey("read-write-client")

		// Pre-populate some data
		initialReq := &pb.WriteBlockCheckpointRequest{
			Checkpoints: []*pb.BlockCheckpoint{
				{ChainSelector: 1, FinalizedBlockHeight: 100},
				{ChainSelector: 2, FinalizedBlockHeight: 200},
			},
		}
		_, err = client.WriteBlockCheckpoint(ctx, initialReq)
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
					resp, err := client.ReadBlockCheckpoint(ctx, &pb.ReadBlockCheckpointRequest{})
					require.NoError(t, err, "reader %d should succeed", readerIndex)
					require.GreaterOrEqual(t, len(resp.Checkpoints), 2, "should always have at least initial data")
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
					writeReq := &pb.WriteBlockCheckpointRequest{
						Checkpoints: []*pb.BlockCheckpoint{
							{
								ChainSelector:        uint64(writerIndex + 10), // Avoid conflicts with initial data
								FinalizedBlockHeight: uint64(time.Now().UnixNano()%10000) + 1,
							},
						},
					}

					_, err := client.WriteBlockCheckpoint(ctx, writeReq)
					require.NoError(t, err, "writer %d should succeed", writerIndex)
					writes++

					time.Sleep(time.Millisecond) // Small delay between writes
				}

				require.Greater(t, writes, 0, "writer %d should have performed at least one write", writerIndex)
			}(i)
		}

		wg.Wait()

		// Final consistency check
		resp, err := client.ReadBlockCheckpoint(ctx, &pb.ReadBlockCheckpointRequest{})
		require.NoError(t, err, "final read should succeed")
		require.GreaterOrEqual(t, len(resp.Checkpoints), 2, "should have at least initial checkpoints")
	})

	t.Run("high_frequency_updates_same_chain", func(t *testing.T) {
		// Setup
		client, _, cleanup, err := CreateServerAndClient(t)
		require.NoError(t, err, "failed to create test server and client")
		defer cleanup()

		ctx := contextWithAPIKey("high-freq-client")
		chainSelector := uint64(1)
		numUpdates := 100
		var wg sync.WaitGroup

		// Rapid updates to same chain
		for i := 0; i < numUpdates; i++ {
			wg.Add(1)
			go func(updateIndex int) {
				defer wg.Done()

				writeReq := &pb.WriteBlockCheckpointRequest{
					Checkpoints: []*pb.BlockCheckpoint{
						{
							ChainSelector:        chainSelector,
							FinalizedBlockHeight: uint64(updateIndex + 1000),
						},
					},
				}

				_, err := client.WriteBlockCheckpoint(ctx, writeReq)
				require.NoError(t, err, "update %d should succeed", updateIndex)
			}(i)
		}

		wg.Wait()

		// Verify final state is consistent (one of the values)
		resp, err := client.ReadBlockCheckpoint(ctx, &pb.ReadBlockCheckpointRequest{})
		require.NoError(t, err, "final read should succeed")
		require.Len(t, resp.Checkpoints, 1, "should have exactly 1 checkpoint")

		finalValue := resp.Checkpoints[0].FinalizedBlockHeight
		require.GreaterOrEqual(t, finalValue, uint64(1000), "final value should be from one of the updates")
		require.LessOrEqual(t, finalValue, uint64(1000+numUpdates-1), "final value should be within expected range")
	})
}

// Helper functions

func contextWithAPIKey(apiKey string) context.Context {
	md := metadata.New(map[string]string{"api-key": apiKey})
	return metadata.NewOutgoingContext(context.Background(), md)
}
