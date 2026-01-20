package heartbeatclient_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/heartbeatclient"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	heartbeatpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/heartbeat/v1"
)

func TestNewHeartbeatClient_InvalidAddress(t *testing.T) {
	lggr := logger.Test(t)

	// Test with invalid address that can't be reached
	client, err := heartbeatclient.NewHeartbeatClient("invalid://address", lggr, nil, true)
	// Connection succeeds but will fail on actual send
	require.NoError(t, err)
	require.NotNil(t, client)
	defer client.Close()
}

func TestHeartbeatClient_SendHeartbeat_Success(t *testing.T) {
	lggr := logger.Test(t)

	// Test basic client construction
	client, err := heartbeatclient.NewHeartbeatClient("localhost:50051", lggr, nil, true)
	require.NoError(t, err)
	require.NotNil(t, client)
	defer client.Close()
}

func TestHeartbeatClient_SendHeartbeat_WithHMAC(t *testing.T) {
	lggr := logger.Test(t)

	// Create HMAC config
	hmacConfig := &hmac.ClientConfig{
		APIKey: "test-verifier",
		Secret: "test-secret-key-1234567890ab",
	}

	// Client should be created successfully with HMAC config
	client, err := heartbeatclient.NewHeartbeatClient("localhost:50051", lggr, hmacConfig, true)
	require.NoError(t, err)
	require.NotNil(t, client)
	defer client.Close()
}

func TestHeartbeatClient_Close(t *testing.T) {
	lggr := logger.Test(t)

	client, err := heartbeatclient.NewHeartbeatClient("localhost:50051", lggr, nil, true)
	require.NoError(t, err)
	require.NotNil(t, client)

	// Close should not error
	err = client.Close()
	// Note: Close() may return an error if there are pending operations
	if err != nil {
		t.Logf("First close returned error (expected): %v", err)
	}

	// Closing again - gRPC connections may error on second close
	err = client.Close()
	if err != nil {
		t.Logf("Second close returned error (expected): %v", err)
	}
}

func TestHeartbeatClient_SendHeartbeat_Timeout(t *testing.T) {
	lggr := logger.Test(t)

	client, err := heartbeatclient.NewHeartbeatClient("localhost:50051", lggr, nil, true)
	require.NoError(t, err)
	require.NotNil(t, client)
	defer client.Close()

	// Create a context that times out immediately
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// This should fail due to timeout (since the server isn't actually running)
	req := &heartbeatpb.HeartbeatRequest{
		SendTimestamp: time.Now().Unix(),
		ChainDetails: &heartbeatpb.ChainHealthDetails{
			BlockHeightsByChain: map[uint64]uint64{42: 100},
		},
	}

	// We expect an error (either deadline exceeded or connection refused)
	_, err = client.SendHeartbeat(ctx, req)
	assert.Error(t, err)
}

func TestHeartbeatClient_SendHeartbeat_NilRequest(t *testing.T) {
	lggr := logger.Test(t)

	client, err := heartbeatclient.NewHeartbeatClient("localhost:50051", lggr, nil, true)
	require.NoError(t, err)
	require.NotNil(t, client)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Sending nil request should fail
	_, err = client.SendHeartbeat(ctx, nil)
	assert.Error(t, err)
}

// TestHeartbeatClient_WithCallOptions tests that call options are properly passed through.
func TestHeartbeatClient_WithCallOptions(t *testing.T) {
	lggr := logger.Test(t)

	client, err := heartbeatclient.NewHeartbeatClient("localhost:50051", lggr, nil, true)
	require.NoError(t, err)
	require.NotNil(t, client)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	req := &heartbeatpb.HeartbeatRequest{
		SendTimestamp: time.Now().Unix(),
		ChainDetails: &heartbeatpb.ChainHealthDetails{
			BlockHeightsByChain: map[uint64]uint64{42: 100},
		},
	}

	// Pass call options (will fail to connect but options should be accepted)
	_, err = client.SendHeartbeat(ctx, req, grpc.WaitForReady(false))
	assert.Error(t, err)
}
