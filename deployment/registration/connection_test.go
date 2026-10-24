package registration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"
)

func TestWaitForConnection(t *testing.T) {
	t.Parallel()
	t.Run("already connected", func(t *testing.T) {
		t.Parallel()
		client := newFakeJD()
		client.addNode(&nodev1.Node{Id: "node-1", IsConnected: true})
		require.NoError(t, WaitForConnection(t.Context(), client, "node-1", WaitConfig{Timeout: time.Second}))
	})
	t.Run("delayed connection", func(t *testing.T) {
		t.Parallel()
		client := newFakeJD()
		calls := 0
		client.getNodeFunc = func(context.Context, *nodev1.GetNodeRequest) (*nodev1.GetNodeResponse, error) {
			calls++
			return &nodev1.GetNodeResponse{Node: &nodev1.Node{Id: "node-1", IsConnected: calls >= 3}}, nil
		}
		err := WaitForConnection(t.Context(), client, "node-1", WaitConfig{Timeout: time.Second, PollInterval: time.Millisecond})
		require.NoError(t, err)
		require.Equal(t, 3, calls)
	})
	t.Run("transient lookup errors", func(t *testing.T) {
		t.Parallel()
		client := newFakeJD()
		calls := 0
		client.getNodeFunc = func(context.Context, *nodev1.GetNodeRequest) (*nodev1.GetNodeResponse, error) {
			calls++
			if calls < 3 {
				return nil, errors.New("temporary")
			}
			return &nodev1.GetNodeResponse{Node: &nodev1.Node{Id: "node-1", IsConnected: true}}, nil
		}
		err := WaitForConnection(t.Context(), client, "node-1", WaitConfig{Timeout: time.Second, PollInterval: time.Millisecond})
		require.NoError(t, err)
		require.Equal(t, 3, calls)
	})
	t.Run("invalid response", func(t *testing.T) {
		t.Parallel()
		client := newFakeJD()
		client.getNodeFunc = func(context.Context, *nodev1.GetNodeRequest) (*nodev1.GetNodeResponse, error) {
			return nil, nil
		}
		require.ErrorContains(t, WaitForConnection(t.Context(), client, "node-1", WaitConfig{Timeout: time.Second}), "invalid JD response")
	})
	t.Run("timeout", func(t *testing.T) {
		t.Parallel()
		client := newFakeJD()
		client.addNode(&nodev1.Node{Id: "node-1"})
		err := WaitForConnection(t.Context(), client, "node-1", WaitConfig{Timeout: 20 * time.Millisecond, PollInterval: time.Millisecond})
		require.ErrorContains(t, err, "timeout waiting for node node-1")
	})
}

func TestWaitForConnectionBoundsHungRPC(t *testing.T) {
	t.Parallel()
	client := newFakeJD()
	client.getNodeFunc = func(ctx context.Context, _ *nodev1.GetNodeRequest) (*nodev1.GetNodeResponse, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	start := time.Now()
	err := WaitForConnection(t.Context(), client, "node-1", WaitConfig{Timeout: 30 * time.Millisecond, PollInterval: time.Millisecond})
	require.ErrorContains(t, err, "timeout waiting for node node-1")
	require.Less(t, time.Since(start), time.Second)
}

func TestWaitForConnectionInputValidation(t *testing.T) {
	t.Parallel()
	client := newFakeJD()
	require.ErrorContains(t, WaitForConnection(t.Context(), nil, "node-1", WaitConfig{}), "JD client is required")
	require.ErrorContains(t, WaitForConnection(t.Context(), client, "", WaitConfig{}), "node ID is required")
}

func TestRegisterAndWait(t *testing.T) {
	t.Parallel()
	t.Run("registered and connected", func(t *testing.T) {
		t.Parallel()
		client := newFakeJD()
		client.getNodeFunc = func(_ context.Context, req *nodev1.GetNodeRequest) (*nodev1.GetNodeResponse, error) {
			if req.PublicKey != nil {
				return nil, status.Error(codes.NotFound, "missing")
			}
			node := client.snapshotNodes()[req.Id]
			if node == nil {
				return nil, status.Error(codes.NotFound, "missing")
			}
			node.IsConnected = true
			return &nodev1.GetNodeResponse{Node: node}, nil
		}
		result, err := RegisterAndWait(t.Context(), client, StaticCSAKeyProvider(validCSAKey(1)), testNodeSpec("verifier-0"), WaitConfig{Timeout: time.Second})
		require.NoError(t, err)
		require.Equal(t, StatusRegistered, result.Status)
		require.NotEmpty(t, result.NodeID)
	})
	t.Run("registration result survives connection timeout", func(t *testing.T) {
		t.Parallel()
		client := newFakeJD()
		result, err := RegisterAndWait(t.Context(), client, StaticCSAKeyProvider(validCSAKey(1)), testNodeSpec("verifier-0"), WaitConfig{Timeout: 20 * time.Millisecond, PollInterval: time.Millisecond})
		require.ErrorContains(t, err, "timeout waiting")
		require.NotEmpty(t, result.NodeID)
		require.Equal(t, StatusRegistered, result.Status)
	})
}
