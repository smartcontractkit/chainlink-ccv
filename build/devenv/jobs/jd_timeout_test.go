package jobs

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/smartcontractkit/chainlink-deployments-framework/offchain"
	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"
)

func TestJDInfrastructureConnectTimeout(t *testing.T) {
	t.Run("default when unset", func(t *testing.T) {
		require.Equal(t, DefaultNodeConnectTimeout, (&JDInfrastructure{}).ConnectTimeout())
	})

	t.Run("default when infra is nil", func(t *testing.T) {
		var infra *JDInfrastructure
		require.Equal(t, DefaultNodeConnectTimeout, infra.ConnectTimeout())
	})

	t.Run("override via node_connect_timeout", func(t *testing.T) {
		infra := &JDInfrastructure{NodeConnectTimeout: "5m"}
		require.Equal(t, 5*time.Minute, infra.ConnectTimeout())
	})

	t.Run("sub-minute override", func(t *testing.T) {
		infra := &JDInfrastructure{NodeConnectTimeout: "10s"}
		require.Equal(t, 10*time.Second, infra.ConnectTimeout())
	})

	t.Run("invalid duration falls back to default", func(t *testing.T) {
		infra := &JDInfrastructure{NodeConnectTimeout: "bogus"}
		require.Equal(t, DefaultNodeConnectTimeout, infra.ConnectTimeout())
	})

	t.Run("non-positive duration falls back to default", func(t *testing.T) {
		infra := &JDInfrastructure{NodeConnectTimeout: "0s"}
		require.Equal(t, DefaultNodeConnectTimeout, infra.ConnectTimeout())
	})
}

// hungGetNodeClient blocks every GetNode until its request context is
// canceled, simulating an unresponsive JD.
type hungGetNodeClient struct {
	offchain.Client
}

func (hungGetNodeClient) GetNode(ctx context.Context, _ *nodev1.GetNodeRequest, _ ...grpc.CallOption) (*nodev1.GetNodeResponse, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestWaitForNodeConnectionBoundsHungRPC guards the per-RPC deadline: a hung
// GetNode must not outlive the configured timeout.
func TestWaitForNodeConnectionBoundsHungRPC(t *testing.T) {
	start := time.Now()
	err := WaitForNodeConnection(t.Context(), hungGetNodeClient{}, "node-1", 3*time.Second)
	require.ErrorContains(t, err, "timeout waiting for node node-1 to connect to JD")
	require.Less(t, time.Since(start), 10*time.Second, "a hung GetNode must not outlive the timeout")
}
