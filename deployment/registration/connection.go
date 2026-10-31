package registration

import (
	"context"
	"fmt"
	"time"

	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"
)

// WaitForConnection waits until JD reports the requested node connected or the timeout expires.
func WaitForConnection(ctx context.Context, client JDClient, nodeID string, config WaitConfig) error {
	if client == nil {
		return fmt.Errorf("JD client is required to wait for node %s", nodeID)
	}
	if nodeID == "" {
		return fmt.Errorf("node ID is required to wait for a JD connection")
	}
	config = config.withDefaults()
	start := time.Now()
	deadline := start.Add(config.Timeout)

	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("timeout waiting for node %s to connect to JD after %s", nodeID, time.Since(start).Round(time.Second))
		}
		rpcCtx, cancel := context.WithTimeout(ctx, remaining)
		resp, err := client.GetNode(rpcCtx, &nodev1.GetNodeRequest{Id: nodeID})
		cancel()
		if err == nil {
			if resp == nil || resp.Node == nil || resp.Node.Id != nodeID {
				return fmt.Errorf("invalid JD response while waiting for node %s to connect", nodeID)
			}
			if resp.Node.IsConnected {
				return nil
			}
		} else if ctx.Err() != nil {
			return fmt.Errorf("wait for node %s to connect: %w", nodeID, ctx.Err())
		}

		timer := time.NewTimer(config.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("wait for node %s to connect: %w", nodeID, ctx.Err())
		case <-timer.C:
		}
	}
}
