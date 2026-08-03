package migration

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/smartcontractkit/chainlink-deployments-framework/offchain"
	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"
)

// FindNodeByCSAKey returns the JD node record registered under a CSA public key. The cutover uses
// it to find the record belonging to the Chainlink node it is about to replace, keyed on the node's
// own CSA key rather than on its name: JD has no name filter, and matching on a name would pick the
// wrong record in a deployment where two node operators chose the same one.
//
// Call it before stopping the Chainlink node, while its CSA key is still readable.
func FindNodeByCSAKey(ctx context.Context, jdClient offchain.Client, csaPublicKey string) (*nodev1.Node, error) {
	if jdClient == nil {
		return nil, fmt.Errorf("JD client is required to look up a node")
	}
	if csaPublicKey == "" {
		return nil, fmt.Errorf("a CSA public key is required to look up a node")
	}

	resp, err := jdClient.ListNodes(ctx, &nodev1.ListNodesRequest{
		Filter: &nodev1.ListNodesRequest_Filter{PublicKeys: []string{csaPublicKey}},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list JD nodes by CSA key: %w", err)
	}
	switch len(resp.GetNodes()) {
	case 1:
		return resp.GetNodes()[0], nil
	case 0:
		return nil, fmt.Errorf("no JD node is registered under CSA key %s", csaPublicKey)
	default:
		return nil, fmt.Errorf("%d JD nodes are registered under CSA key %s", len(resp.GetNodes()), csaPublicKey)
	}
}

// AdoptJDIdentity repoints an existing JD node record at a new CSA public key, so the standalone
// verifier takes over the record the Chainlink node was using rather than registering a second one.
//
// This is why the CSA private key never has to be exported. JD identifies a node by the CSA key it
// authenticates with, so the alternative — carrying the key across — would mean copying a private
// key out of the node and, for the window in which both processes hold it, two processes able to
// claim the same identity. Repointing the record leaves the node ID, its name, and its job history
// in place while the key itself is only ever generated where it is used.
//
// The Chainlink node must already be stopped: while it is connected, it and the standalone verifier
// are two processes contending for one record.
func AdoptJDIdentity(ctx context.Context, jdClient offchain.Client, nodeID, name, csaPublicKey string) error {
	if jdClient == nil {
		return fmt.Errorf("JD client is required to adopt node %s", nodeID)
	}
	if nodeID == "" {
		return fmt.Errorf("node ID is required to adopt a JD identity")
	}
	if csaPublicKey == "" {
		return fmt.Errorf("node %s: a CSA public key is required", nodeID)
	}

	if _, err := jdClient.UpdateNode(ctx, &nodev1.UpdateNodeRequest{
		Id:        nodeID,
		Name:      name,
		PublicKey: csaPublicKey,
	}); err != nil {
		return fmt.Errorf("failed to repoint JD node %s (%s) at the standalone CSA key: %w", name, nodeID, err)
	}
	return nil
}

// WaitForNodeConnected blocks until JD reports the node as connected, which after AdoptJDIdentity
// means the standalone process has authenticated with the adopted record. Without this wait, job
// proposals can be sent to a record whose new owner has not dialed in yet and sit unclaimed.
func WaitForNodeConnected(ctx context.Context, jdClient offchain.Client, nodeID string, timeout time.Duration) error {
	if jdClient == nil {
		return fmt.Errorf("JD client is required to wait for node %s", nodeID)
	}
	if nodeID == "" {
		return fmt.Errorf("node ID is required to wait for a JD connection")
	}
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var lastErr error
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			resp, err := jdClient.GetNode(ctx, &nodev1.GetNodeRequest{Id: nodeID})
			if err != nil {
				lastErr = err
			} else if resp.GetNode().GetIsConnected() {
				return nil
			}
			if time.Now().After(deadline) {
				if lastErr != nil {
					return fmt.Errorf("timed out waiting for JD node %s to connect, last error: %w", nodeID, lastErr)
				}
				return fmt.Errorf("timed out waiting for JD node %s to connect", nodeID)
			}
		}
	}
}

// StopCLNodes stops the given Chainlink node containers and waits for them to exit. It is the step
// that makes the cutover a cutover: the standalone verifier adopts the node's JD record, so the
// node has to be off the record before the verifier comes up.
//
// The containers are stopped rather than removed, so a failed migration can be diagnosed from their
// logs and, in devenv, restarted.
func StopCLNodes(ctx context.Context, containerNames []string) error {
	if len(containerNames) == 0 {
		return nil
	}
	args := append([]string{"stop"}, containerNames...)
	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to stop Chainlink node containers %v: %w: %s",
			containerNames, err, strings.TrimSpace(string(output)))
	}
	return nil
}
