// Package jobs provides utilities for Job Distributor operations in devenv.
package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-deployments-framework/offchain"
	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"
)

// BootstrapJDRegistration holds the information needed to register a bootstrap with JD.
type BootstrapJDRegistration struct {
	Name         string
	CSAPublicKey string
	NodeID       string // Set after registration
}

// RegisterBootstrapWithJD registers a bootstrap with JD using its CSA public key.
// This allows JD to route job proposals to the bootstrap.
// The bootstrap must already be started and have its CSA key available.
func RegisterBootstrapWithJD(ctx context.Context, jdClient offchain.Client, reg *BootstrapJDRegistration) error {
	if reg.CSAPublicKey == "" {
		return fmt.Errorf("CSA public key is required to register bootstrap %s", reg.Name)
	}

	resp, err := jdClient.RegisterNode(ctx, &nodev1.RegisterNodeRequest{
		Name:      reg.Name,
		PublicKey: reg.CSAPublicKey,
	})
	if err != nil {
		return fmt.Errorf("failed to register bootstrap %s with JD: %w", reg.Name, err)
	}

	reg.NodeID = resp.Node.Id
	Plog.Info().
		Str("bootstrap", reg.Name).
		Str("nodeID", resp.Node.Id).
		Str("csaKey", reg.CSAPublicKey[:16]+"...").
		Msg("Registered bootstrap with JD")

	return nil
}

// WaitForBootstrapConnection waits for a bootstrap to connect to JD after registration.
func WaitForBootstrapConnection(ctx context.Context, jdClient offchain.Client, nodeID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return fmt.Errorf("timeout waiting for bootstrap %s to connect to JD", nodeID)
			}

			nodeResp, err := jdClient.GetNode(ctx, &nodev1.GetNodeRequest{Id: nodeID})
			if err != nil {
				Plog.Debug().Str("nodeID", nodeID).Err(err).Msg("Failed to get node status, retrying...")
				continue
			}

			if nodeResp.Node != nil && nodeResp.Node.IsConnected {
				Plog.Info().Str("nodeID", nodeID).Msg("Bootstrap connected to JD")
				return nil
			}

			Plog.Debug().Str("nodeID", nodeID).Bool("isConnected", nodeResp.Node.IsConnected).Msg("Bootstrap not yet connected, waiting...")
		}
	}
}
