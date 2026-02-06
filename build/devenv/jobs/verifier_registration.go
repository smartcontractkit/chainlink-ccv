// Package jobs provides utilities for Job Distributor operations in devenv.
package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-deployments-framework/offchain"
	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"
)

// VerifierJDRegistration holds the information needed to register a verifier with JD.
type VerifierJDRegistration struct {
	Name           string
	CSAPublicKey   string
	SigningAddress string
	NodeID         string // Set after registration
}

// RegisterVerifierWithJD registers a standalone verifier with JD using its CSA public key.
// This allows JD to route job proposals to the verifier.
// The verifier must already be started and have its CSA key available.
func RegisterVerifierWithJD(ctx context.Context, jdClient offchain.Client, reg *VerifierJDRegistration) error {
	if reg.CSAPublicKey == "" {
		return fmt.Errorf("CSA public key is required to register verifier %s", reg.Name)
	}

	resp, err := jdClient.RegisterNode(ctx, &nodev1.RegisterNodeRequest{
		Name:      reg.Name,
		PublicKey: reg.CSAPublicKey,
	})
	if err != nil {
		return fmt.Errorf("failed to register verifier %s with JD: %w", reg.Name, err)
	}

	reg.NodeID = resp.Node.Id
	Plog.Info().
		Str("verifier", reg.Name).
		Str("nodeID", resp.Node.Id).
		Str("csaKey", reg.CSAPublicKey[:16]+"...").
		Msg("Registered verifier with JD")

	return nil
}

// WaitForVerifierConnection waits for a verifier to connect to JD after registration.
func WaitForVerifierConnection(ctx context.Context, jdClient offchain.Client, nodeID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return fmt.Errorf("timeout waiting for verifier %s to connect to JD", nodeID)
			}

			nodeResp, err := jdClient.GetNode(ctx, &nodev1.GetNodeRequest{Id: nodeID})
			if err != nil {
				Plog.Debug().Str("nodeID", nodeID).Err(err).Msg("Failed to get node status, retrying...")
				continue
			}

			if nodeResp.Node != nil && nodeResp.Node.IsConnected {
				Plog.Info().Str("nodeID", nodeID).Msg("Verifier connected to JD")
				return nil
			}

			Plog.Debug().Str("nodeID", nodeID).Bool("isConnected", nodeResp.Node.IsConnected).Msg("Verifier not yet connected, waiting...")
		}
	}
}
