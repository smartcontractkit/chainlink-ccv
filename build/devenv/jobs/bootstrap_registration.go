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

// CSAKeyProvider supplies the CSA public key used to register a node with JD.
// Implementations may obtain the key from a CL node API, a bootstrap info
// server, or any other node-specific source.
type CSAKeyProvider interface {
	CSAKey(context.Context) (string, error)
}

// BootstrapCSAKeyProvider provides the CSA key fetched from a standalone
// service's bootstrap HTTP info server.
type BootstrapCSAKeyProvider string

func (p BootstrapCSAKeyProvider) CSAKey(context.Context) (string, error) {
	if p == "" {
		return "", fmt.Errorf("CSA public key is empty")
	}
	return string(p), nil
}

// RegisterNodeWithJD registers a node regardless of how its CSA key is
// obtained and returns the JD node ID.
func RegisterNodeWithJD(ctx context.Context, provider CSAKeyProvider, alias string, jdClient offchain.Client) (string, error) {
	if provider == nil {
		return "", fmt.Errorf("CSA key provider is required to register node %s", alias)
	}
	if jdClient == nil {
		return "", fmt.Errorf("JD client is required to register node %s", alias)
	}

	csaKey, err := provider.CSAKey(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get CSA key for node %s: %w", alias, err)
	}

	resp, err := jdClient.RegisterNode(ctx, &nodev1.RegisterNodeRequest{
		Name:      alias,
		PublicKey: csaKey,
	})
	if err != nil {
		return "", fmt.Errorf("failed to register node %s with JD: %w", alias, err)
	}
	if resp == nil || resp.Node == nil {
		return "", fmt.Errorf("JD returned no node when registering %s", alias)
	}

	Plog.Info().
		Str("node", alias).
		Str("nodeID", resp.Node.Id).
		Msg("Registered node with JD")
	return resp.Node.Id, nil
}

// RegisterBootstrapWithJD registers a bootstrap with JD using its CSA public key.
// This allows JD to route job proposals to the bootstrap.
// The bootstrap must already be started and have its CSA key available.
func RegisterBootstrapWithJD(ctx context.Context, jdClient offchain.Client, reg *BootstrapJDRegistration) error {
	if reg == nil {
		return fmt.Errorf("bootstrap registration is required")
	}
	if reg.CSAPublicKey == "" {
		return fmt.Errorf("CSA public key is required to register bootstrap %s", reg.Name)
	}

	nodeID, err := RegisterNodeWithJD(ctx, BootstrapCSAKeyProvider(reg.CSAPublicKey), reg.Name, jdClient)
	if err != nil {
		return fmt.Errorf("failed to register bootstrap %s with JD: %w", reg.Name, err)
	}

	reg.NodeID = nodeID

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
