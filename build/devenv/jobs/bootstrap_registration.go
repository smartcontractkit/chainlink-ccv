// Package jobs provides utilities for Job Distributor operations in devenv.
package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-deployments-framework/offchain"

	"github.com/smartcontractkit/chainlink-ccv/deployment/registration"
)

const (
	DefaultRegistrationProduct     = "ccv"
	DefaultRegistrationEnvironment = "devenv"
)

// BootstrapJDRegistration holds the information needed to register a bootstrap with JD.
type BootstrapJDRegistration struct {
	Name         string
	CSAPublicKey string
	NodeID       string // Set after registration
}

// CSAKeyProvider supplies the CSA public key used to register a node with JD.
type CSAKeyProvider = registration.CSAKeyProvider

// BootstrapCSAKeyProvider supplies an already resolved bootstrap CSA public key.
type BootstrapCSAKeyProvider = registration.StaticCSAKeyProvider

// DevenvNodeSpec returns the common identity used for normal devenv JD registrations.
func DevenvNodeSpec(name string) registration.NodeSpec {
	return registration.NodeSpec{
		Name:        name,
		Product:     DefaultRegistrationProduct,
		Environment: DefaultRegistrationEnvironment,
	}
}

// RegisterNodeWithJD reconciles a node registration and returns its JD node ID.
func RegisterNodeWithJD(ctx context.Context, provider CSAKeyProvider, alias string, jdClient offchain.Client) (string, error) {
	if provider == nil {
		return "", fmt.Errorf("CSA key provider is required to register node %s", alias)
	}
	if jdClient == nil {
		return "", fmt.Errorf("JD client is required to register node %s", alias)
	}
	result, err := registration.Register(ctx, jdClient, provider, DevenvNodeSpec(alias))
	if err != nil {
		return "", fmt.Errorf("failed to register node %s with JD: %w", alias, err)
	}

	Plog.Info().
		Str("node", alias).
		Str("nodeID", result.NodeID).
		Str("status", string(result.Status)).
		Msg("Reconciled node registration with JD")
	return result.NodeID, nil
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
	return registration.WaitForConnection(ctx, jdClient, nodeID, registration.WaitConfig{Timeout: timeout})
}
