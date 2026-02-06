// Package jobs provides utilities for Job Distributor operations in devenv.
package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/sethvargo/go-retry"

	"github.com/smartcontractkit/chainlink-deployments-framework/offchain"
	jobv1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/job"
	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"
)

// VerifierKeys represents the keys exposed by a verifier's /info endpoint.
type VerifierKeys struct {
	SigningAddress string `json:"signing_address"`
	CSAPublicKey   string `json:"csa_public_key"`
}

// QueryVerifierKeys polls the verifier's /info endpoint until keys are available.
// This is used in devenv to discover the verifier's generated keys after it starts.
func QueryVerifierKeys(ctx context.Context, verifierURL string) (*VerifierKeys, error) {
	var keys VerifierKeys

	backoff := retry.WithMaxDuration(60*time.Second, retry.NewExponential(1*time.Second))

	err := retry.Do(ctx, backoff, func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, verifierURL+"/info", nil)
		if err != nil {
			return retry.RetryableError(err)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return retry.RetryableError(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return retry.RetryableError(fmt.Errorf("status %d", resp.StatusCode))
		}

		if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
			return retry.RetryableError(err)
		}

		// Validate that we have both keys
		if keys.SigningAddress == "" || keys.CSAPublicKey == "" {
			return retry.RetryableError(fmt.Errorf("incomplete key info"))
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to query verifier keys from %s: %w", verifierURL, err)
	}

	return &keys, nil
}

// QueryVerifierHealth polls the verifier's /health endpoint until it returns healthy.
func QueryVerifierHealth(ctx context.Context, verifierURL string) error {
	backoff := retry.WithMaxDuration(120*time.Second, retry.NewExponential(2*time.Second))

	return retry.Do(ctx, backoff, func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, verifierURL+"/health", nil)
		if err != nil {
			return retry.RetryableError(err)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return retry.RetryableError(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return retry.RetryableError(fmt.Errorf("health check failed with status %d", resp.StatusCode))
		}

		return nil
	})
}

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

// ProposeJobToVerifier proposes a job spec to a standalone verifier via JD.
func ProposeJobToVerifier(ctx context.Context, jdClient offchain.Client, nodeID, jobSpec string) (string, error) {
	resp, err := jdClient.ProposeJob(ctx, &jobv1.ProposeJobRequest{
		NodeId: nodeID,
		Spec:   jobSpec,
	})
	if err != nil {
		return "", fmt.Errorf("failed to propose job to verifier: %w", err)
	}

	Plog.Info().
		Str("nodeID", nodeID).
		Str("proposalID", resp.Proposal.Id).
		Str("jobID", resp.Proposal.JobId).
		Msg("Proposed job to verifier")

	return resp.Proposal.Id, nil
}
