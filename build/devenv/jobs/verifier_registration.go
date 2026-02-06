// Package jobs provides utilities for Job Distributor operations in devenv.
package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/sethvargo/go-retry"
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

// NOTE: Full JD registration integration would require:
// 1. Update NewVerifier to not provision signing key
// 2. Start verifier container in JD mode (with JD_WSRPC_URL env var)
// 3. Query /info to get CSA and signing keys
// 4. Register verifier with JD using CSA key
// 5. Deploy contracts with signing address
// 6. Propose job to verifier via JD with TOML config
//
// This follows the same pattern as Chainlink node deployment.
