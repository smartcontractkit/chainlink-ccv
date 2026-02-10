package kmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	ks "github.com/smartcontractkit/chainlink-common/keystore"
)

// Client is an HTTP client for the KMD server.
type Client struct {
	kmdURL string
	client *http.Client
}

// NewClient creates a new Client.
func NewClient(kmdURL string) *Client {
	return &Client{
		kmdURL: kmdURL,
		client: http.DefaultClient,
	}
}

// Sign signs data using the KMD server.
func (c *Client) Sign(ctx context.Context, req ks.SignRequest) (ks.SignResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return ks.SignResponse{}, fmt.Errorf("failed to marshal sign request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/signer/sign", c.kmdURL), bytes.NewBuffer(body))
	if err != nil {
		return ks.SignResponse{}, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return ks.SignResponse{}, fmt.Errorf("failed to do HTTP request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ks.SignResponse{}, fmt.Errorf("failed to sign data: %s", resp.Status)
	}
	var signResponse ks.SignResponse
	if err := json.NewDecoder(resp.Body).Decode(&signResponse); err != nil {
		return ks.SignResponse{}, fmt.Errorf("failed to decode sign response: %w", err)
	}
	return signResponse, nil
}
