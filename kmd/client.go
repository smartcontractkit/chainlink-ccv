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

func (c *Client) CreateKeys(ctx context.Context, req ks.CreateKeysRequest) (ks.CreateKeysResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return ks.CreateKeysResponse{}, fmt.Errorf("failed to marshal create keys request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s%s", c.kmdURL, CreateEndpoint), bytes.NewReader(body))
	if err != nil {
		return ks.CreateKeysResponse{}, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.ContentLength = int64(len(body))
	fmt.Printf("creating keys with request: %s\n", string(body))
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return ks.CreateKeysResponse{}, fmt.Errorf("failed to do HTTP request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return ks.CreateKeysResponse{}, fmt.Errorf("failed to create keys: %s", resp.Status)
	}
	var createKeysResponse ks.CreateKeysResponse
	if err := json.NewDecoder(resp.Body).Decode(&createKeysResponse); err != nil {
		return ks.CreateKeysResponse{}, fmt.Errorf("failed to decode create keys response: %w", err)
	}
	return createKeysResponse, nil
}

// GetKeys gets keys from the KMD server.
func (c *Client) GetKeys(ctx context.Context, req ks.GetKeysRequest) (ks.GetKeysResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return ks.GetKeysResponse{}, fmt.Errorf("failed to marshal get keys request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s%s", c.kmdURL, GetKeysEndpoint), bytes.NewReader(body))
	if err != nil {
		return ks.GetKeysResponse{}, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.ContentLength = int64(len(body))
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return ks.GetKeysResponse{}, fmt.Errorf("failed to do HTTP request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return ks.GetKeysResponse{}, fmt.Errorf("failed to get keys: %s", resp.Status)
	}
	var getKeysResponse ks.GetKeysResponse
	if err := json.NewDecoder(resp.Body).Decode(&getKeysResponse); err != nil {
		return ks.GetKeysResponse{}, fmt.Errorf("failed to decode get keys response: %w", err)
	}
	return getKeysResponse, nil
}

// Sign signs data using the KMD server and returns the signature.
func (c *Client) Sign(ctx context.Context, req ks.SignRequest) (ks.SignResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return ks.SignResponse{}, fmt.Errorf("failed to marshal sign request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s%s", c.kmdURL, SignEndpoint), bytes.NewReader(body))
	if err != nil {
		return ks.SignResponse{}, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.ContentLength = int64(len(body))
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return ks.SignResponse{}, fmt.Errorf("failed to do HTTP request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return ks.SignResponse{}, fmt.Errorf("failed to sign data: %s", resp.Status)
	}
	var signResponse ks.SignResponse
	if err := json.NewDecoder(resp.Body).Decode(&signResponse); err != nil {
		return ks.SignResponse{}, fmt.Errorf("failed to decode sign response: %w", err)
	}
	return signResponse, nil
}
