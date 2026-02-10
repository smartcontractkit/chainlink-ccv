package kmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

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

// doJSON performs a JSON POST with req and returns the response decoded into T.
// statusErrMsg is used in the error when status is not 200.
func doJSON[T any](c *Client, ctx context.Context, endpoint, statusErrMsg string, req any) (T, error) {
	var zero T
	body, err := json.Marshal(req)
	if err != nil {
		return zero, fmt.Errorf("failed to marshal request: %w", err)
	}
	reqURL, err := url.JoinPath(c.kmdURL, strings.TrimPrefix(endpoint, "/"))
	if err != nil {
		return zero, fmt.Errorf("failed to build request URL: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, "POST", reqURL, bytes.NewReader(body))
	if err != nil {
		return zero, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.ContentLength = int64(len(body))
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return zero, fmt.Errorf("failed to do HTTP request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return zero, fmt.Errorf("%s: %s", statusErrMsg, resp.Status)
	}
	var result T
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return zero, fmt.Errorf("failed to decode response: %w", err)
	}
	return result, nil
}

func (c *Client) CreateKeys(ctx context.Context, req ks.CreateKeysRequest) (ks.CreateKeysResponse, error) {
	return doJSON[ks.CreateKeysResponse](c, ctx, CreateEndpoint, "failed to create keys", req)
}

// GetKeys gets keys from the KMD server.
func (c *Client) GetKeys(ctx context.Context, req ks.GetKeysRequest) (ks.GetKeysResponse, error) {
	return doJSON[ks.GetKeysResponse](c, ctx, GetKeysEndpoint, "failed to get keys", req)
}

// Sign signs data using the KMD server and returns the signature.
func (c *Client) Sign(ctx context.Context, req ks.SignRequest) (ks.SignResponse, error) {
	return doJSON[ks.SignResponse](c, ctx, SignEndpoint, "failed to sign data", req)
}
