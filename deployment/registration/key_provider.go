package registration

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/smartcontractkit/chainlink-common/keystore"
)

const (
	defaultHTTPTimeout  = 10 * time.Second
	maxKeyResponseBytes = 1 << 20
)

// CSAKeyProvider supplies the chain-agnostic public key used for JD authentication.
type CSAKeyProvider interface {
	// CSAKey returns the node's CSA public key.
	CSAKey(context.Context) (string, error)
}

// StaticCSAKeyProvider supplies an already resolved CSA public key.
type StaticCSAKeyProvider string

func (p StaticCSAKeyProvider) CSAKey(context.Context) (string, error) {
	if strings.TrimSpace(string(p)) == "" {
		return "", fmt.Errorf("CSA public key is empty")
	}
	return string(p), nil
}

// InfoServerCSAKeyProvider resolves a node's CSA key through its bootstrap info server.
type InfoServerCSAKeyProvider struct {
	URL        string
	HTTPClient *http.Client
}

func (p InfoServerCSAKeyProvider) CSAKey(ctx context.Context) (string, error) {
	keys, err := FetchPublicKeys(ctx, p.HTTPClient, p.URL, DefaultCSAKeyName)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(keys[DefaultCSAKeyName]), nil
}

// FetchPublicKeys retrieves named public keys without interpreting any chain-specific key type.
func FetchPublicKeys(ctx context.Context, client *http.Client, infoServerURL string, keyNames ...string) (map[string][]byte, error) {
	if len(keyNames) == 0 {
		return nil, fmt.Errorf("at least one key name is required")
	}
	endpoint, err := keyEndpoint(infoServerURL)
	if err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{Timeout: defaultHTTPTimeout}
	}

	payload, err := json.Marshal(keystore.GetKeysRequest{KeyNames: keyNames})
	if err != nil {
		return nil, fmt.Errorf("marshal key request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create key request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch public keys: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch public keys: unexpected HTTP status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxKeyResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read key response: %w", err)
	}
	if len(body) > maxKeyResponseBytes {
		return nil, fmt.Errorf("key response exceeds %d bytes", maxKeyResponseBytes)
	}
	var response keystore.GetKeysResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("decode key response: %w", err)
	}

	keys := make(map[string][]byte, len(response.Keys))
	for _, key := range response.Keys {
		name := key.KeyInfo.Name
		if _, exists := keys[name]; exists {
			return nil, fmt.Errorf("duplicate key %q in response", name)
		}
		keys[name] = key.KeyInfo.PublicKey
	}
	for _, name := range keyNames {
		key, ok := keys[name]
		if !ok {
			return nil, fmt.Errorf("key %q not found in response", name)
		}
		if len(key) == 0 {
			return nil, fmt.Errorf("key %q has an empty public key", name)
		}
	}
	return keys, nil
}

func keyEndpoint(infoServerURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(infoServerURL))
	if err != nil {
		return "", fmt.Errorf("parse bootstrap info-server URL: %w", err)
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return "", fmt.Errorf("bootstrap info-server URL must use http or https and include a host")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("bootstrap info-server URL must not contain credentials, query, or fragment")
	}
	return strings.TrimRight(parsed.String(), "/") + GetKeysEndpoint, nil
}
