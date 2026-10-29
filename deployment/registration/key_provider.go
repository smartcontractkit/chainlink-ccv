package registration

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap/info"
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
	keys, err := info.FetchPublicKeys(ctx, p.HTTPClient, p.URL, info.DefaultCSAKeyName)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(keys[info.DefaultCSAKeyName]), nil
}
