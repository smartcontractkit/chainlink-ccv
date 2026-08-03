package migration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

// nodeAPIPrefix is where the node mounts its REST API. The session endpoint lives outside it.
const nodeAPIPrefix = "/v2"

// NodeClient is a minimal client for the slice of a Chainlink node's REST API the migration
// needs: session login, the key listings used to resolve what to export, the job list used for
// the preflight check, and the two key export endpoints. It exists because the devenv client —
// chainlink-testing-framework's clclient and the chainlink deployment SDK — lives in the devenv
// module, and importing either here would drag the whole Chainlink node dependency graph into
// the verifier and executor binaries for four HTTP calls.
type NodeClient struct {
	baseURL string
	http    *http.Client
}

// NewNodeClient builds a client for a node's base URL, e.g. http://localhost:6688. The cookie
// jar holds the session Login creates, so the caller authenticates once and then uses the client
// normally.
func NewNodeClient(rawURL string) (*NodeClient, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, fmt.Errorf("invalid node URL %q: %w", rawURL, err)
	}
	if u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("invalid node URL %q: expected http(s)://host[:port]", rawURL)
	}
	// baseURL is rebuilt from the parsed URL rather than kept raw: a pasted URL carrying a path,
	// query or fragment would turn every request into <path>/v2/..., which fails confusingly.
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("invalid node URL %q: expected the base URL only, http(s)://host[:port]", rawURL)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie jar: %w", err)
	}
	return &NodeClient{
		baseURL: u.Scheme + "://" + u.Host,
		http:    &http.Client{Jar: jar, Timeout: 30 * time.Second},
	}, nil
}

// Login authenticates the client with the node's API credentials — the same email and password
// the operator UI takes. The export endpoints require an admin role, which the UI account has.
func (c *NodeClient) Login(ctx context.Context, email, password string) error {
	body, err := json.Marshal(map[string]string{"email": email, "password": password})
	if err != nil {
		return fmt.Errorf("failed to encode the login request: %w", err)
	}
	respBody, status, err := c.do(ctx, http.MethodPost, "/sessions", nil, bytes.NewReader(body), "application/json")
	if err != nil {
		return err
	}
	if status == http.StatusUnauthorized {
		return fmt.Errorf("the node rejected the API credentials (401 unauthorized): check the credentials")
	}
	if status != http.StatusOK {
		return fmt.Errorf("login failed: %s", statusError(status, respBody))
	}
	return nil
}

// EVMOCR2BundleID returns the ID of the node's OCR2 key bundle for EVM — the bundle whose
// onchain signing key the node publishes to JD, and therefore the one sitting in the
// CommitteeVerifier signer set. A node with several EVM bundles is an error rather than a guess:
// exporting either without checking which one JD records risks importing an identity no contract
// knows about.
func (c *NodeClient) EVMOCR2BundleID(ctx context.Context) (string, error) {
	list, err := getList[ocr2BundleAttributes](ctx, c, nodeAPIPrefix+"/keys/ocr2")
	if err != nil {
		return "", err
	}
	var evm []string
	for _, item := range list.Data {
		if strings.EqualFold(item.Attributes.ChainType, "evm") {
			evm = append(evm, item.ID)
		}
	}
	switch len(evm) {
	case 1:
		return evm[0], nil
	case 0:
		return "", fmt.Errorf("the node has no OCR2 key bundle for EVM; there is no signing key to migrate")
	default:
		return "", fmt.Errorf(
			"the node has %d EVM OCR2 key bundles (%s) and only one can be registered with the committee; "+
				"name the one whose onchain signing address the JD node record publishes (--bundle-id)",
			len(evm), strings.Join(evm, ", "))
	}
}

// AccountForChain returns the account address enabled for chainID — the funded transmitter the
// node's executor job submits from, and the account the node's JD chain config recorded when it
// was created. Keys disabled for the chain are skipped, mirroring how the node picks its
// transmitter.
func (c *NodeClient) AccountForChain(ctx context.Context, chainID string) (string, error) {
	list, err := getList[ethKeyAttributes](ctx, c, nodeAPIPrefix+"/keys/eth")
	if err != nil {
		return "", err
	}
	var matches []string
	for _, item := range list.Data {
		if item.Attributes.Disabled {
			continue
		}
		if item.Attributes.EVMChainID.String() != chainID {
			continue
		}
		matches = append(matches, item.Attributes.Address)
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return "", fmt.Errorf("the node has no account enabled for chain %s", chainID)
	default:
		return "", fmt.Errorf(
			"the node has %d accounts enabled for chain %s (%s); name the one the executor transmits from (--account)",
			len(matches), chainID, strings.Join(matches, ", "))
	}
}

// CCVJobCounts counts the node's CCV jobs by type, for the preflight check.
func (c *NodeClient) CCVJobCounts(ctx context.Context) (verifiers, executors int, err error) {
	list, err := getList[jobAttributes](ctx, c, nodeAPIPrefix+"/jobs")
	if err != nil {
		return 0, 0, err
	}
	for _, item := range list.Data {
		switch item.Attributes.Type {
		case JobTypeVerifier:
			verifiers++
		case JobTypeExecutor:
			executors++
		}
	}
	return verifiers, executors, nil
}

// ExportOCR2Bundle downloads the `chainlink keys ocr2 export` file for id, encrypted under
// password. The raw body is byte-for-byte the file the standalone verifier imports.
func (c *NodeClient) ExportOCR2Bundle(ctx context.Context, id, password string) ([]byte, error) {
	return c.exportKey(ctx, nodeAPIPrefix+"/keys/ocr2/export/"+url.PathEscape(id), password)
}

// ExportETHKey downloads the `chainlink keys eth export` file for address, encrypted under
// password.
func (c *NodeClient) ExportETHKey(ctx context.Context, address, password string) ([]byte, error) {
	return c.exportKey(ctx, nodeAPIPrefix+"/keys/eth/export/"+url.PathEscape(address), password)
}

func (c *NodeClient) exportKey(ctx context.Context, path, password string) ([]byte, error) {
	query := url.Values{"newpassword": []string{password}}
	body, status, err := c.do(ctx, http.MethodPost, path, query, nil, "")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("POST %s failed: %s", path, statusError(status, body))
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("POST %s returned an empty body", path)
	}
	return body, nil
}

// ocr2BundleAttributes, ethKeyAttributes and jobAttributes are the fields of each list endpoint's
// attributes object the migration reads. Everything else in the response is left undecoded.
type ocr2BundleAttributes struct {
	ChainType string `json:"chainType"`
}

type ethKeyAttributes struct {
	Address    string      `json:"address"`
	EVMChainID json.Number `json:"evmChainID"`
	Disabled   bool        `json:"disabled"`
}

type jobAttributes struct {
	Type string `json:"type"`
}

// jsonAPIList is the envelope every v2 list endpoint answers with.
type jsonAPIList[A any] struct {
	Data []struct {
		ID         string `json:"id"`
		Attributes A      `json:"attributes"`
	} `json:"data"`
}

func getList[A any](ctx context.Context, c *NodeClient, path string) (jsonAPIList[A], error) {
	var out jsonAPIList[A]
	body, status, err := c.do(ctx, http.MethodGet, path, nil, nil, "")
	if err != nil {
		return out, err
	}
	if status != http.StatusOK {
		return out, fmt.Errorf("GET %s failed: %s", path, statusError(status, body))
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, fmt.Errorf("GET %s returned a response this tool does not understand: %w", path, err)
	}
	return out, nil
}

// do performs one request and returns the raw body and status. A non-2xx status is not an error
// here: each caller turns it into a message with its operation's context.
func (c *NodeClient) do(ctx context.Context, method, path string, query url.Values, body io.Reader, contentType string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to build the %s %s request: %w", method, path, err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if query != nil {
		req.URL.RawQuery = query.Encode()
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("%s %s: could not reach the node: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, 0, fmt.Errorf("%s %s: failed to read the response: %w", method, path, err)
	}
	return respBody, resp.StatusCode, nil
}

// statusError renders a non-2xx response for an error message. The body is quoted, truncated,
// rather than summarized away: node JSON:API error documents name the problem.
func statusError(status int, body []byte) string {
	const maxBody = 300
	text := strings.TrimSpace(string(body))
	if len(text) > maxBody {
		text = text[:maxBody] + "..."
	}
	if text == "" {
		return fmt.Sprintf("status %d", status)
	}
	return fmt.Sprintf("status %d: %s", status, text)
}
