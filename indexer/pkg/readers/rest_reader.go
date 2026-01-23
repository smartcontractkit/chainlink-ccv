package readers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	v1 "github.com/smartcontractkit/chainlink-ccv/integration/pkg/api/v1"
)

const (
	userAgent       = "chainlink-ccv-indexer/1.0"
	jsonContentType = "application/json"
)

var _ protocol.VerifierResultsAPI = (*restReader)(nil)

type RestReaderConfig struct {
	BaseURL        string        // Base URL for the REST API
	Since          int64         // Starting timestamp
	RequestTimeout time.Duration // Timeout for HTTP requests (default: 10s)
	HTTPClient     *http.Client  // Custom HTTP client (optional)
	Logger         logger.Logger // Logger instance (required)
}

type restReader struct {
	baseURL    string
	since      int64
	httpClient *http.Client
	lggr       logger.Logger
	mu         sync.RWMutex
}

// NewRestReader creates a new REST-based reader with resilience policies.
func NewRestReader(config RestReaderConfig) *ResilientReader {
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: config.RequestTimeout}
	}

	underlying := &restReader{
		baseURL:    config.BaseURL,
		since:      config.Since,
		httpClient: httpClient,
		lggr:       config.Logger,
	}

	return NewResilientReader(underlying, config.Logger, DefaultResilienceConfig())
}

func (r *restReader) GetVerifications(ctx context.Context, messageIDs []protocol.Bytes32) (map[protocol.Bytes32]protocol.VerifierResult, error) {
	url := r.buildRequestURL(messageIDs)
	r.lggr.Debugw("REST reader calling token verifier", "url", url)

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", jsonContentType)
	req.Header.Set("User-Agent", userAgent)

	// Execute HTTP request
	response, err := r.httpClient.Do(req)
	if err != nil {
		r.lggr.Errorw("REST reader HTTP request failed", "url", url, "error", err)
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer closeHTTPResponse(response)

	// Validate status code
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		r.lggr.Errorw("REST reader unexpected status", "url", url, "status", response.StatusCode)
		return nil, fmt.Errorf("unexpected status code: %d", response.StatusCode)
	}

	// Read and parse response body
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var queryResponses v1.VerifierResultsResponse
	if err := json.Unmarshal(body, &queryResponses); err != nil {
		r.lggr.Errorw("REST reader parse failed", "url", url, "body", string(body), "error", err)
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return queryResponses.ToVerifierResults()
}

// buildRequestURL constructs the URL for fetching CCV data.
func (r *restReader) buildRequestURL(messageIDs []protocol.Bytes32) string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	messageIDStrings := make([]string, 0, len(messageIDs))
	for _, id := range messageIDs {
		messageIDStrings = append(messageIDStrings, id.String())
	}

	queryParams := strings.Join(messageIDStrings, "&messageID=")
	return fmt.Sprintf("%s/verifications?messageID=%s", r.baseURL, queryParams)
}

// closeHTTPResponse safely closes the HTTP response body.
func closeHTTPResponse(response *http.Response) {
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
}
