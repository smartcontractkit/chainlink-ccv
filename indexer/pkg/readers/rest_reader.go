package readers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	userAgent       = "chainlink-ccv-indexer/1.0"
	jsonContentType = "application/json"
)

var (
	_ protocol.OffchainStorageReader = (*restReader)(nil)
)

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

// ReadCCVData implements the OffchainStorageReader interface.
// It performs a HTTP GET request to fetch CCV data.
func (r *restReader) ReadCCVData(ctx context.Context) ([]protocol.QueryResponse, error) {
	url := r.buildRequestURL()

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
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer closeHTTPResponse(response)

	// Validate status code
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected status code: %d", response.StatusCode)
	}

	// Read and parse response body
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var queryResponses []protocol.QueryResponse
	if err := json.Unmarshal(body, &queryResponses); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Update since timestamp
	r.updateSinceTimestamp(queryResponses)

	return queryResponses, nil
}

// buildRequestURL constructs the URL for fetching CCV data.
func (r *restReader) buildRequestURL() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return fmt.Sprintf("%s/messages?since=%d", r.baseURL, r.since)
}

// updateSinceTimestamp updates the since parameter for the next request.
func (r *restReader) updateSinceTimestamp(responses []protocol.QueryResponse) {
	if len(responses) == 0 {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Update since to the latest timestamp we've seen
	for _, resp := range responses {
		if resp.Timestamp != nil && *resp.Timestamp > r.since {
			r.since = *resp.Timestamp
		}
	}
}

// closeHTTPResponse safely closes the HTTP response body.
func closeHTTPResponse(response *http.Response) {
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
}
