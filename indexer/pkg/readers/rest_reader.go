package readers

//
// import (
// 	"context"
// 	"encoding/json"
// 	"fmt"
// 	"io"
// 	"net/http"
// 	"sync"
// 	"time"
//
// 	"github.com/smartcontractkit/chainlink-ccv/protocol"
// 	"github.com/smartcontractkit/chainlink-common/pkg/logger"
// )
//
// const (
// 	userAgent       = "chainlink-ccv-indexer/1.0"
// 	jsonContentType = "application/json"
// )
//
// var _ protocol.OffchainStorageReader = (*restReader)(nil)
//
// type RestReaderConfig struct {
// 	BaseURL        string        // Base URL for the REST API
// 	Since          int64         // Starting timestamp
// 	RequestTimeout time.Duration // Timeout for HTTP requests (default: 10s)
// 	HTTPClient     *http.Client  // Custom HTTP client (optional)
// 	Logger         logger.Logger // Logger instance (required)
// }
//
// type restReader struct {
// 	baseURL      string
// 	since        int64
// 	httpClient   *http.Client
// 	lggr         logger.Logger
// 	mu           sync.RWMutex
// 	seenMessages map[protocol.Bytes32]struct{} // Track seen message IDs for deduplication
// 	maxSeenCache int                           // Maximum number of message IDs to cache
// }
//
// // NewRestReader creates a new REST-based reader with resilience policies.
// func NewRestReader(config RestReaderConfig) protocol.OffchainStorageReader {
// 	httpClient := config.HTTPClient
// 	if httpClient == nil {
// 		httpClient = &http.Client{Timeout: config.RequestTimeout}
// 	}
//
// 	underlying := &restReader{
// 		baseURL:      config.BaseURL,
// 		since:        config.Since,
// 		httpClient:   httpClient,
// 		lggr:         config.Logger,
// 		seenMessages: make(map[protocol.Bytes32]struct{}),
// 		maxSeenCache: 10000, // Cache up to 10k message IDs
// 	}
//
// 	return NewResilientReader(underlying, config.Logger, DefaultResilienceConfig())
// }
//
// // ReadCCVData implements the OffchainStorageReader interface.
// // It performs a HTTP GET request to fetch CCV data.
// func (r *restReader) ReadCCVData(ctx context.Context) ([]protocol.QueryResponse, error) {
// 	url := r.buildRequestURL()
//
// 	// Create HTTP request
// 	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create request: %w", err)
// 	}
//
// 	req.Header.Set("Accept", jsonContentType)
// 	req.Header.Set("User-Agent", userAgent)
//
// 	// Execute HTTP request
// 	response, err := r.httpClient.Do(req)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to execute request: %w", err)
// 	}
// 	defer closeHTTPResponse(response)
//
// 	// Validate status code
// 	if response.StatusCode < 200 || response.StatusCode >= 300 {
// 		return nil, fmt.Errorf("unexpected status code: %d", response.StatusCode)
// 	}
//
// 	// Read and parse response body
// 	body, err := io.ReadAll(response.Body)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to read response body: %w", err)
// 	}
//
// 	var queryResponses []protocol.QueryResponse
// 	if err := json.Unmarshal(body, &queryResponses); err != nil {
// 		return nil, fmt.Errorf("failed to parse response: %w", err)
// 	}
//
// 	// Filter out duplicate messages
// 	uniqueResponses := r.deduplicateMessages(queryResponses)
//
// 	// Update since timestamp
// 	r.updateSinceTimestamp(uniqueResponses)
//
// 	return uniqueResponses, nil
// }
//
// // buildRequestURL constructs the URL for fetching CCV data.
// func (r *restReader) buildRequestURL() string {
// 	r.mu.RLock()
// 	defer r.mu.RUnlock()
// 	return fmt.Sprintf("%s/messages?since=%d", r.baseURL, r.since)
// }
//
// // updateSinceTimestamp updates the since parameter for the next request.
// func (r *restReader) updateSinceTimestamp(responses []protocol.QueryResponse) {
// 	if len(responses) == 0 {
// 		return
// 	}
//
// 	r.mu.Lock()
// 	defer r.mu.Unlock()
//
// 	// Update since to the latest timestamp we've seen
// 	latestTimestamp := int64(0)
// 	for _, resp := range responses {
// 		if resp.Timestamp != nil && *resp.Timestamp > latestTimestamp {
// 			latestTimestamp = *resp.Timestamp
// 		}
// 	}
//
// 	if latestTimestamp > r.since {
// 		r.since = latestTimestamp
// 	}
// }
//
// // deduplicateMessages filters out messages that have already been seen.
// func (r *restReader) deduplicateMessages(responses []protocol.QueryResponse) []protocol.QueryResponse {
// 	if len(responses) == 0 {
// 		return responses
// 	}
//
// 	r.mu.Lock()
// 	defer r.mu.Unlock()
//
// 	// Filter out duplicates
// 	uniqueResponses := make([]protocol.QueryResponse, 0, len(responses))
// 	duplicateCount := 0
//
// 	for _, resp := range responses {
// 		messageID := resp.Data.MessageID
//
// 		// Check if we've seen this message before
// 		if _, seen := r.seenMessages[messageID]; seen {
// 			duplicateCount++
// 			continue
// 		}
//
// 		// Add to unique responses
// 		uniqueResponses = append(uniqueResponses, resp)
//
// 		// Track this message ID
// 		r.seenMessages[messageID] = struct{}{}
// 	}
//
// 	// Prevent unbounded growth of the seen cache
// 	if len(r.seenMessages) > r.maxSeenCache {
// 		r.lggr.Infow("Seen message cache exceeded limit, clearing oldest entries",
// 			"cacheSize", len(r.seenMessages),
// 			"maxSize", r.maxSeenCache,
// 		)
// 		// Clear half the cache (simple eviction strategy)
// 		// In production, you might want a more sophisticated LRU cache
// 		newCache := make(map[protocol.Bytes32]struct{}, r.maxSeenCache/2)
// 		// Keep only the messages from this batch
// 		for _, resp := range uniqueResponses {
// 			newCache[resp.Data.MessageID] = struct{}{}
// 		}
// 		r.seenMessages = newCache
// 	}
//
// 	if duplicateCount > 0 {
// 		r.lggr.Debugw("Filtered duplicate messages",
// 			"total", len(responses),
// 			"duplicates", duplicateCount,
// 			"unique", len(uniqueResponses),
// 			"cacheSize", len(r.seenMessages),
// 		)
// 	}
//
// 	return uniqueResponses
// }
//
// // closeHTTPResponse safely closes the HTTP response body.
// func closeHTTPResponse(response *http.Response) {
// 	if response != nil && response.Body != nil {
// 		_ = response.Body.Close()
// 	}
// }
