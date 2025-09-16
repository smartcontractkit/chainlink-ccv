package storageaccess

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

var _ IndexerAPI = (*IndexerAPIReader)(nil)

type IndexerAPIReader struct {
	httpClient *http.Client
	lggr       logger.Logger
	indexerURI string
}

type CCVDataResponse struct {
	Success bool                       `json:"success"`
	Error   string                     `json:"error,omitempty"`
	CCVData map[string][]types.CCVData `json:"ccvData"`
}

func NewIndexerAPIReader(lggr logger.Logger, indexerURI string) *IndexerAPIReader {
	return &IndexerAPIReader{
		lggr:       lggr,
		indexerURI: indexerURI,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Reads all CCVData that matches the provided query parameters. Returns a map of messageID to an array of all known CCVData for that messageID.
// Does not provide a guarantee that the returned CCVData is enough to be executed.
func (i *IndexerAPIReader) ReadCCVData(
	ctx context.Context,
	startUnix int64,
	endUnix int64,
	sourceChainSelectors []types.ChainSelector,
	destChainSelectors []types.ChainSelector,
	limit uint64,
	offset uint64,
) (map[string][]types.CCVData, error) {
	// Build the URL with query parameters
	baseURL := strings.TrimSuffix(i.indexerURI, "/")
	endpoint := fmt.Sprintf("%s/v1/ccvdata", baseURL)

	u, err := url.Parse(endpoint)
	if err != nil {
		i.lggr.Errorw("Failed to parse indexer URI", "error", err, "uri", i.indexerURI)
		return nil, fmt.Errorf("failed to parse indexer URI: %w", err)
	}

	// Build query parameters
	params := url.Values{}

	// Add timestamps
	params.Add("start", strconv.FormatInt(startUnix, 10))
	params.Add("end", strconv.FormatInt(endUnix, 10))

	// Add source chain selectors (comma-separated)
	if len(sourceChainSelectors) > 0 {
		var sourceSelectors []string
		for _, selector := range sourceChainSelectors {
			sourceSelectors = append(sourceSelectors, strconv.FormatUint(uint64(selector), 10))
		}
		params.Add("sourceChainSelectors", strings.Join(sourceSelectors, ","))
	}

	// Add destination chain selectors (comma-separated)
	if len(destChainSelectors) > 0 {
		var destSelectors []string
		for _, selector := range destChainSelectors {
			destSelectors = append(destSelectors, strconv.FormatUint(uint64(selector), 10))
		}
		params.Add("destChainSelectors", strings.Join(destSelectors, ","))
	}

	// Add limit (default: 100)
	params.Add("limit", strconv.FormatUint(limit, 10))

	// Add offset (default: 0)
	params.Add("offset", strconv.FormatUint(offset, 10))

	u.RawQuery = params.Encode()

	i.lggr.Debugw("Making request to indexer", "url", u.String(), "params", params)

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		i.lggr.Errorw("Failed to create HTTP request", "error", err)
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	// Make the HTTP request
	resp, err := i.httpClient.Do(req)
	if err != nil {
		i.lggr.Errorw("Failed to make HTTP request", "error", err)
		return nil, fmt.Errorf("failed to make HTTP request: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		i.lggr.Errorw("Indexer returned non-OK status", "status", resp.StatusCode)
		return nil, fmt.Errorf("indexer returned status %d", resp.StatusCode)
	}

	// Parse JSON response
	var response CCVDataResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		i.lggr.Errorw("Failed to decode JSON response", "error", err)
		return nil, fmt.Errorf("failed to decode JSON response: %w", err)
	}

	// Check if the response indicates success
	if !response.Success {
		i.lggr.Errorw("Indexer returned error", "error", response.Error)
		return nil, fmt.Errorf("indexer returned error: %s", response.Error)
	}

	i.lggr.Debugw("Successfully retrieved CCV data", "dataCount", len(response.CCVData))
	return response.CCVData, nil
}
