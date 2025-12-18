package storageaccess

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

var _ IndexerAPI = &IndexerAPIReader{}

type IndexerAPIReader struct {
	httpClient *http.Client
	lggr       logger.Logger
	indexerURI string
}

func NewIndexerAPIReader(lggr logger.Logger, indexerURI string) *IndexerAPIReader {
	if indexerURI == "" {
		return nil
	}
	return &IndexerAPIReader{
		lggr:       lggr,
		indexerURI: indexerURI,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

type queryParams struct {
	SourceChainSelectors []protocol.ChainSelector
	DestChainSelectors   []protocol.ChainSelector
	Start                int64
	End                  int64
	Limit                uint64
	Offset               uint64
}

func (i *IndexerAPIReader) makeRequest(ctx context.Context, endpoint string, params queryParams, result any) error {
	fullURL, err := url.JoinPath(i.indexerURI, endpoint)
	if err != nil {
		i.lggr.Errorw("Failed to join indexer URI and endpoint", "error", err, "uri", i.indexerURI, "endpoint", endpoint)
		return fmt.Errorf("failed to join indexer URI and endpoint: %w", err)
	}

	u, err := url.Parse(fullURL)
	if err != nil {
		i.lggr.Errorw("Failed to parse indexer URI", "error", err, "uri", i.indexerURI)
		return fmt.Errorf("failed to parse indexer URI: %w", err)
	}

	queryValues := url.Values{}
	if params.Start != 0 {
		queryValues.Add("start", strconv.FormatInt(params.Start, 10))
	}
	if params.End != 0 {
		queryValues.Add("end", strconv.FormatInt(params.End, 10))
	}
	if params.Limit != 0 {
		queryValues.Add("limit", strconv.FormatUint(params.Limit, 10))
	}
	if params.Offset != 0 {
		queryValues.Add("offset", strconv.FormatUint(params.Offset, 10))
	}
	if len(params.SourceChainSelectors) > 0 {
		var sourceSelectors []string
		for _, selector := range params.SourceChainSelectors {
			sourceSelectors = append(sourceSelectors, strconv.FormatUint(uint64(selector), 10))
		}
		queryValues.Add("sourceChainSelectors", strings.Join(sourceSelectors, ","))
	}
	if len(params.DestChainSelectors) > 0 {
		var destSelectors []string
		for _, selector := range params.DestChainSelectors {
			destSelectors = append(destSelectors, strconv.FormatUint(uint64(selector), 10))
		}
		queryValues.Add("destChainSelectors", strings.Join(destSelectors, ","))
	}

	u.RawQuery = queryValues.Encode()
	i.lggr.Debugw("Making request to indexer", "url", u.String(), "params", queryValues)

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		i.lggr.Errorw("Failed to create HTTP request", "error", err)
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := i.httpClient.Do(req)
	if err != nil {
		i.lggr.Errorw("Failed to make HTTP request", "error", err)
		return fmt.Errorf("failed to make HTTP request: %w", err)
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			i.lggr.Errorw("Failed to close response body", "error", err)
		}
	}()

	body, err := maybeGetBody(resp.Body)
	if err != nil {
		i.lggr.Errorw("Failed to read response body", "error", err)
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		i.lggr.Errorw("Indexer returned non-OK status", "status", resp.StatusCode, "body", body)
		if len(body) > 0 {
			return fmt.Errorf("indexer returned status %d: %s", resp.StatusCode, body)
		}
		return fmt.Errorf("indexer returned status %d", resp.StatusCode)
	}

	if err := json.Unmarshal(body, result); err != nil {
		i.lggr.Errorw("Failed to decode JSON response", "error", err, "body", body)
		if len(body) > 0 {
			return fmt.Errorf("failed to decode JSON response: %w; body: %s", err, body)
		}
		return fmt.Errorf("failed to decode JSON response: %w", err)
	}

	return nil
}

func (i *IndexerAPIReader) ReadVerifierResults(
	ctx context.Context,
	queryData VerifierResultsRequest,
) (map[string][]protocol.VerifierResult, error) {
	var response VerifierResultsResponse
	err := i.makeRequest(ctx, "/v1/verifierresponse", queryParams(queryData), &response)
	if err != nil {
		return nil, err
	}

	if !response.Success {
		i.lggr.Errorw("Indexer ReadVerifierResults returned error", "error", response.Error)
		return nil, fmt.Errorf("indexer ReadVerifierResults returned error: %s", response.Error)
	}

	i.lggr.Debugw("Successfully retrieved CCV data", "dataCount", len(response.CCVData))
	return response.CCVData, nil
}

func (i *IndexerAPIReader) ReadMessages(
	ctx context.Context,
	queryData protocol.MessagesV1Request,
) (map[string]protocol.MessageWithMetadata, error) {
	var response protocol.MessagesV1Response
	err := i.makeRequest(ctx, "/v1/messages", queryParams(queryData), &response)
	if err != nil {
		return nil, err
	}

	if !response.Success {
		i.lggr.Errorw("Indexer ReadMessages returned error", "error", response.Error)
		return nil, fmt.Errorf("indexer ReadMessages returned error: %s", response.Error)
	}

	i.lggr.Debugw("Successfully retrieved Messages", "dataCount", len(response.Messages))

	return response.Messages, nil
}

func (i *IndexerAPIReader) GetVerifierResults(ctx context.Context, messageID protocol.Bytes32) ([]protocol.VerifierResult, error) {
	var response protocol.MessageIDV1Response
	request := "/v1/messageid/0x" + common.Bytes2Hex(messageID[:])
	err := i.makeRequest(ctx, request, queryParams{}, &response)
	if err != nil {
		return nil, err
	}
	if !response.Success {
		i.lggr.Errorw("Indexer GetVerifierResults returned error", "error", response.Error)
		return nil, fmt.Errorf("indexer GetVerifierResults returned error: %s", response.Error)
	}

	withoutMeta := make([]protocol.VerifierResult, 0, len(response.Results))
	for _, result := range response.Results {
		withoutMeta = append(withoutMeta, result.VerifierResult)
	}

	i.lggr.Infow("Successfully retrieved VerifierResults",
		"messageID", messageID,
		"numberOfResults", len(response.Results),
		"verifierAddresses", sourceVerifierAddresses(withoutMeta),
	)

	return withoutMeta, nil
}

func sourceVerifierAddresses(verifierResults []protocol.VerifierResult) []string {
	sourceVerifierAddresses := make([]string, 0, len(verifierResults))
	for _, verifierResult := range verifierResults {
		sourceVerifierAddresses = append(sourceVerifierAddresses, verifierResult.VerifierSourceAddress.String())
	}
	return sourceVerifierAddresses
}

// maybeGetBody returns a trimmed, possibly truncated string of at most 16 KiB
// read from the provided reader. It does NOT close the reader; callers must
// ensure the underlying ReadCloser is closed. This avoids double-close issues.
func maybeGetBody(body io.Reader) ([]byte, error) {
	if body == nil {
		return nil, fmt.Errorf("nil reader detected")
	}

	const maxBody = 16 * 1024
	lr := io.LimitReader(body, int64(maxBody+1))
	b, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %v", err)
	}

	if len(b) > maxBody {
		return nil, fmt.Errorf("response body too large")
	}

	return b, nil
}
