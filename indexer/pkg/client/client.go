package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	v1 "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api/handlers/v1"
	iclient "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/client/internal"
)

var ErrResponseTooLarge = errors.New("response body too large")

const MaxBodySize = 10 << 20 // 10MB

// NewIndexerClient creates a new IndexerAdapterClient to interact with the Indexer Adapter service.
func NewIndexerClient(indexerURI string, httpClient *http.Client) (*IndexerClient, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	cl, err := iclient.NewClient(indexerURI, iclient.WithHTTPClient(httpClient))
	if err != nil {
		return nil, err
	}

	return &IndexerClient{
		indexerURI: indexerURI,
		client:     cl,
	}, nil
}

type IndexerClient struct {
	client     iclient.ClientInterface
	indexerURI string
}

func parseVerifierResultsParams(queryData v1.VerifierResultsInput) *iclient.VerifierResultsParams {
	var params iclient.VerifierResultsParams
	if len(queryData.SourceChainSelectors) > 0 {
		params.SourceChainSelectors = &queryData.SourceChainSelectors
	}
	if len(queryData.DestChainSelectors) > 0 {
		params.DestChainSelectors = &queryData.DestChainSelectors
	}
	if queryData.Start != 0 {
		params.Start = &queryData.Start
	}
	if queryData.End != 0 {
		params.End = &queryData.End
	}
	if queryData.Limit != 0 {
		params.Limit = &queryData.Limit
	}
	if queryData.Offset != 0 {
		params.Offset = &queryData.Offset
	}
	return &params
}

func (ic *IndexerClient) VerifierResults(ctx context.Context, queryData v1.VerifierResultsInput) (int /* status */, v1.VerifierResultsResponse, error) {
	resp, err := ic.client.VerifierResults(ctx, parseVerifierResultsParams(queryData))
	if err != nil {
		err = fmt.Errorf("indexer ReadVerifierResults request error: %w", err)
		return 0, v1.VerifierResultsResponse{}, err
	}

	var verifierResultResponse v1.VerifierResultsResponse
	if err = processResponse(resp, &verifierResultResponse); err != nil {
		err = fmt.Errorf("indexer ReadVerifierResults error: %w", err)
		return resp.StatusCode, v1.VerifierResultsResponse{}, err
	}

	return resp.StatusCode, verifierResultResponse, nil
}

func parseMessagesParams(queryData v1.MessagesInput) *iclient.MessagesParams {
	var params iclient.MessagesParams
	if len(queryData.SourceChainSelectors) > 0 {
		params.SourceChainSelectors = &queryData.SourceChainSelectors
	}
	if len(queryData.DestChainSelectors) > 0 {
		params.DestChainSelectors = &queryData.DestChainSelectors
	}
	if queryData.Start != 0 {
		params.Start = &queryData.Start
	}
	if queryData.End != 0 {
		params.End = &queryData.End
	}
	if queryData.Limit != 0 {
		params.Limit = &queryData.Limit
	}
	if queryData.Offset != 0 {
		params.Offset = &queryData.Offset
	}
	return &params
}

// Messages reads all messages that matches the provided query parameters. Returns a map of messageID to the contents of the message.
func (ic *IndexerClient) Messages(ctx context.Context, queryData v1.MessagesInput) (int /* status */, v1.MessagesResponse, error) {
	resp, err := ic.client.Messages(ctx, parseMessagesParams(queryData))
	if err != nil {
		return 0, v1.MessagesResponse{}, fmt.Errorf("indexer Messages request error: %w", err)
	}

	var messagesResponse v1.MessagesResponse
	if err = processResponse(resp, &messagesResponse); err != nil {
		return resp.StatusCode, v1.MessagesResponse{}, fmt.Errorf("indexer Messages error: %w", err)
	}

	return resp.StatusCode, messagesResponse, nil
}

// VerifierResultsByMessageID returns all verifierResults for a given messageID.
func (ic *IndexerClient) VerifierResultsByMessageID(ctx context.Context, queryData v1.VerifierResultsByMessageIDInput) (int /* status */, v1.VerifierResultsByMessageIDResponse, error) {
	resp, err := ic.client.VerifierResultsByMessageId(ctx, queryData.MessageID)
	if err != nil {
		return 0, v1.VerifierResultsByMessageIDResponse{},
			fmt.Errorf("indexer VerifierResultsByMessageID request error: %w", err)
	}

	var messageIDResponse v1.VerifierResultsByMessageIDResponse
	if err = processResponse(resp, &messageIDResponse); err != nil {
		return resp.StatusCode, v1.VerifierResultsByMessageIDResponse{},
			fmt.Errorf("indexer VerifierResultsByMessageID error: %w", err)
	}

	return resp.StatusCode, messageIDResponse, nil
}

func processResponse(resp *http.Response, rspObj any) error {
	if resp == nil {
		return fmt.Errorf("cannot process nil response")
	}
	b, err := maybeGetBody(resp.Body, MaxBodySize)
	if err != nil {
		return fmt.Errorf("failed to read error response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("indexer returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	// decode from the bytes we've already read (resp.Body has been closed by maybeGetBody)
	if err := json.Unmarshal(b, rspObj); err != nil {
		return fmt.Errorf("failed to decode JSON response: %w", err)
	}

	return nil
}

// maybeGetBody reads up to maxBody bytes from the provided io.ReadCloser. If
// the body is larger than maxBody the function returns ErrResponseTooLarge.
// The ReadCloser is closed before the function returns. On success the read
// bytes (up to maxBody) are returned; on error a non-nil error is returned.
func maybeGetBody(body io.ReadCloser, maxBody int) ([]byte, error) {
	if body == nil {
		return nil, fmt.Errorf("nil reader detected")
	}

	lr := io.LimitReader(body, int64(maxBody+1))
	b, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %v", err)
	}

	if len(b) > maxBody {
		return nil, ErrResponseTooLarge
	}

	if err = body.Close(); err != nil {
		return nil, fmt.Errorf("failed to close body: %v", err)
	}

	return b, nil
}
