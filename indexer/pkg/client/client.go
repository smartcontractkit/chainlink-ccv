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
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

var ErrResponseTooLarge = errors.New("response body too large")

const MaxBodySize = 10 << 20 // 10MB

// NewIndexerClient creates a new IndexerAdapterClient to interact with the Indexer Adapter service.
func NewIndexerClient(lggr logger.Logger, indexerURI string, httpClient *http.Client) (*IndexerClient, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	cl, err := iclient.NewClient(indexerURI, iclient.WithHTTPClient(httpClient))
	if err != nil {
		return nil, err
	}

	return &IndexerClient{
		lggr:       lggr,
		indexerURI: indexerURI,
		client:     cl,
	}, nil
}

type IndexerClient struct {
	client     *iclient.Client
	lggr       logger.Logger
	indexerURI string
}

func (ic *IndexerClient) VerifierResult(ctx context.Context, queryData v1.VerifierResultsInput) (v1.VerifierResultResponse, error) {
	var params iclient.VerifierResultParams
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

	resp, err := ic.client.VerifierResult(ctx, &params)
	if err != nil {
		ic.lggr.Errorw("Indexer ReadVerifierResults request error", "error", err)
		return v1.VerifierResultResponse{}, err
	}

	var verifierResultResponse v1.VerifierResultResponse
	if err = processResponse(resp, &verifierResultResponse); err != nil {
		ic.lggr.Errorw("Indexer ReadVerifierResults returned error", "error", err)
		return v1.VerifierResultResponse{}, err
	}

	ic.lggr.Debugw("Successfully retrieved VerifierResults", "dataCount", len(verifierResultResponse.VerifierResults))
	return verifierResultResponse, nil
}

// GetMessages reads all messages that matches the provided query parameters. Returns a map of messageID to the contents of the message.
func (ic *IndexerClient) GetMessages(ctx context.Context, queryData v1.MessagesInput) (v1.MessagesResponse, error) {
	var params iclient.GetMessagesParams
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

	resp, err := ic.client.GetMessages(ctx, &params)
	if err != nil {
		ic.lggr.Errorw("Indexer ReadMessages request error", "error", err)
	}

	var messagesResponse v1.MessagesResponse
	if err = processResponse(resp, &messagesResponse); err != nil {
		ic.lggr.Errorw("Indexer GetMessages returned error", "error", err)
		return v1.MessagesResponse{}, err
	}

	ic.lggr.Debugw("Successfully retrieved Messages", "dataCount", len(messagesResponse.Messages))
	return messagesResponse, nil
}

// MessageByID returns all verifierResults for a given messageID.
func (ic *IndexerClient) MessageByID(ctx context.Context, queryData v1.MessageIDInput) (v1.MessageIDResponse, error) {
	resp, err := ic.client.MessageById(ctx, queryData.MessageID)
	if err != nil {
		ic.lggr.Errorw("Indexer GetVerifierResults request error", "error", err)
		return v1.MessageIDResponse{}, err
	}

	var messageIDResponse v1.MessageIDResponse
	if err = processResponse(resp, &messageIDResponse); err != nil {
		ic.lggr.Errorw("Indexer GetVerifierResults returned error", "error", err)
		return v1.MessageIDResponse{}, err
	}

	addrs := make([]string, 0, len(messageIDResponse.Results))
	for _, result := range messageIDResponse.Results {
		addrs = append(addrs, result.VerifierResult.VerifierSourceAddress.String())
	}

	ic.lggr.Infow("Successfully retrieved VerifierResults",
		"messageID", queryData.MessageID,
		"numberOfResults", len(addrs),
		"verifierAddresses", addrs,
	)
	return messageIDResponse, nil
}

func processResponse(resp *http.Response, rspObj any) error {
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
