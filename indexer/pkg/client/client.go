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
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

var ErrResponseTooLarge = errors.New("response body too large")

const MaxBodySize = 10 << 20 // 10MB

func NewIndexerClient(lggr logger.Logger, indexerURI string, httpClient *http.Client) (*IndexerClient, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	cl, err := iclient.NewClientWithResponses(indexerURI, iclient.WithHTTPClient(httpClient))
	if err != nil {
		return nil, err
	}

	return &IndexerClient{
		lggr:                lggr,
		indexerURI:          indexerURI,
		ClientWithResponses: cl,
	}, nil
}

type IndexerClient struct {
	*iclient.ClientWithResponses
	lggr       logger.Logger
	indexerURI string
}

func (ic *IndexerClient) ReadVerifierResults(ctx context.Context, queryData protocol.VerifierResultsV1Request) (v1.VerifierResultResponse, error) {
	resp, err := ic.VerifierResult(ctx, &iclient.VerifierResultParams{
		SourceChainSelectors: &queryData.SourceChainSelectors,
		DestChainSelectors:   &queryData.DestChainSelectors,
		Start:                &queryData.Start,
	})

	var verifierResultResponse v1.VerifierResultResponse
	if err = processResponse(resp, &verifierResultResponse); err != nil {
		ic.lggr.Errorw("Indexer ReadVerifierResults returned error", "error", err)
		return v1.VerifierResultResponse{}, err
	}

	ic.lggr.Debugw("Successfully retrieved VerifierResults", "dataCount", len(verifierResultResponse.VerifierResults))
	return verifierResultResponse, nil
}

// ReadMessages reads all messages that matches the provided query parameters. Returns a map of messageID to the contents of the message.
func (ic *IndexerClient) ReadMessages(ctx context.Context, queryData protocol.MessagesV1Request) (map[string]protocol.MessageWithMetadata, error) {
	resp, err := ic.GetMessages(ctx, &iclient.GetMessagesParams{
		SourceChainSelectors: &queryData.SourceChainSelectors,
		DestChainSelectors:   &queryData.DestChainSelectors,
		Start:                &queryData.Start,
		End:                  &queryData.End,
		Limit:                &queryData.Limit,
		Offset:               &queryData.Offset,
	})

	var messagesResponse protocol.MessagesV1Response
	if err = processResponse(resp, &messagesResponse); err != nil {
		ic.lggr.Errorw("Indexer ReadMessages returned error", "error", err)
		return nil, err
	}

	ic.lggr.Debugw("Successfully retrieved Messages", "dataCount", len(messagesResponse.Messages))
	return messagesResponse.Messages, nil
}

func getAddrs(results []protocol.VerifierResult) []string {
	addrs := make([]string, 0, len(results))
	for _, result := range results {
		addrs = append(addrs, result.VerifierSourceAddress.String())
	}
	return addrs
}

// GetVerifierResults returns all verifierResults for a given messageID.
func (ic *IndexerClient) GetVerifierResults(ctx context.Context, messageID protocol.Bytes32) ([]protocol.VerifierResult, error) {
	resp, err := ic.MessageById(ctx, messageID.String())

	var messageIDResponse protocol.MessageIDV1Response
	if err = processResponse(resp, &messageIDResponse); err != nil {
		ic.lggr.Errorw("Indexer GetVerifierResults returned error", "error", messageIDResponse.Error)
		return nil, err
	}

	resultWithoutMeta := make([]protocol.VerifierResult, 0, len(messageIDResponse.Results))
	for _, result := range messageIDResponse.Results {
		resultWithoutMeta = append(resultWithoutMeta, result.VerifierResult)
	}

	ic.lggr.Infow("Successfully retrieved VerifierResults",
		"messageID", messageID,
		"numberOfResults", len(resultWithoutMeta),
		"verifierAddresses", getAddrs(resultWithoutMeta),
	)
	return resultWithoutMeta, nil
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
