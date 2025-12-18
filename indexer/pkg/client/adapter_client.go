package client

import (
	"context"
	"net/http"

	v1 "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api/handlers/v1"
	iclient "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/client/internal"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// NewIndexerAdapterClient creates a new IndexerAdapterClient to interact with the Indexer Adapter service.
// deprecated: use NewIndexerClient instead, this version uses deprecated types and inconsistent responses.
func NewIndexerAdapterClient(lggr logger.Logger, indexerURI string, httpClient *http.Client) (*IndexerAdapterClient, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	cl, err := iclient.NewClient(indexerURI, iclient.WithHTTPClient(httpClient))
	if err != nil {
		return nil, err
	}

	return &IndexerAdapterClient{
		lggr:       lggr,
		indexerURI: indexerURI,
		client:     cl,
	}, nil
}

type IndexerAdapterClient struct {
	client     *iclient.Client
	lggr       logger.Logger
	indexerURI string
}

func (ic *IndexerAdapterClient) ReadVerifierResults(ctx context.Context, queryData v1.VerifierResultsInput) (v1.VerifierResultResponse, error) {
	resp, err := ic.client.VerifierResult(ctx, &iclient.VerifierResultParams{
		SourceChainSelectors: &queryData.SourceChainSelectors,
		DestChainSelectors:   &queryData.DestChainSelectors,
		Start:                &queryData.Start,
		End:                  &queryData.End,
		Limit:                &queryData.Limit,
		Offset:               &queryData.Offset,
	})
	if err != nil {
		ic.lggr.Errorw("Indexer ReadVerifierResults request error", "error", err)
		return v1.VerifierResultResponse{}, err
	}

	var verifierResultResponse v1.VerifierResultResponse
	if err = processResponse(resp, &verifierResultResponse); err != nil {
		ic.lggr.Errorw("Indexer ReadVerifierResults returned error", "error", err)
		return v1.VerifierResultResponse{}, err
	}

	// ic.lggr.Debugw("Successfully retrieved VerifierResults", "dataCount", len(verifierResultResponse.VerifierResults))
	ic.lggr.Infow("Successfully retrieved VerifierResults", "dataCount", len(verifierResultResponse.VerifierResults))
	return verifierResultResponse, nil
}

// ReadMessages reads all messages that matches the provided query parameters. Returns a map of messageID to the contents of the message.
func (ic *IndexerAdapterClient) ReadMessages(ctx context.Context, queryData protocol.MessagesV1Request) (map[string]protocol.MessageWithMetadata, error) {
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

	ic.lggr.Infow("Sending GetMessages request to Indexer", "params", params)
	resp, err := ic.client.GetMessages(ctx, &params)
	if err != nil {
		ic.lggr.Errorw("Indexer GetMessages request error", "error", err)
		return nil, err
	}

	var messagesResponse protocol.MessagesV1Response
	if err = processResponse(resp, &messagesResponse); err != nil {
		ic.lggr.Errorw("Indexer GetMessages returned error", "error", err)
		return nil, err
	}

	// ic.lggr.Debugw("Successfully retrieved Messages", "dataCount", len(messagesResponse.Messages))
	ic.lggr.Infow("Successfully retrieved Messages", "dataCount", len(messagesResponse.Messages))
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
func (ic *IndexerAdapterClient) GetVerifierResults(ctx context.Context, messageID protocol.Bytes32) ([]protocol.VerifierResult, error) {
	resp, err := ic.client.MessageById(ctx, messageID.String())
	if err != nil {
		ic.lggr.Errorw("Indexer GetVerifierResults request error", "error", err)
		return nil, err
	}

	var messageIDResponse protocol.MessageIDV1Response
	if err = processResponse(resp, &messageIDResponse); err != nil {
		ic.lggr.Errorw("Indexer GetVerifierResults returned error", "error", err)
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
