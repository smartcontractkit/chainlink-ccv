package executor

import (
	"context"

	v1 "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api/handlers/v1"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/client"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// IndexerReaderAdapter adapts the IndexerClient to conform to the VerifierResultsReader and MessageReader interface.
type IndexerReaderAdapter struct {
	client *client.IndexerClient
}

func NewIndexerReaderAdapter(client *client.IndexerClient) *IndexerReaderAdapter {
	return &IndexerReaderAdapter{
		client: client,
	}
}

func (ira *IndexerReaderAdapter) GetVerifierResults(ctx context.Context, messageID protocol.Bytes32) ([]protocol.VerifierResult, error) {
	res, err := ira.client.VerifierResultsByMessageID(ctx, v1.VerifierResultsByMessageIDInput{MessageID: messageID.String()})
	if err != nil {
		return nil, err
	}

	results := make([]protocol.VerifierResult, 0, len(res.Results))
	for _, result := range res.Results {
		results = append(results, result.VerifierResult)
	}

	return results, nil
}

func (ira *IndexerReaderAdapter) ReadMessages(ctx context.Context, queryData v1.MessagesInput) (map[string]common.MessageWithMetadata, error) {
	res, err := ira.client.Messages(ctx, queryData)
	if err != nil {
		return nil, err
	}

	return res.Messages, nil
}
