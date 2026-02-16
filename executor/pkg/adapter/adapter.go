package executor

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	v1 "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api/handlers/v1"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/client"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// IndexerReaderAdapter adapts multiple IndexerClients to conform to the VerifierResultsReader and MessageReader interface.
// It queries all clients concurrently and prefers the primary client's result, falling back to alternates only when primary is unreachable and unhealthy.
type IndexerReaderAdapter struct {
	clients    []client.IndexerClientInterface // Primary is index 0
	monitoring executor.Monitoring
	lggr       logger.Logger
}

// clientResult holds the result from a single indexer client query.
type clientResult[T any] struct {
	status   int   // HTTP status code
	response T     // Response data
	err      error // Error if any
}

// NewIndexerReaderAdapter creates a new IndexerReaderAdapter that queries multiple indexer clients concurrently.
func NewIndexerReaderAdapter(indexerURIs []string, httpClient *http.Client, monitoring executor.Monitoring, lggr logger.Logger) (*IndexerReaderAdapter, error) {
	if len(indexerURIs) == 0 {
		return nil, fmt.Errorf("at least one indexer URI must be provided")
	}

	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	clients := make([]client.IndexerClientInterface, 0, len(indexerURIs))
	for i, uri := range indexerURIs {
		c, err := client.NewIndexerClient(uri, httpClient)
		if err != nil {
			return nil, fmt.Errorf("failed to create indexer client %d (%s): %w", i, uri, err)
		}
		clients = append(clients, c)
	}

	lggr.Infow("Created indexer adapter with multiple clients",
		"primaryURI", indexerURIs[0],
		"totalClients", len(clients))

	return &IndexerReaderAdapter{
		clients:    clients,
		monitoring: monitoring,
		lggr:       lggr,
	}, nil
}

// callAllClients calls all indexer clients concurrently and collects their results.
func callAllClients[TInput any, TResponse any](
	ctx context.Context,
	clients []client.IndexerClientInterface,
	callFn func(client.IndexerClientInterface, context.Context, TInput) (int, TResponse, error),
	input TInput,
) []clientResult[TResponse] {
	var wg sync.WaitGroup
	results := make([]clientResult[TResponse], len(clients))

	for i, c := range clients {
		wg.Add(1)
		go func(idx int, cl client.IndexerClientInterface) {
			defer wg.Done()
			status, resp, err := callFn(cl, ctx, input)
			results[idx] = clientResult[TResponse]{
				status:   status,
				response: resp,
				err:      err,
			}
		}(i, c)
	}
	wg.Wait()

	return results
}

// selectResult selects the best result from all client responses, preferring the primary client.
// Returns primary result if status != 0, otherwise checks primary health and falls back to alternates if unhealthy.
func selectResult[T any](
	ctx context.Context,
	ira *IndexerReaderAdapter,
	results []clientResult[T],
) (int, T, error) {
	// The primary result is always at index 0.
	if len(results) == 0 {
		var zero T
		return 0, zero, fmt.Errorf("no client results available")
	}
	primaryResult := results[0]

	// If primary status != 0, always return primary result (even if error)
	if primaryResult.status != 0 {
		ira.lggr.Debugw("Using primary indexer result",
			"status", primaryResult.status,
			"hasError", primaryResult.err != nil)
		return primaryResult.status, primaryResult.response, primaryResult.err
	}

	// Primary status == 0 (unreachable), check health
	ira.lggr.Warnw("Primary indexer unreachable, checking health",
		"error", primaryResult.err)

	healthCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	healthErr := ira.clients[0].Health(healthCtx)
	if healthErr == nil {
		// Primary is healthy despite status 0 - trust primary
		ira.lggr.Infow("Primary indexer health check passed, using primary result")
		return primaryResult.status, primaryResult.response, primaryResult.err
	}

	// Primary is unhealthy, select first alternate with status != 0
	ira.lggr.Warnw("Primary indexer unhealthy, finding healthy alternate",
		"healthError", healthErr)

	for i, res := range results {
		// Skip primary (index 0) since we already checked it
		if i == 0 {
			continue
		}
		if res.status != 0 {
			ira.lggr.Infow("Using alternate indexer",
				"clientIdx", i,
				"status", res.status)
			return res.status, res.response, res.err
		}
	}

	// No alternate clients healthy. Return primary with its status and error.
	ira.lggr.Errorw("No non-0 status codes found, returning primary result")
	return primaryResult.status, primaryResult.response, primaryResult.err
}

func (ira *IndexerReaderAdapter) GetVerifierResults(ctx context.Context, messageID protocol.Bytes32) ([]protocol.VerifierResult, error) {
	input := v1.VerifierResultsByMessageIDInput{MessageID: messageID.String()}

	// Call all clients concurrently
	results := callAllClients(
		ctx,
		ira.clients,
		func(c client.IndexerClientInterface, ctx context.Context, in v1.VerifierResultsByMessageIDInput) (int, v1.VerifierResultsByMessageIDResponse, error) {
			return c.VerifierResultsByMessageID(ctx, in)
		},
		input,
	)

	// Select best result (primary preferred, fallback to alternates)
	_, res, err := selectResult(ctx, ira, results)

	if err != nil {
		ira.monitoring.Metrics().IncrementHeartbeatFailure(ctx)
		return nil, err
	}

	// Track successful communication
	ira.monitoring.Metrics().IncrementHeartbeatSuccess(ctx)
	ira.monitoring.Metrics().SetLastHeartbeatTimestamp(ctx, time.Now().Unix())

	// Convert response
	verifierResults := make([]protocol.VerifierResult, 0, len(res.Results))
	for _, result := range res.Results {
		verifierResults = append(verifierResults, result.VerifierResult)
	}

	return verifierResults, nil
}

func (ira *IndexerReaderAdapter) ReadMessages(ctx context.Context, queryData v1.MessagesInput) (map[string]common.MessageWithMetadata, error) {
	// Call all clients concurrently
	results := callAllClients(
		ctx,
		ira.clients,
		func(c client.IndexerClientInterface, ctx context.Context, in v1.MessagesInput) (int, v1.MessagesResponse, error) {
			return c.Messages(ctx, in)
		},
		queryData,
	)

	// Select best result (primary preferred, fallback to alternates)
	_, res, err := selectResult(ctx, ira, results)

	if err != nil {
		ira.monitoring.Metrics().IncrementHeartbeatFailure(ctx)
		return nil, err
	}

	// Track successful communication
	ira.monitoring.Metrics().IncrementHeartbeatSuccess(ctx)
	ira.monitoring.Metrics().SetLastHeartbeatTimestamp(ctx, time.Now().Unix())

	return res.Messages, nil
}
