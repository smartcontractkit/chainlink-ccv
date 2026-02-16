package executor

import (
	"context"
	"fmt"
	"net/http"
	"time"

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
	monitoring Monitoring
	lggr       logger.Logger
}

// clientResult holds the result from a single indexer client query.
type clientResult[T any] struct {
	idx      int   // Client index (0 = primary)
	status   int   // HTTP status code
	response T     // Response data
	err      error // Error if any
}

// NewIndexerReaderAdapter creates a new IndexerReaderAdapter that queries multiple indexer clients concurrently.
func NewIndexerReaderAdapter(indexerURIs []string, httpClient *http.Client, monitoring Monitoring, lggr logger.Logger) (*IndexerReaderAdapter, error) {
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
	resultsCh := make(chan clientResult[TResponse], len(clients))

	// Fan-out: call all clients concurrently
	for i, c := range clients {
		go func(idx int, cl client.IndexerClientInterface) {
			status, resp, err := callFn(cl, ctx, input)
			resultsCh <- clientResult[TResponse]{
				idx:      idx,
				status:   status,
				response: resp,
				err:      err,
			}
		}(i, c)
	}

	// Collect all results
	results := make([]clientResult[TResponse], 0, len(clients))
	for i := 0; i < len(clients); i++ {
		results = append(results, <-resultsCh)
	}

	return results
}

// selectResult selects the best result from all client responses, preferring the primary client.
// Returns primary result if status != 0, otherwise checks primary health and falls back to alternates if unhealthy.
func selectResult[T any](
	ctx context.Context,
	ira *IndexerReaderAdapter,
	results []clientResult[T],
) (int, T, error) {
	// Find primary result (idx == 0)
	var primaryResult clientResult[T]
	var foundPrimary bool

	for _, r := range results {
		if r.idx == 0 {
			primaryResult = r
			foundPrimary = true
			break
		}
	}

	if !foundPrimary {
		var zero T
		return 0, zero, fmt.Errorf("primary client result not found")
	}

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
	ira.lggr.Warnw("Primary indexer unhealthy, selecting alternate",
		"healthError", healthErr)

	var selected *clientResult[T]
	for i := range results {
		r := &results[i]
		if r.idx != 0 && r.status != 0 {
			if selected == nil || r.idx < selected.idx {
				selected = r
			}
		}
	}
	if selected != nil {
		ira.lggr.Infow("Using alternate indexer",
			"clientIdx", selected.idx,
			"status", selected.status)
		return selected.status, selected.response, selected.err
	}

	// All clients failed or returned status 0
	ira.lggr.Errorw("All indexer clients failed or unreachable")
	var zero T
	return 0, zero, fmt.Errorf("all indexer clients failed: primary error: %w", primaryResult.err)
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
