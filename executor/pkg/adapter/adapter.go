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
// It uses the active client first. If the active client returns status 0 (unreachable), it concurrently checks the active
// client's health and queries alternate clients, falling over to the first healthy alternate. Once failed over, it persists on that client.
type IndexerReaderAdapter struct {
	clients         []client.IndexerClientInterface
	monitoring      executor.Monitoring
	lggr            logger.Logger
	activeClientIdx int          // Index of currently active client
	mu              sync.RWMutex // Protects activeClientIdx
}

// clientResult holds the result from a single indexer client query.
type clientResult[T any] struct {
	status   int   // HTTP status code
	response T     // Response data
	err      error // Error if any
}

// NewIndexerReaderAdapter creates a new IndexerReaderAdapter that queries multiple indexer clients concurrently.
func NewIndexerReaderAdapter(ctx context.Context, indexerURIs []string, httpClient *http.Client, monitoring executor.Monitoring, lggr logger.Logger) (*IndexerReaderAdapter, error) {
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
		"activeURI", indexerURIs[0],
		"totalClients", len(clients))

	return &IndexerReaderAdapter{
		clients:         clients,
		monitoring:      monitoring,
		lggr:            lggr,
		activeClientIdx: 0, // Start with first client
	}, nil
}

// getActiveClientIdx safely retrieves the current active client index.
func (ira *IndexerReaderAdapter) getActiveClientIdx() int {
	ira.mu.RLock()
	defer ira.mu.RUnlock()
	return ira.activeClientIdx
}

// setActiveClientIdx safely sets the active client index.
func (ira *IndexerReaderAdapter) setActiveClientIdx(idx int) {
	ira.mu.Lock()
	defer ira.mu.Unlock()
	ira.activeClientIdx = idx
}

// queryWithFailover implements the common failover logic for all query methods.
func queryWithFailover[TInput any, TResponse any](
	ctx context.Context,
	ira *IndexerReaderAdapter,
	input TInput,
	callFn func(client.IndexerClientInterface, context.Context, TInput) (int, TResponse, error),
) (int, TResponse, error) {
	activeIdx := ira.getActiveClientIdx()

	// Call active client
	status, resp, err := callFn(ira.clients[activeIdx], ctx, input)

	// If active client succeeds, return immediately
	if status != 0 {
		ira.lggr.Debugw("Active indexer returned result",
			"activeIdx", activeIdx,
			"status", status,
			"hasError", err != nil)
		return activeIdx, resp, err
	}

	// Active client unreachable - check health and query alternates concurrently
	ira.lggr.Warnw("Active indexer unreachable, checking health and querying alternates",
		"activeIdx", activeIdx,
		"error", err)

	var wg sync.WaitGroup
	var healthErr error
	alternateResults := make([]clientResult[TResponse], len(ira.clients))

	// Check active client health
	wg.Add(1)
	go func() {
		defer wg.Done()
		healthCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		healthErr = ira.clients[activeIdx].Health(healthCtx)
	}()

	// Query all alternate clients
	for i, cl := range ira.clients {
		if i == activeIdx {
			continue
		}
		wg.Add(1)
		go func(idx int, client client.IndexerClientInterface) {
			defer wg.Done()
			status, resp, err := callFn(client, ctx, input)
			alternateResults[idx] = clientResult[TResponse]{
				status:   status,
				response: resp,
				err:      err,
			}
		}(i, cl)
	}
	wg.Wait()

	// If health check passed, use active client result despite status 0
	if healthErr == nil {
		ira.lggr.Infow("Active indexer health check passed, using result despite status 0",
			"activeIdx", activeIdx)
		return activeIdx, resp, err
	}

	// Active client unhealthy - select first healthy alternate
	ira.lggr.Warnw("Active indexer unhealthy, selecting alternate",
		"activeIdx", activeIdx,
		"healthError", healthErr)

	for i, result := range alternateResults {
		if i == activeIdx {
			continue
		}
		if result.status != 0 {
			ira.lggr.Infow("Selected healthy alternate indexer",
				"clientIdx", i,
				"status", result.status)
			ira.setActiveClientIdx(i)
			return i, result.response, result.err
		}
	}
	// No healthy alternates found, return active client result
	ira.lggr.Errorw("No healthy alternates found, returning active client result",
		"activeIdx", activeIdx)
	return activeIdx, resp, err
}

// handleQueryResult processes the result of a query with failover, updating metrics and active client.
func (ira *IndexerReaderAdapter) handleQueryResult(ctx context.Context, selectedIdx int, err error) error {
	if err != nil {
		ira.monitoring.Metrics().IncrementHeartbeatFailure(ctx)
		return err
	}

	// Update active client if failover occurred
	currentActive := ira.getActiveClientIdx()
	if selectedIdx != currentActive {
		ira.lggr.Infow("Switching active indexer",
			"from", currentActive,
			"to", selectedIdx)
		ira.setActiveClientIdx(selectedIdx)
	}

	// Track success
	ira.monitoring.Metrics().IncrementHeartbeatSuccess(ctx)
	ira.monitoring.Metrics().SetLastHeartbeatTimestamp(ctx, time.Now().Unix())
	return nil
}

func (ira *IndexerReaderAdapter) GetVerifierResults(ctx context.Context, messageID protocol.Bytes32) ([]protocol.VerifierResult, error) {
	input := v1.VerifierResultsByMessageIDInput{MessageID: messageID.String()}

	selectedIdx, resp, err := queryWithFailover(
		ctx,
		ira,
		input,
		func(c client.IndexerClientInterface, ctx context.Context, in v1.VerifierResultsByMessageIDInput) (int, v1.VerifierResultsByMessageIDResponse, error) {
			return c.VerifierResultsByMessageID(ctx, in)
		},
	)

	if err := ira.handleQueryResult(ctx, selectedIdx, err); err != nil {
		return nil, err
	}

	// Convert response to protocol format
	verifierResults := make([]protocol.VerifierResult, 0, len(resp.Results))
	for _, result := range resp.Results {
		verifierResults = append(verifierResults, result.VerifierResult)
	}

	return verifierResults, nil
}

func (ira *IndexerReaderAdapter) ReadMessages(ctx context.Context, queryData v1.MessagesInput) (map[string]common.MessageWithMetadata, error) {
	selectedIdx, resp, err := queryWithFailover(
		ctx,
		ira,
		queryData,
		func(c client.IndexerClientInterface, ctx context.Context, in v1.MessagesInput) (int, v1.MessagesResponse, error) {
			return c.Messages(ctx, in)
		},
	)

	if err := ira.handleQueryResult(ctx, selectedIdx, err); err != nil {
		return nil, err
	}

	return resp.Messages, nil
}
