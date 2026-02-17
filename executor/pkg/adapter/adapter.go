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
// It first queries the primary client. If primary returns status 0, it concurrently checks primary's health and queries alternates,
// falling back to alternates only when primary is unreachable and unhealthy.
// When failed over to an alternate, it periodically checks primary health to switch back when primary recovers.
type IndexerReaderAdapter struct {
	clients           []client.IndexerClientInterface // Primary is index 0
	monitoring        executor.Monitoring
	lggr              logger.Logger
	activeClientIdx   int          // Index of currently active client (0 = primary)
	mu                sync.RWMutex // Protects activeClientIdx
	healthCheckCtx    context.Context
	healthCheckCancel context.CancelFunc
	healthCheckWg     sync.WaitGroup
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
		"primaryURI", indexerURIs[0],
		"totalClients", len(clients))

	healthCheckCtx, cancel := context.WithCancel(ctx)
	
	return &IndexerReaderAdapter{
		clients:           clients,
		monitoring:        monitoring,
		lggr:              lggr,
		activeClientIdx:   0, // Start with primary
		healthCheckCtx:    healthCheckCtx,
		healthCheckCancel: cancel,
	}, nil
}

// callAlternateClients calls alternate indexer clients (excluding primary) concurrently and collects their results.
// Returns a slice where index 0 is a placeholder (zero value), and indices 1+ contain alternate results.
//
//nolint:gofumpt
func callAlternateClients[TInput any, TResponse any](
	ctx context.Context,
	clients []client.IndexerClientInterface,
	callFn func(client.IndexerClientInterface, context.Context, TInput) (int, TResponse, error),
	input TInput,
) []clientResult[TResponse] {
	var wg sync.WaitGroup
	results := make([]clientResult[TResponse], len(clients))

	// Start from index 1 to skip primary (index 0)
	for i := 1; i < len(clients); i++ {
		wg.Add(1)
		go func(idx int, cl client.IndexerClientInterface) {
			defer wg.Done()
			status, resp, err := callFn(cl, ctx, input)
			results[idx] = clientResult[TResponse]{
				status:   status,
				response: resp,
				err:      err,
			}
		}(i, clients[i])
	}
	wg.Wait()

	return results
}

// selectResultWithHealthCheck selects the best result when primary returned status 0.
// It expects that the health check and alternate calls were done concurrently.
// Returns (clientIdx, status, response, error) where clientIdx is the index of the selected client.
// Returns primary result (idx 0) if health check passed, otherwise returns first alternate with status != 0.
func selectResultWithHealthCheck[T any](
	ira *IndexerReaderAdapter,
	primaryResult clientResult[T],
	healthErr error,
	alternateResults []clientResult[T],
) (int, int, T, error) {
	// If health check passed, use primary result regardless
	if healthErr == nil {
		ira.lggr.Infow("Primary indexer health check passed, using primary result")
		return 0, primaryResult.status, primaryResult.response, primaryResult.err
	}

	// Primary is unhealthy, select first alternate with status != 0
	ira.lggr.Warnw("Primary indexer unhealthy, finding healthy alternate",
		"healthError", healthErr)

	for i, res := range alternateResults {
		// Skip index 0 (placeholder for primary)
		if i == 0 {
			continue
		}
		if res.status != 0 {
			ira.lggr.Infow("Using alternate indexer",
				"clientIdx", i,
				"status", res.status)
			return i, res.status, res.response, res.err
		}
	}

	// No alternate clients healthy. Return primary with its status and error.
	ira.lggr.Errorw("No non-0 status codes found, returning primary result")
	return 0, primaryResult.status, primaryResult.response, primaryResult.err
}

// Close stops the background health checker and cleans up resources.
func (ira *IndexerReaderAdapter) Close() error {
	if ira.healthCheckCancel != nil {
		ira.healthCheckCancel()
	}
	ira.healthCheckWg.Wait()
	return nil
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

// startPrimaryHealthChecker starts a background goroutine that checks primary health every minute
// and switches back to primary when it becomes healthy again.
func (ira *IndexerReaderAdapter) startPrimaryHealthChecker() {
	ira.healthCheckWg.Add(1)
	go func() {
		defer ira.healthCheckWg.Done()

		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		ira.lggr.Infow("Started background primary health checker")

		for {
			select {
			case <-ira.healthCheckCtx.Done():
				ira.lggr.Infow("Stopping primary health checker")
				return
			case <-ticker.C:
				// Check if we're still on an alternate
				if ira.getActiveClientIdx() == 0 {
					ira.lggr.Debugw("Already on primary, stopping health checker")
					return
				}

				// Check primary health
				healthCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				healthErr := ira.clients[0].Health(healthCtx)
				cancel()

				if healthErr == nil {
					// Primary is healthy, switch back
					ira.lggr.Infow("Primary indexer health check passed, switching back to primary")
					ira.setActiveClientIdx(0)
					return
				}

				ira.lggr.Debugw("Primary indexer still unhealthy",
					"healthError", healthErr)
			}
		}
	}()
}

// trackSuccess records successful indexer communication.
func (ira *IndexerReaderAdapter) trackSuccess(ctx context.Context) {
	ira.monitoring.Metrics().IncrementHeartbeatSuccess(ctx)
	ira.monitoring.Metrics().SetLastHeartbeatTimestamp(ctx, time.Now().Unix())
}

// trackFailure records failed indexer communication.
func (ira *IndexerReaderAdapter) trackFailure(ctx context.Context) {
	ira.monitoring.Metrics().IncrementHeartbeatFailure(ctx)
}

// handleFailoverSwitch switches to an alternate indexer and starts the health checker if needed.
func (ira *IndexerReaderAdapter) handleFailoverSwitch(selectedIdx int) {
	if selectedIdx != 0 && ira.getActiveClientIdx() == 0 {
		ira.lggr.Infow("Switching to alternate indexer and starting primary health checker",
			"newActiveIdx", selectedIdx)
		ira.setActiveClientIdx(selectedIdx)
		ira.startPrimaryHealthChecker()
	}
}

// queryWithFailover implements the common failover logic for all query methods.
// It returns the selected client index and the result.
func queryWithFailover[TInput any, TResponse any](
	ctx context.Context,
	ira *IndexerReaderAdapter,
	input TInput,
	callFn func(client.IndexerClientInterface, context.Context, TInput) (int, TResponse, error),
) (int, TResponse, error) {
	activeIdx := ira.getActiveClientIdx()

	// Fast path: Use non-primary active indexer directly
	if activeIdx != 0 {
		ira.lggr.Debugw("Using non-primary active indexer", "activeIdx", activeIdx)
		_, resp, err := callFn(ira.clients[activeIdx], ctx, input)
		return activeIdx, resp, err
	}

	// Call primary indexer first
	primaryStatus, primaryResp, primaryErr := callFn(ira.clients[0], ctx, input)
	primaryResult := clientResult[TResponse]{
		status:   primaryStatus,
		response: primaryResp,
		err:      primaryErr,
	}

	// Fast path: Primary returned non-zero status
	if primaryStatus != 0 {
		ira.lggr.Debugw("Using primary indexer result",
			"status", primaryStatus,
			"hasError", primaryErr != nil)
		return 0, primaryResp, primaryErr
	}

	// Primary returned status 0 - concurrently check health and call alternates
	ira.lggr.Warnw("Primary indexer unreachable, checking health and querying alternates",
		"error", primaryErr)

	var wg sync.WaitGroup
	var healthErr error
	var alternateResults []clientResult[TResponse]

	// Concurrently check primary health
	wg.Add(1)
	go func() {
		defer wg.Done()
		healthCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		healthErr = ira.clients[0].Health(healthCtx)
	}()

	// Concurrently query alternate clients
	wg.Add(1)
	go func() {
		defer wg.Done()
		alternateResults = callAlternateClients(ctx, ira.clients, callFn, input)
	}()

	wg.Wait()

	// Select best result and handle failover if needed
	selectedIdx, _, res, err := selectResultWithHealthCheck(ira, primaryResult, healthErr, alternateResults)
	return selectedIdx, res, err
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

	if err != nil {
		ira.trackFailure(ctx)
		return nil, err
	}

	// Handle failover switch if needed
	ira.handleFailoverSwitch(selectedIdx)

	// Track success
	ira.trackSuccess(ctx)

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

	if err != nil {
		ira.trackFailure(ctx)
		return nil, err
	}

	// Handle failover switch if needed
	ira.handleFailoverSwitch(selectedIdx)

	// Track success
	ira.trackSuccess(ctx)

	return resp.Messages, nil
}
