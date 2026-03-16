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
// It uses the active client first. If the active client returns a non-success status (anything other than 200 or 404),
// it concurrently checks the active client's health and queries alternate clients, falling over to the first healthy alternate.
// Once failed over, it persists on that client.
// Status-code semantics (e.g. whether 404 is an error) are handled by each caller, not by the failover layer.
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
		"activeURI", indexerURIs[0],
		"totalClients", len(clients))

	return &IndexerReaderAdapter{
		clients:         clients,
		monitoring:      monitoring,
		lggr:            lggr,
		activeClientIdx: 0, // Start with first client
	}, nil
}

func (ira *IndexerReaderAdapter) getActiveClientIdx() int {
	ira.mu.RLock()
	defer ira.mu.RUnlock()
	return ira.activeClientIdx
}

func (ira *IndexerReaderAdapter) setActiveClientIdx(idx int) {
	ira.mu.Lock()
	defer ira.mu.Unlock()
	ira.activeClientIdx = idx
}

func isSuccessStatus(status int) bool {
	return status == http.StatusOK || status == http.StatusNotFound
}

// queryWithFailover implements the common failover logic for all query methods.
// Returns (selectedClientIdx, httpStatus, response, error). The caller is responsible
// for interpreting status-code semantics (e.g. whether 404 is an error).
func queryWithFailover[TInput, TResponse any](
	ctx context.Context,
	ira *IndexerReaderAdapter,
	input TInput,
	callFn func(client.IndexerClientInterface, context.Context, TInput) (int, TResponse, error),
) (int, int, TResponse, error) {
	activeIdx := ira.getActiveClientIdx()

	// Call active client
	status, resp, err := callFn(ira.clients[activeIdx], ctx, input)

	if isSuccessStatus(status) {
		ira.lggr.Debugw("Active indexer returned result",
			"activeIdx", activeIdx,
			"status", status)
		return activeIdx, status, resp, err
	}

	ira.lggr.Warnw("Active indexer returned non-success status, checking health and querying alternates",
		"activeIdx", activeIdx,
		"status", status,
		"error", err)

	var wg sync.WaitGroup
	var healthErr error
	alternateResults := make([]clientResult[TResponse], len(ira.clients))

	// Check active client health
	wg.Go(func() {
		healthCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		healthErr = ira.clients[activeIdx].Health(healthCtx)
	})

	// Query all alternate clients
	for i, cl := range ira.clients {
		if i == activeIdx {
			continue
		}
		wg.Go(func() {
			status, resp, err := callFn(cl, ctx, input)
			alternateResults[i] = clientResult[TResponse]{
				status:   status,
				response: resp,
				err:      err,
			}
		})
	}
	wg.Wait()

	// Health check passed — the initial failure was transient, retry the query
	if healthErr == nil {
		ira.lggr.Infow("Active indexer health check passed, retrying query", "activeIdx", activeIdx)
		retryStatus, retryResp, retryErr := callFn(ira.clients[activeIdx], ctx, input)
		if isSuccessStatus(retryStatus) {
			return activeIdx, retryStatus, retryResp, retryErr
		}
		ira.lggr.Warnw("Retry on active indexer also failed after health check passed",
			"activeIdx", activeIdx, "retryStatus", retryStatus, "retryError", retryErr)
	}

	// Active client failed - select first healthy alternate
	ira.lggr.Warnw("Active indexer unavailable, selecting alternate",
		"activeIdx", activeIdx,
		"healthError", healthErr)

	for i, result := range alternateResults {
		if i == activeIdx {
			continue
		}
		if isSuccessStatus(result.status) {
			ira.lggr.Infow("Selected healthy alternate indexer",
				"clientIdx", i,
				"status", result.status)
			ira.setActiveClientIdx(i)
			return i, result.status, result.response, result.err
		}
	}
	// No healthy alternates found, return active client result
	ira.lggr.Errorw("No healthy alternates found, returning active client result",
		"activeIdx", activeIdx)
	return activeIdx, status, resp, err
}

// recordHeartbeatSuccess records a successful heartbeat and reconciles the
// active client index. queryWithFailover already updates the index on failover;
// this serves as a defensive reconciliation.
func (ira *IndexerReaderAdapter) recordHeartbeatSuccess(ctx context.Context, selectedIdx int) {
	if currentActive := ira.getActiveClientIdx(); selectedIdx != currentActive {
		ira.lggr.Infow("Switching active indexer",
			"from", currentActive,
			"to", selectedIdx)
		ira.setActiveClientIdx(selectedIdx)
	}

	ira.monitoring.Metrics().IncrementHeartbeatSuccess(ctx)
	ira.monitoring.Metrics().SetLastHeartbeatTimestamp(ctx, time.Now().Unix())
}

func (ira *IndexerReaderAdapter) handleQueryResult(ctx context.Context, selectedIdx int, err error) error {
	if err != nil {
		ira.monitoring.Metrics().IncrementHeartbeatFailure(ctx)
		return err
	}

	ira.recordHeartbeatSuccess(ctx, selectedIdx)
	return nil
}

func (ira *IndexerReaderAdapter) GetVerifierResults(ctx context.Context, messageID protocol.Bytes32) ([]protocol.VerifierResult, error) {
	input := v1.VerifierResultsByMessageIDInput{MessageID: messageID.String()}

	selectedIdx, status, resp, err := queryWithFailover(
		ctx,
		ira,
		input,
		func(c client.IndexerClientInterface, ctx context.Context, in v1.VerifierResultsByMessageIDInput) (int, v1.VerifierResultsByMessageIDResponse, error) {
			return c.VerifierResultsByMessageID(ctx, in)
		},
	)

	// 404 means the indexer is healthy but hasn't seen this message yet
	if status == http.StatusNotFound {
		ira.recordHeartbeatSuccess(ctx, selectedIdx)
		return nil, nil
	}

	if err := ira.handleQueryResult(ctx, selectedIdx, err); err != nil {
		return nil, err
	}

	verifierResults := make([]protocol.VerifierResult, 0, len(resp.Results))
	for _, result := range resp.Results {
		verifierResults = append(verifierResults, result.VerifierResult)
	}

	return verifierResults, nil
}

func (ira *IndexerReaderAdapter) ReadMessages(ctx context.Context, queryData v1.MessagesInput) (map[string]common.MessageWithMetadata, error) {
	selectedIdx, _, resp, err := queryWithFailover(
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
