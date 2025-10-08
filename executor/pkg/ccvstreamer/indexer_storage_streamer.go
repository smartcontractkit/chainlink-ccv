package ccvstreamer

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/exp/maps"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/common/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// Ensure IndexerStorageStreamer implements the MessageSubscriber interface.
var _ executor.MessageSubscriber = &IndexerStorageStreamer{}

type IndexerStorageConfig struct {
	IndexerClient   *storageaccess.IndexerAPIReader
	LastQueryTime   int64
	PollingInterval time.Duration
	Backoff         time.Duration
	QueryLimit      uint64
}

func NewIndexerStorageStreamer(
	lggr logger.Logger,
	indexerConfig IndexerStorageConfig,
) *IndexerStorageStreamer {

	return &IndexerStorageStreamer{
		reader:          indexerConfig.IndexerClient,
		lggr:            lggr,
		queryLimit:      indexerConfig.QueryLimit,
		lastQueryTime:   indexerConfig.LastQueryTime,
		pollingInterval: indexerConfig.PollingInterval,
		backoff:         indexerConfig.Backoff,
	}
}

type IndexerStorageStreamer struct {
	reader          *storageaccess.IndexerAPIReader
	lggr            logger.Logger
	lastQueryTime   int64
	pollingInterval time.Duration
	backoff         time.Duration
	queryLimit      uint64
	mu              sync.RWMutex
	running         bool
	querymu         sync.RWMutex
}

func (oss *IndexerStorageStreamer) IsRunning() bool {
	oss.mu.RLock()
	defer oss.mu.RUnlock()
	return oss.running
}

// Start implements the MessageSubscriber interface.
func (oss *IndexerStorageStreamer) Start(
	ctx context.Context,
	wg *sync.WaitGroup,
) (<-chan executor.StreamerResult, error) {
	if oss.reader == nil {
		return nil, errors.New("reader not set")
	}

	messagesCh := make(chan executor.StreamerResult)
	wg.Add(1)
	oss.running = true

	go func() {
		defer func() {
			wg.Done()
			close(messagesCh)

			oss.mu.Lock()
			oss.running = false
			oss.mu.Unlock()
		}()
		newtime := time.Now().Unix()
		offset := uint64(0)
		for {
			select {
			case <-ctx.Done():
				// Context canceled, stop loop.
				return
			default:
				// Non-blocking: call ReadCCVData
				oss.lggr.Debugw("IndexerStorageStreamer querying for results", "offset", offset, "start", oss.lastQueryTime, "end", newtime)
				responses, err := oss.reader.ReadMessages(ctx, storageaccess.MessagesV1Request{
					Limit:                oss.queryLimit,
					Offset:               offset,
					Start:                oss.lastQueryTime,
					End:                  newtime,
					SourceChainSelectors: nil,
					DestChainSelectors:   nil,
				})
				if len(responses) != 0 {
					oss.lggr.Infow("IndexerStorageStreamer found messages using query", "offset", offset, "start", oss.lastQueryTime, "end", newtime, "messages", responses)
				}

				result := executor.StreamerResult{
					Messages: maps.Values(responses),
					Error:    err,
				}

				select {
				case <-ctx.Done():
					return
				case messagesCh <- result:
				}

				// Handle query results and determine next action
				var waitDuration time.Duration
				shouldUpdateQueryWindow := false

				switch {
				case err != nil:
					// Error occurred: backoff and retry with same parameters
					oss.lggr.Infow("IndexerStorageStreamer read error", "error", err)
					waitDuration = oss.backoff

				case uint64(len(responses)) == oss.queryLimit:
					// Hit query limit: query again immediately with same time range but incremented offset
					oss.lggr.Infow("IndexerStorageStreamer hit query limit, there may be more results to read", "limit", oss.queryLimit)
					offset += oss.queryLimit
					continue // Skip waiting and time updates, query immediately

				default:
					// Complete result set received: update query window and reset for next polling cycle
					waitDuration = oss.pollingInterval
					shouldUpdateQueryWindow = true
					offset = 0
				}

				// Wait before next iteration (common for error and complete cases)
				select {
				case <-ctx.Done():
					return
				case <-time.After(waitDuration):
				}

				// Update query window if we completed a full result set
				if shouldUpdateQueryWindow {
					oss.querymu.Lock()
					oss.lastQueryTime = newtime
					oss.querymu.Unlock()
				}

				// Update time for next iteration
				newtime = time.Now().Unix()
			}
		}
	}()

	return messagesCh, nil
}

func validateVerifierResults(results []protocol.CCVData) error {
	messageIDs := make(map[protocol.Bytes32]struct{}, 0)
	generatedIDs := make(map[protocol.Bytes32]struct{}, 0)
	for _, res := range results {
		messageIDs[res.MessageID] = struct{}{}
		genID, err := res.Message.MessageID()
		if err != nil {
			return fmt.Errorf("invalid generated messageId")
		}
		generatedIDs[genID] = struct{}{}
	}
	if len(messageIDs) != 1 {
		return fmt.Errorf("verifier results contain multiple message IDs")
	}
	if len(generatedIDs) != 1 {
		return fmt.Errorf("verifier results contain multiple generated message IDs")
	}
	return nil
}
