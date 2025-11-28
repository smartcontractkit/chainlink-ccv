package ccvstreamer

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// Ensure IndexerStorageStreamer implements the MessageSubscriber interface.
var _ executor.MessageSubscriber = &IndexerStorageStreamer{}

type IndexerStorageConfig struct {
	IndexerClient    executor.MessageReader
	InitialQueryTime time.Time
	PollingInterval  time.Duration
	Backoff          time.Duration
	QueryLimit       uint64
}

func NewIndexerStorageStreamer(
	lggr logger.Logger,
	indexerConfig IndexerStorageConfig,
) *IndexerStorageStreamer {
	return &IndexerStorageStreamer{
		reader:          indexerConfig.IndexerClient,
		lggr:            lggr,
		queryLimit:      indexerConfig.QueryLimit,
		lastQueryTime:   indexerConfig.InitialQueryTime,
		pollingInterval: indexerConfig.PollingInterval,
		backoff:         indexerConfig.Backoff,
	}
}

type IndexerStorageStreamer struct {
	reader          executor.MessageReader
	lggr            logger.Logger
	lastQueryTime   time.Time
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
	results chan protocol.MessageWithMetadata,
	errors chan error,
) error {
	if oss.reader == nil {
		return fmt.Errorf("reader not set")
	}
	if oss.running {
		return fmt.Errorf("IndexerStorageStreamer already running")
	}

	oss.running = true

	go func() {
		defer func() {
			oss.mu.Lock()
			oss.running = false
			oss.mu.Unlock()
		}()
		var waitDuration time.Duration
		for {
			select {
			case <-ctx.Done():
				// Context canceled, stop loop.
				return
			default:
				responses, err := oss.reader.ReadMessages(ctx, protocol.MessagesV1Request{
					Limit:                oss.queryLimit,
					Start:                oss.lastQueryTime,
					SourceChainSelectors: nil,
					DestChainSelectors:   nil,
				})
				oss.lggr.Infow("IndexerStorageStreamer query results", "start", oss.lastQueryTime, "count", len(responses), "error", err)

				for _, msgWithMetadata := range responses {
					oss.lggr.Infow("Found message from Indexer", "msgWithMetadata", msgWithMetadata)
					if msgWithMetadata.Metadata.IngestionTimestamp.After(oss.lastQueryTime) {
						oss.lastQueryTime = msgWithMetadata.Metadata.IngestionTimestamp
					}
					results <- msgWithMetadata
				}

				// Determine if we should wait before querying again, or read new results immediately.
				switch {
				case err != nil:
					// Error occurred: backoff and retry with same parameters
					waitDuration = oss.backoff
					errors <- fmt.Errorf("IndexerStorageStreamer read error: %w", err)

				case uint64(len(responses)) == oss.queryLimit:
					// Hit query limit: query again immediately with same time range but incremented offset
					oss.lggr.Infow("IndexerStorageStreamer hit query limit, there may be more results to read", "limit", oss.queryLimit)
					continue // Skip waiting and time updates, query immediately

				default:
					// Complete result set received: update query window and reset for next polling cycle
					waitDuration = oss.pollingInterval
				}

				// Wait before next iteration (common for error and complete cases)
				select {
				case <-ctx.Done():
					return
				case <-time.After(waitDuration):
				}
			}
		}
	}()

	return nil
}
