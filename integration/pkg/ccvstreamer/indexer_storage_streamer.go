package ccvstreamer

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/message_heap"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// Ensure IndexerStorageStreamer implements the MessageSubscriber interface.
var (
	_             executor.MessageSubscriber = &IndexerStorageStreamer{}
	pollingBuffer                            = -1 * time.Millisecond
)

type IndexerStorageConfig struct {
	IndexerClient    executor.MessageReader
	InitialQueryTime time.Time
	PollingInterval  time.Duration
	Backoff          time.Duration
	QueryLimit       uint64
	ExpiryDuration   time.Duration
	CleanInterval    time.Duration
	TimeProvider     common.TimeProvider
}

func NewIndexerStorageStreamer(
	lggr logger.Logger,
	indexerConfig IndexerStorageConfig,
) *IndexerStorageStreamer {
	expirableSet := message_heap.NewExpirableSet(indexerConfig.ExpiryDuration)
	return &IndexerStorageStreamer{
		reader:          indexerConfig.IndexerClient,
		lggr:            lggr,
		queryLimit:      indexerConfig.QueryLimit,
		lastQueryTime:   indexerConfig.InitialQueryTime,
		pollingInterval: indexerConfig.PollingInterval,
		backoff:         indexerConfig.Backoff,
		expirableSet:    expirableSet,
		cleanInterval:   indexerConfig.CleanInterval,
		timeProvider:    indexerConfig.TimeProvider,
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
	expirableSet    *message_heap.ExpirableMessageSet
	cleanInterval   time.Duration
	timeProvider    common.TimeProvider
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
		ticker := time.NewTicker(oss.cleanInterval)
		defer ticker.Stop()
		var nextQueryTime time.Time
		for {
			select {
			case <-ctx.Done():
				// Context canceled, stop loop.
				return
			case <-ticker.C:
				oss.expirableSet.CleanExpired(oss.timeProvider.GetTime())
			default:
				if oss.timeProvider.GetTime().Before(nextQueryTime) {
					continue
				}
				responses, err := oss.reader.ReadMessages(ctx, protocol.MessagesV1Request{
					Limit:                oss.queryLimit,
					Start:                oss.lastQueryTime.Add(pollingBuffer).UnixMilli(),
					SourceChainSelectors: nil,
					DestChainSelectors:   nil,
				})
				oss.lggr.Infow("IndexerStorageStreamer query results", "start", oss.lastQueryTime, "count", len(responses), "error", err)

				for _, msgWithMetadata := range responses {
					if msgWithMetadata.Metadata.IngestionTimestamp.After(oss.lastQueryTime) {
						oss.lastQueryTime = msgWithMetadata.Metadata.IngestionTimestamp
					}
					netNewMessage := oss.expirableSet.PushUnlessExists(msgWithMetadata.Message.MustMessageID(), msgWithMetadata.Metadata.IngestionTimestamp)
					if netNewMessage {
						oss.lggr.Infow("Found net new message from Indexer", "msgWithMetadata", msgWithMetadata)
						results <- msgWithMetadata
					}
				}

				// Determine if we should wait before querying again, or read new results immediately.
				switch {
				case err != nil:
					// Error occurred: backoff and retry with same parameters
					nextQueryTime = oss.timeProvider.GetTime().Add(oss.backoff)
					errors <- fmt.Errorf("IndexerStorageStreamer read error: %w", err)

				case uint64(len(responses)) == oss.queryLimit:
					// Hit query limit: query again immediately with same time range but incremented offset
					oss.lggr.Infow("IndexerStorageStreamer hit query limit, there may be more results to read", "limit", oss.queryLimit)
					continue // Skip waiting and time updates, query immediately

				default:
					// Complete result set received: update query window and reset for next polling cycle
					nextQueryTime = oss.timeProvider.GetTime().Add(oss.pollingInterval)
				}
			}
		}
	}()

	return nil
}
