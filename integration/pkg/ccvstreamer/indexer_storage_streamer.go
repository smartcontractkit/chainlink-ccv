package ccvstreamer

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/message_heap"
	v1 "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api/handlers/v1"
	icommon "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// Ensure IndexerStorageStreamer implements the MessageSubscriber interface.
var (
	_ executor.MessageSubscriber = &IndexerStorageStreamer{}
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
	latestSeenTime  time.Time
	pollingInterval time.Duration
	backoff         time.Duration
	queryLimit      uint64
	offset          uint64
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
// It returns a channel of messages and a channel of errors, and an error if the reader is not set or the streamer is already running.
func (oss *IndexerStorageStreamer) Start(
	ctx context.Context,
) (<-chan icommon.MessageWithMetadata, <-chan error, error) {
	if oss.reader == nil {
		return nil, nil, fmt.Errorf("reader not set")
	}
	if oss.running {
		return nil, nil, fmt.Errorf("IndexerStorageStreamer already running")
	}

	oss.running = true

	// be careful closing the results channel before context is done. This might cause unintended consequences upstream.
	results := make(chan icommon.MessageWithMetadata)
	errors := make(chan error)
	go func() {
		defer func() {
			oss.mu.Lock()
			oss.running = false
			oss.mu.Unlock()
			close(results)
			close(errors)
		}()
		ticker := time.NewTicker(oss.cleanInterval)
		defer ticker.Stop()
		nextQueryTimer := time.NewTimer(0)
		defer nextQueryTimer.Stop()
		for {
			select {
			case <-ctx.Done():
				// Context canceled, stop loop.
				return
			case <-ticker.C:
				oss.expirableSet.CleanExpired(oss.timeProvider.GetTime())
			case <-nextQueryTimer.C:
				responses, err := oss.reader.ReadMessages(ctx, v1.MessagesInput{
					Limit:                oss.queryLimit,
					Start:                oss.lastQueryTime.Format(time.RFC3339),
					Offset:               oss.offset,
					SourceChainSelectors: nil,
					DestChainSelectors:   nil,
				})
				oss.lggr.Debugw("IndexerStorageStreamer query results", "start", oss.lastQueryTime, "count", len(responses), "error", err)

				for _, msgWithMetadata := range responses {
					if msgWithMetadata.Metadata.IngestionTimestamp.After(oss.lastQueryTime) {
						oss.latestSeenTime = msgWithMetadata.Metadata.IngestionTimestamp
					}
					netNewMessage := oss.expirableSet.PushUnlessExists(msgWithMetadata.Message.MustMessageID(), msgWithMetadata.Metadata.IngestionTimestamp)
					if netNewMessage {
						oss.lggr.Infow("Found net new message from Indexer", "messageID", msgWithMetadata.Message.MustMessageID(), "msgWithMetadata", msgWithMetadata)
						results <- msgWithMetadata
					}
				}

				// Determine if we should wait before querying again, or read new results immediately.
				switch {
				case err != nil:
					// Error occurred: backoff and retry with same parameters
					oss.lggr.Errorw("IndexerStorageStreamer read error", "error", err)
					nextQueryTimer.Reset(oss.backoff)
					errors <- fmt.Errorf("IndexerStorageStreamer read error: %w", err)
				case uint64(len(responses)) == oss.queryLimit:
					// Hit query limit: query again immediately with same time range but incremented offset
					oss.lggr.Infow("IndexerStorageStreamer hit query limit, there may be more results to read", "limit", oss.queryLimit)
					oss.offset += uint64(len(responses))
					nextQueryTimer.Reset(0)
				default:
					// Complete result set received: update query window and reset for next polling cycle
					oss.offset = 0
					oss.lastQueryTime = oss.latestSeenTime
					nextQueryTimer.Reset(oss.pollingInterval)
				}
			}
		}
	}()

	return results, errors, nil
}
