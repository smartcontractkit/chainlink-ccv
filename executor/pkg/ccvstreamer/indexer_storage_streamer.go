package ccvstreamer

import (
	"context"
	"errors"
	"fmt"
	mapset "github.com/deckarep/golang-set/v2"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	storageaccess "github.com/smartcontractkit/chainlink-ccv/common/storageaccess"
	protocol "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

// Ensure IndexerStorageStreamer implements the CCVResultStreamer interface.
var _ executor.CCVResultStreamer = &IndexerStorageStreamer{}

func NewIndexerStorageStreamer(
	indexerURI string, lggr logger.Logger, lastQueryTime int64, pollingInterval, backoff time.Duration,
) *IndexerStorageStreamer {
	client := storageaccess.NewIndexerAPIReader(lggr, indexerURI)

	return &IndexerStorageStreamer{
		reader:          client,
		lastQueryTime:   lastQueryTime,
		pollingInterval: pollingInterval,
		backoff:         backoff,
	}
}

type IndexerStorageStreamer struct {
	reader          *storageaccess.IndexerAPIReader
	lastQueryTime   int64
	pollingInterval time.Duration
	backoff         time.Duration
	mu              sync.RWMutex
	running         bool
	querymu         sync.RWMutex
}

func (oss *IndexerStorageStreamer) IsRunning() bool {
	oss.mu.RLock()
	defer oss.mu.RUnlock()
	return oss.running
}

// Start implements the CCVResultStreamer interface.
func (oss *IndexerStorageStreamer) Start(
	ctx context.Context,
	lggr logger.Logger,
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

		for {
			select {
			case <-ctx.Done():
				// Context canceled, stop loop.
				return
			default:

				// reset the last query time for new reads
				newtime := time.Now().Unix()

				msgs := make([]types.MessageWithCCVData, 0)
				// Non-blocking: call ReadCCVData
				lggr.Infow("IndexerStorageStreamer reading ccv data", "lastQueryTime", oss.lastQueryTime)

				responses, err := oss.reader.ReadVerifierResults(ctx, storageaccess.VerifierResultsRequest{
					Limit:                0,
					Offset:               0,
					Start:                oss.lastQueryTime,
					End:                  0,
					SourceChainSelectors: nil,
					DestChainSelectors:   nil,
				})

				for id, verifierResults := range responses {
					if len(verifierResults) < 1 {
						lggr.Errorw("invalid message from reader", "messageID", id, "verifierResults", verifierResults)
						continue
					}

					if err := validateVerifierResults(verifierResults); err != nil {
						lggr.Errorw("invalid verifier results from reader", "messageID", id, "error", err)
						continue
					}

					lggr.Infow("received message", "messageID", id, "ccvData", verifierResults)
					msgs = append(msgs, types.MessageWithCCVData{
						Message:           verifierResults[0].Message,
						CCVData:           verifierResults,
						VerifiedTimestamp: verifierResults[0].Timestamp,
					})
				}

				result := executor.StreamerResult{
					Messages: msgs,
					Error:    err,
				}

				select {
				case <-ctx.Done():
					return
				case messagesCh <- result:
				}

				// If there is no error, and there are results, read again immediately.
				delay := time.Duration(0)

				// there was an error, use the backoff duration.
				if err != nil {
					lggr.Errorw("IndexerStorageStreamer failed to read ccv data", "error", err)
					delay = oss.backoff
				} else if len(responses) == 0 {
					// no results, use the polling interval.
					delay = oss.pollingInterval
				}

				// maybe wait before the next read.
				if delay != 0 {
					select {
					case <-ctx.Done():
						return
					case <-time.After(delay):
					}
				}

				oss.querymu.Lock()
				oss.lastQueryTime = newtime
				oss.querymu.Unlock()
			}
		}
	}()

	return messagesCh, nil
}

func validateVerifierResults(results []protocol.CCVData) error {
	messageIds := mapset.NewSet[protocol.Bytes32]()
	genMessageIds := mapset.NewSet[protocol.Bytes32]()
	for _, res := range results {
		messageIds.Add(res.MessageID)
		genId, err := res.Message.MessageID()
		if err != nil {
			return fmt.Errorf("invalid generated messageId")
		}
		genMessageIds.Add(genId)
	}
	if messageIds.Cardinality() != 1 {
		return fmt.Errorf("verifier results contain multiple message IDs")
	}
	if genMessageIds.Cardinality() != 1 {
		return fmt.Errorf("verifier results contain multiple generated message IDs")
	}
	return nil
}
