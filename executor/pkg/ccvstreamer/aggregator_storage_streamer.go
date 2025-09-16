package ccvstreamer

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	protocol "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

// Ensure OffchainStorageStreamer implements the CCVResultStreamer interface.
var _ executor.CCVResultStreamer = &OffchainStorageStreamer{}

func NewOffchainStorageStreamer(
	reader protocol.OffchainStorageReader, pollingInterval, backoff time.Duration,
) *OffchainStorageStreamer {
	return &OffchainStorageStreamer{
		reader:          reader,
		pollingInterval: pollingInterval,
		backoff:         backoff,
	}
}

type OffchainStorageStreamer struct {
	reader          protocol.OffchainStorageReader
	pollingInterval time.Duration
	backoff         time.Duration
	mu              sync.RWMutex
	running         bool
}

func (oss *OffchainStorageStreamer) IsRunning() bool {
	oss.mu.RLock()
	defer oss.mu.RUnlock()
	return oss.running
}

// Start implements the CCVResultStreamer interface using an OffchainStorageReader.
func (oss *OffchainStorageStreamer) Start(
	ctx context.Context,
	lggr logger.Logger,
	wg *sync.WaitGroup,
) (<-chan executor.StreamerResult, error) {
	// TODO: validate the reader?
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
				// Non-blocking: call ReadCCVData
				responses, err := oss.reader.ReadCCVData(ctx)

				msgs := make([]types.MessageWithCCVData, len(responses))
				for _, msg := range responses {
					// TODO: convert QueryResponse to MessageWithCCVData
					lggr.Infow("received message", "messageID", msg.Data.MessageID.String())
					msgs = append(msgs, types.MessageWithCCVData{
						Message:           msg.Data.Message,
						VerifiedTimestamp: *msg.Timestamp,
					})
				}

				result := executor.StreamerResult{
					Messages: msgs,
					Error:    err,
				}

				lggr.Infow("OffchainStorageStreamer read", "count", len(msgs), "error", err)
				lggr.Infow("OffchainStorageStreamer writing ", "result", result)
				select {
				case <-ctx.Done():
					return
				case messagesCh <- result:
				}

				// If there is no error, and there are results, read again immediately.
				delay := time.Duration(0)

				// there was an error, use the backoff duration.
				if err != nil {
					lggr.Errorw("OffchainStorageStreamer failed to read ccv data", "error", err)
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
			}
		}
	}()

	return messagesCh, nil
}
