package ccvstreamer

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/types"
	protocol_types "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// Ensure OffchainStorageStreamer implements the CCVResultStreamer interface.
var _ executor.CCVResultStreamer = &OffchainStorageStreamer{}

func NewOffchainStorageStreamer(
	reader protocol_types.OffchainStorageReader, pollilngInterval, backoff time.Duration,
) *OffchainStorageStreamer {
	return &OffchainStorageStreamer{
		reader:          reader,
		pollingInterval: pollilngInterval,
		backoff:         backoff,
	}
}

type OffchainStorageStreamer struct {
	reader          protocol_types.OffchainStorageReader
	pollingInterval time.Duration
	backoff         time.Duration

	mu      sync.RWMutex
	err     error
	running bool
}

func (oss *OffchainStorageStreamer) Status() (bool, error) {
	oss.mu.RLock()
	defer oss.mu.RUnlock()
	return oss.running, oss.err
}

// Start implements the CCVResultStreamer interface using an OffchainStorageReader.
func (oss *OffchainStorageStreamer) Start(
	ctx context.Context,
	lggr logger.Logger,
	wg *sync.WaitGroup,
) (<-chan types.MessageWithCCVData, error) {
	// TODO: validate the reader?
	if oss.reader == nil {
		return nil, errors.New("reader not set")
	}

	messagesCh := make(chan types.MessageWithCCVData)
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
			case <-time.After(oss.pollingInterval):
				// Non-blocking: call ReadCCVData
				responses, err := oss.reader.ReadCCVData(ctx)
				if err != nil {
					lggr.Errorw("OffchainStorageStreamer failed to read ccv data", "error", err)
					oss.mu.Lock()
					oss.err = err
					oss.mu.Unlock()

					select {
					case <-ctx.Done():
						return
					case <-time.After(oss.backoff):
					}
					continue
				}
				for _, msg := range responses {
					// TODO: convert QueryResponse to MessageWithCCVData
					var msg2 types.MessageWithCCVData
					lggr.Infow("received message", "message", msg)
					select {
					case <-ctx.Done():
						return
					case messagesCh <- msg2:
					}
				}
			}
		}
	}()

	return messagesCh, nil
}
