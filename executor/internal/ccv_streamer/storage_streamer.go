package ccv_streamer

import (
	"context"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/executor/types"
	protocol_types "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// OffchainStorageStreamer implements the Streamer interface using an OffchainStorageReader.
func OffchainStorageStreamer(reader protocol_types.OffchainStorageReader, backoff time.Duration) Streamer {
	return func(
		ctx context.Context,
		lggr logger.Logger,
		wg *sync.WaitGroup,
	) <-chan types.MessageWithCCVData {
		messagesCh := make(chan types.MessageWithCCVData)
		wg.Add(1)

		go func() {
			defer wg.Done()
			defer close(messagesCh)

			for {
				select {
				case <-ctx.Done():
					// Context canceled, stop loop.
					return
				default:
					// Non-blocking: call ReadCCVData
					responses, err := reader.ReadCCVData(ctx)
					if err != nil {
						lggr.Errorw("failed to read ccv data", "error", err)
						select {
						case <-ctx.Done():
							return
						case <-time.After(backoff):
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

		return messagesCh
	}
}
