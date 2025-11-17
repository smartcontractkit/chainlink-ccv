package readers

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
)

// VerifierReader provides the link between the workers and the verifier.
// The reader batches up requests from multiple workers for a best effort
// attempt at batching the requests into a single network call.
//
// It provides a one-shot results channel for every call to ProcessMessage;
// this channel will emit a message once the batch has been completed.
type VerifierReader struct {
	demux         *common.Demultiplexer[protocol.Bytes32, protocol.CCVData]
	batchCh       chan batcher.BatchResult[protocol.Bytes32]
	batcher       *batcher.Batcher[protocol.Bytes32]
	batcherCtx    context.Context
	batcherCancel context.CancelFunc
	verifier      protocol.VerifierResultsAPI
	runCancel     context.CancelFunc
	runWg         sync.WaitGroup
	closeOnce     sync.Once
}

// VerifierReaderConfig holds configuration parameters for a verifierReader.
type VerifierReaderConfig struct {
	// BatchSize is the maximum batch size to send to the verifier.
	BatchSize int
	// MaxWaitTime is the maximum time to wait before sending a batch to the verifier.
	MaxWaitTime time.Duration
	// MaxPendingBatches is the size of the batch channel which can fill up if the verifier
	// is slower than the batcher.
	MaxPendingBatches int
}

// NewVerifierReader creates and returns a new VerifierReader instance.
// The returned reader batches message verification requests and processes them
// asynchronously. The context is used to control the lifetime of the internal
// batcher goroutine.
func NewVerifierReader(ctx context.Context, verifier protocol.VerifierResultsAPI, config VerifierReaderConfig) *VerifierReader {
	batchCh := make(chan batcher.BatchResult[protocol.Bytes32], config.MaxPendingBatches)
	batcherCtx, batcherCancel := context.WithCancel(ctx)

	return &VerifierReader{
		verifier:      verifier,
		demux:         common.NewDemultiplexer[protocol.Bytes32, protocol.CCVData](),
		batchCh:       batchCh,
		batcher:       batcher.NewBatcher(batcherCtx, config.BatchSize, config.MaxWaitTime, batchCh),
		batcherCtx:    batcherCtx,
		batcherCancel: batcherCancel,
	}
}

// ProcessMessage enqueues a message for verification and returns a channel
// that will receive the verification result once processing completes.
//
// The messageID is added to the current batch. When the batch is processed
// (either due to size limits or timeout), the result will be sent on the
// returned channel. The channel is closed after the result is sent.
//
// ProcessMessage returns an error if the message cannot be added to the batch,
// typically because the batcher has been closed or the context has been
// canceled.
func (v *VerifierReader) ProcessMessage(messageID protocol.Bytes32) (chan common.Result[protocol.CCVData], error) {
	err := v.batcher.Add(messageID)
	if err != nil {
		return nil, err
	}

	return v.demux.Create(messageID), nil
}

// Start begins processing batched verification requests in a background goroutine.
// The goroutine runs until ctx is canceled, at which point it stops processing
// new batches and returns.
//
// Start returns immediately after spawning the background goroutine. It does not
// wait for the goroutine to complete.
func (v *VerifierReader) Start(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	v.runCancel = cancel
	v.runWg.Add(1)
	go func() {
		defer v.runWg.Done()
		v.run(runCtx)
	}()
	return nil
}

// run processes batches of verification requests until the context is canceled.
// It receives batches from the batch channel, calls the verifier API, and
// distributes results back to waiting callers via the demultiplexer.
func (v *VerifierReader) run(ctx context.Context) {
	for {
		select {
		case batch, ok := <-v.batchCh:
			if !ok {
				// Channel closed, exit gracefully
				return
			}
			respMap := v.callVerifier(ctx, batch.Items)

			// Iterate over the responses and send the responses back to the caller
			for msgID, verificationResult := range respMap {
				v.demux.Resolve(msgID, verificationResult.Value(), verificationResult.Err())
			}
		case <-ctx.Done():
			return
		}
	}
}

// callVerifier invokes the verifier API with a batch of message IDs and returns
// a map of results keyed by message ID. Each result contains either the
// verification data or an error if the verification failed or was not found.
//
// If the verifier API returns an error, that error is associated with all
// message IDs in the batch. Individual message IDs may still have associated
// data in the response map if the verifier was able to return partial results.
func (v *VerifierReader) callVerifier(ctx context.Context, batch []protocol.Bytes32) map[protocol.Bytes32]common.Result[protocol.CCVData] {
	respMap := make(map[protocol.Bytes32]common.Result[protocol.CCVData])

	if v.verifier == nil {
		// If verifier is not set, return error for all items
		for _, messageID := range batch {
			respMap[messageID] = common.NewResult(protocol.CCVData{}, context.DeadlineExceeded)
		}
		return respMap
	}

	response, err := v.verifier.GetVerifications(ctx, batch)

	// Iterate over the batch of results, return both value and error (if any)
	for _, messageID := range batch {
		value, ok := response[messageID]
		switch {
		case err != nil:
			respMap[messageID] = common.NewResult(value, err)
		case !ok:
			respMap[messageID] = common.NewResult(value, errors.New("verification not found"))
		default:
			respMap[messageID] = common.NewResult(value, nil)
		}
	}

	return respMap
}

// Close gracefully stops the verifier reader. It cancels the batcher's context to
// trigger it to close the batch channel, cancels the run goroutine's context,
// waits for it to finish processing any in-flight batches, and then closes the batcher.
// Subsequent calls to Close are safe and will be no-ops.
func (v *VerifierReader) Close() error {
	var err error
	v.closeOnce.Do(func() {
		// Cancel the batcher's context first, which will cause it to flush remaining
		// items and close the batch channel, allowing the run goroutine to exit
		if v.batcherCancel != nil {
			v.batcherCancel()
		}

		// Cancel the run goroutine context to stop processing new batches
		if v.runCancel != nil {
			v.runCancel()
		}

		// Wait for the run goroutine to finish processing any in-flight batches
		v.runWg.Wait()

		// Close the batcher, which waits for its goroutine to finish
		if v.batcher != nil {
			err = v.batcher.Close()
		}
	})
	return err
}
