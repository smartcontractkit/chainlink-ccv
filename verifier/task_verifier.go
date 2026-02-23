package verifier

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

// TaskVerifierProcessor is responsible for processing read messages from SourceReaderServices,
// verifying them using the provided Verifier, and sending the results to storageBatcher (effectively to StorageWriterProcessor).
// It's the second stage in the verifier processing pipeline.
// It spawns a goroutine per source chain to handle verification concurrently and independently.
// Retries are handled for individual messages based on the verification result. General idea is very similar to
// StorageWriterProcessor, but here Verifier decides whether the error is retryable or not and what delay should be set.
// That way we give Verifier who is aware of the business logic more control over retry behavior.
type TaskVerifierProcessor struct {
	services.StateMachine
	wg     sync.WaitGroup
	cancel context.CancelFunc

	lggr       logger.Logger
	verifierID string
	monitoring Monitoring
	verifier   Verifier

	// Pending writing tracker (shared with SRS and SWP)
	writingTracker *PendingWritingTracker

	// Consumes from
	sourceFanouts map[protocol.ChainSelector]SourceReaderFanout
	// produces to
	storageBatcher *batcher.Batcher[protocol.VerifierNodeResult]
}

// SourceReaderFanout defines the interface that TaskVerifierProcessor expects from SourceReaderService
// to read ready tasks and retry failed ones. This abstraction allows TaskVerifierProcessor to not depend
// directly on SourceReaderService implementation details.
type SourceReaderFanout interface {
	// RetryTasks re-queues the given tasks for retry after the specified delay. Should delegate to
	// the underlying Batcher used by SourceReaderService.
	RetryTasks(minDelay time.Duration, tasks ...VerificationTask) error
	// ReadyTasksChannel provides a channel from which ready tasks can be consumed
	ReadyTasksChannel() <-chan batcher.BatchResult[VerificationTask]
}

func NewTaskVerifierProcessor(
	lggr logger.Logger,
	verifierID string,
	verifier Verifier,
	monitoring Monitoring,
	sourceStates map[protocol.ChainSelector]*SourceReaderService,
	storageBatcher *batcher.Batcher[protocol.VerifierNodeResult],
	writingTracker *PendingWritingTracker,
) (*TaskVerifierProcessor, error) {
	sourceFanouts := make(map[protocol.ChainSelector]SourceReaderFanout)
	for chainSelector, srs := range sourceStates {
		sourceFanouts[chainSelector] = srs
	}

	return NewTaskVerifierProcessorWithFanouts(
		lggr, verifierID, verifier, monitoring, sourceFanouts, storageBatcher, writingTracker,
	)
}

func NewTaskVerifierProcessorWithFanouts(
	lggr logger.Logger,
	verifierID string,
	verifier Verifier,
	monitoring Monitoring,
	sourceFanouts map[protocol.ChainSelector]SourceReaderFanout,
	storageBatcher *batcher.Batcher[protocol.VerifierNodeResult],
	writingTracker *PendingWritingTracker,
) (*TaskVerifierProcessor, error) {
	p := &TaskVerifierProcessor{
		lggr:           lggr,
		verifierID:     verifierID,
		monitoring:     monitoring,
		verifier:       verifier,
		sourceFanouts:  sourceFanouts,
		storageBatcher: storageBatcher,
		writingTracker: writingTracker,
	}
	return p, nil
}

func (p *TaskVerifierProcessor) Start(ctx context.Context) error {
	return p.StartOnce(p.Name(), func() error {
		cancelCtx, cancel := context.WithCancel(ctx)
		p.cancel = cancel
		for sourceChainSelector, fanout := range p.sourceFanouts {
			p.wg.Go(func() {
				p.run(cancelCtx, sourceChainSelector, fanout)
			})
		}
		return nil
	})
}

func (p *TaskVerifierProcessor) Close() error {
	return p.StopOnce(p.Name(), func() error {
		p.cancel()
		p.wg.Wait()
		return nil
	})
}

func (p *TaskVerifierProcessor) run(
	ctx context.Context,
	selector protocol.ChainSelector,
	sourceFanout SourceReaderFanout,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case batch, ok := <-sourceFanout.ReadyTasksChannel():
			if !ok {
				p.lggr.Infow("ReadyTasksChannel closed; exiting readyTasksLoop")
				return
			}
			if batch.Error != nil {
				p.lggr.Errorw("Error batch received from SourceReaderService",
					"error", batch.Error)
				continue
			}
			p.processReadyTasks(ctx, selector, sourceFanout, batch.Items)
		}
	}
}

// processReadyTasks receives tasks that are already ready (finality + curses handled
// by SRS) and fans out verification per source chain.
func (p *TaskVerifierProcessor) processReadyTasks(
	ctx context.Context,
	chainSelector protocol.ChainSelector,
	sourceFanout SourceReaderFanout,
	tasks []VerificationTask,
) {
	if len(tasks) == 0 {
		return
	}

	p.lggr.Debugw("Processing batch of finalized messages", "batchSize", len(tasks))

	// Metrics: finality wait duration based on QueuedAt set in SRS
	for _, task := range tasks {
		if !task.QueuedAt.IsZero() && p.monitoring != nil {
			finalityWaitDuration := time.Since(task.QueuedAt)
			p.monitoring.Metrics().
				With("source_chain", task.Message.SourceChainSelector.String(), "verifier_id", p.verifierID).
				RecordFinalityWaitDuration(ctx, finalityWaitDuration)
		}
	}

	results := p.verifier.VerifyMessages(ctx, tasks)
	p.handleVerificationResults(ctx, chainSelector, sourceFanout, results)
}

// handleVerificationResults processes both successful results and errors from verification.
// Successful results are added to the storage batcher, while errors are retried or marked as permanent failures.
func (p *TaskVerifierProcessor) handleVerificationResults(
	ctx context.Context,
	chainSelector protocol.ChainSelector,
	src SourceReaderFanout,
	results []VerificationResult,
) {
	if len(results) == 0 {
		return
	}

	var successCount, errorCount int

	// Process each result
	for _, result := range results {
		if result.Error != nil {
			errorCount++
			p.handleVerificationError(ctx, chainSelector, src, *result.Error)
		} else if result.Result != nil {
			successCount++
			p.handleVerificationSuccess(result.Result)
		}
	}

	p.lggr.Debugw("Verification batch completed",
		"chainSelector", chainSelector,
		"totalResults", len(results),
		"successCount", successCount,
		"errorCount", errorCount)
}

// handleVerificationError processes a single verification error, either retrying or marking as permanent failure.
func (p *TaskVerifierProcessor) handleVerificationError(
	ctx context.Context,
	chainSelector protocol.ChainSelector,
	src SourceReaderFanout,
	verificationError VerificationError,
) {
	message := verificationError.Task.Message

	p.monitoring.Metrics().
		With(
			"source_chain", message.SourceChainSelector.String(),
			"dest_chain", message.DestChainSelector.String(),
			"verifier_id", p.verifierID,
		).
		IncrementMessagesVerificationFailed(ctx)

	p.lggr.Errorw("Message verification failed",
		"error", verificationError.Error,
		"messageID", verificationError.Task.MessageID,
		"nonce", message.SequenceNumber,
		"sourceChain", message.SourceChainSelector,
		"destChain", message.DestChainSelector,
		"timestamp", verificationError.Timestamp,
		"chainSelector", chainSelector,
		"retryable", verificationError.Retryable,
	)

	if verificationError.Retryable {
		p.retryVerificationTask(chainSelector, src, verificationError)
	} else {
		p.handlePermanentFailure(chainSelector, verificationError)
	}
}

// retryVerificationTask attempts to re-queue a task for retry.
func (p *TaskVerifierProcessor) retryVerificationTask(
	chainSelector protocol.ChainSelector,
	src SourceReaderFanout,
	verificationError VerificationError,
) {
	err := src.RetryTasks(
		verificationError.DelayOrDefault(),
		verificationError.Task,
	)
	if err != nil {
		message := verificationError.Task.Message
		p.lggr.Errorw("Failed to re-queue message for verification retry",
			"error", err.Error(),
			"messageID", verificationError.Task.MessageID,
			"nonce", message.SequenceNumber,
			"sourceChain", message.SourceChainSelector,
			"destChain", message.DestChainSelector,
			"chainSelector", chainSelector,
		)
	}
}

// handlePermanentFailure removes a permanently failed task from the tracker.
func (p *TaskVerifierProcessor) handlePermanentFailure(
	chainSelector protocol.ChainSelector,
	verificationError VerificationError,
) {
	p.writingTracker.Remove(
		chainSelector,
		verificationError.Task.MessageID,
	)
}

// handleVerificationSuccess adds a successful result to the storage batcher.
func (p *TaskVerifierProcessor) handleVerificationSuccess(result *protocol.VerifierNodeResult) {
	if err := p.storageBatcher.Add(*result); err != nil {
		p.lggr.Errorw("Failed to add verified result to storage batcher",
			"error", err,
			"messageID", result.MessageID.String(),
			"sequenceNumber", result.Message.SequenceNumber,
			"sourceChain", result.Message.SourceChainSelector,
		)
	}
}

func (p *TaskVerifierProcessor) Name() string {
	return fmt.Sprintf("verifier.TaskVerifierProcessor[%s]", p.verifierID)
}

func (p *TaskVerifierProcessor) HealthReport() map[string]error {
	report := make(map[string]error)
	report[p.Name()] = p.Ready()
	return report
}

var (
	_ services.Service        = (*TaskVerifierProcessor)(nil)
	_ protocol.HealthReporter = (*TaskVerifierProcessor)(nil)
)
