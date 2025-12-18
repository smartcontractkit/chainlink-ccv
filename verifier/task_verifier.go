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

type TaskVerifierProcessor struct {
	services.StateMachine
	wg sync.WaitGroup

	lggr       logger.Logger
	verifierID string
	monitoring Monitoring
	verifier   Verifier

	// Consumes from
	sourceReaders map[protocol.ChainSelector]*SourceReaderService
	// produces to
	storageBatcher *batcher.Batcher[protocol.VerifierNodeResult]
}

func NewTaskVerifierProcessor(
	lggr logger.Logger,
	verifierID string,
	verifier Verifier,
	monitoring Monitoring,
	sourceStates map[protocol.ChainSelector]*SourceReaderService,
	storageBatcher *batcher.Batcher[protocol.VerifierNodeResult],
) (*TaskVerifierProcessor, error) {
	p := &TaskVerifierProcessor{
		lggr:           lggr,
		verifierID:     verifierID,
		monitoring:     monitoring,
		verifier:       verifier,
		sourceReaders:  sourceStates,
		storageBatcher: storageBatcher,
	}
	return p, nil
}

func (p *TaskVerifierProcessor) Start(ctx context.Context) error {
	return p.StartOnce(p.Name(), func() error {
		for _, state := range p.sourceReaders {
			p.wg.Go(func() {
				p.run(ctx, state.ReadyTasksChannel())
			})
		}
		return nil
	})
}

func (p *TaskVerifierProcessor) Close() error {
	return p.StopOnce(p.Name(), func() error {
		p.wg.Wait()
		return nil
	})
}

func (p *TaskVerifierProcessor) run(ctx context.Context, ch <-chan batcher.BatchResult[VerificationTask]) {
	for {
		select {
		case <-ctx.Done():
			return
		case batch, ok := <-ch:
			if !ok {
				p.lggr.Infow("ReadyTasksChannel closed; exiting readyTasksLoop")
				return
			}
			if batch.Error != nil {
				p.lggr.Errorw("Error batch received from SourceReaderService",
					"error", batch.Error)
				continue
			}
			p.processReadyTasks(ctx, batch.Items)
		}
	}
}

// processReadyTasks receives tasks that are already ready (finality + curses handled
// by SRS2) and fans out verification per source chain.
func (p *TaskVerifierProcessor) processReadyTasks(ctx context.Context, tasks []VerificationTask) {
	if len(tasks) == 0 {
		return
	}

	p.lggr.Debugw("Processing batch of finalized messages", "batchSize", len(tasks))

	// Metrics: finality wait duration based on QueuedAt set in SRS2
	for _, task := range tasks {
		if !task.QueuedAt.IsZero() && p.monitoring != nil {
			finalityWaitDuration := time.Since(task.QueuedAt)
			p.monitoring.Metrics().
				With("source_chain", task.Message.SourceChainSelector.String(), "verifier_id", p.verifierID).
				RecordFinalityWaitDuration(ctx, finalityWaitDuration)
		}
	}

	// Group tasks by source chain
	tasksByChain := make(map[protocol.ChainSelector][]VerificationTask)
	for _, task := range tasks {
		tasksByChain[task.Message.SourceChainSelector] = append(tasksByChain[task.Message.SourceChainSelector], task)
	}

	// TODO: Can parallelize chains
	// Process each chain's tasks as a batch
	for chainSelector, chainTasks := range tasksByChain {
		_, ok := p.sourceReaders[chainSelector]
		if !ok {
			p.lggr.Errorw("No source state found for finalized messages",
				"chainSelector", chainSelector,
				"taskCount", len(chainTasks))
			continue
		}

		errorBatch := p.verifier.VerifyMessages(ctx, chainTasks, p.storageBatcher)
		p.handleVerificationErrors(ctx, errorBatch, chainSelector, len(tasks))
	}
}

// handleVerificationErrors processes and logs errors from a verification batch.
func (p *TaskVerifierProcessor) handleVerificationErrors(ctx context.Context, errorBatch batcher.BatchResult[VerificationError], chainSelector protocol.ChainSelector, totalTasks int) {
	if len(errorBatch.Items) <= 0 {
		p.lggr.Debugw("Verification batch completed successfully",
			"chainSelector", chainSelector,
			"totalTasks", totalTasks)
		return
	}

	p.lggr.Infow("Verification batch completed with errors",
		"chainSelector", chainSelector,
		"totalTasks", totalTasks,
		"errorCount", len(errorBatch.Items))

	// Log and record metrics for each error
	for _, verificationError := range errorBatch.Items {
		message := verificationError.Task.Message

		// Record verification error metric
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
