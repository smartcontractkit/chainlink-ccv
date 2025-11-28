package verifier

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

// SourceReaderService2 is a higher-level wrapper around SourceReaderService that:
//
//   - Reads raw VerificationTasks from the underlying SourceReaderService
//   - Maintains a per-chain pending queue
//   - Runs finality checks (default + custom) to decide when tasks are ready
//   - Applies curse checker gating (source -> dest lane)
//   - Handles reorgs and finality violations via a protocol.ReorgDetector
//   - Emits only "ready" tasks on ReadyTasksChannel()
//
// Coordinator should consume ReadyTasksChannel() and never see raw tasks.
type SourceReaderService2 struct {
	sync   services.StateMachine
	stopCh services.StopChan
	wg     sync.WaitGroup

	lggr logger.Logger

	// Underlying reader (existing implementation)
	reader *SourceReaderService

	// Ready tasks channel exposed to coordinator
	readyTasksCh chan batcher.BatchResult[VerificationTask]

	// Configuration
	finalityCheckInterval time.Duration

	// Dependencies / configuration copied from coordinator
	curseDetector      common.CurseCheckerService
	chainStatusManager protocol.ChainStatusManager
	reorgDetector      protocol.ReorgDetector

	// Per-chain identity (copied from underlying reader)
	chainSelector protocol.ChainSelector

	// Mutable state guarded by mu
	mu           sync.Mutex
	pendingTasks []VerificationTask
	disabled     bool // set to true on finality violation
}

// NewSourceReaderService2 constructs the pipeline on top of an existing SourceReaderService.
//
// Typical wiring from coordinator:
//
//	srs := NewSourceReaderService(...)
//	srs2 := NewSourceReaderService2(
//	    srs,
//	    vc.lggr,
//	    vc.curseDetector,
//	    vc.chainStatusManager,
//	    detector,               // protocol.ReorgDetector
//	    finalityCheckInterval,  // same as coordinator
//	)
func NewSourceReaderService2(
	reader *SourceReaderService,
	lggr logger.Logger,
	curseDetector common.CurseCheckerService,
	chainStatusManager protocol.ChainStatusManager,
	reorgDetector protocol.ReorgDetector,
	finalityCheckInterval time.Duration,
) *SourceReaderService2 {
	if lggr == nil {
		// Fallback to underlying reader logger if present
		lggr = reader.logger
	}

	return &SourceReaderService2{
		lggr:                  lggr,
		reader:                reader,
		readyTasksCh:          make(chan batcher.BatchResult[VerificationTask]),
		finalityCheckInterval: finalityCheckInterval,
		curseDetector:         curseDetector,
		chainStatusManager:    chainStatusManager,
		reorgDetector:         reorgDetector,
		chainSelector:         reader.chainSelector,
	}
}

// ReadyTasksChannel exposes batches of tasks that are already ready for verification.
func (s *SourceReaderService2) ReadyTasksChannel() <-chan batcher.BatchResult[VerificationTask] {
	return s.readyTasksCh
}

// Start starts:
//   - underlying SourceReaderService (log polling)
//   - enqueue loop (raw -> pending queue)
//   - finality loop (pending queue -> ready)
//   - reorg / finality violation loop (if reorgDetector != nil)
func (s *SourceReaderService2) Start(ctx context.Context) error {
	return s.sync.StartOnce("SourceReaderService2", func() error {
		s.lggr.Infow("Starting SourceReaderService2",
			"chainSelector", s.chainSelector)

		// 1. Start underlying reader
		if err := s.reader.Start(ctx); err != nil {
			s.lggr.Errorw("Failed to start underlying SourceReaderService",
				"chainSelector", s.chainSelector,
				"error", err)
			return err
		}

		// 2. Start reorg detector (if provided)
		var reorgStatusCh <-chan protocol.ChainStatus
		if s.reorgDetector != nil {
			statusCh, err := s.reorgDetector.Start(ctx)
			if err != nil {
				s.lggr.Errorw("Failed to start reorg detector",
					"chainSelector", s.chainSelector,
					"error", err)
				return err
			}
			reorgStatusCh = statusCh

			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.reorgUpdatesLoop(ctx, reorgStatusCh)
			}()
		} else {
			s.lggr.Infow("No reorg detector configured for SourceReaderService2",
				"chainSelector", s.chainSelector)
		}

		// 3. Start enqueue loop (raw tasks -> pending queue)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.enqueueLoop()
		}()

		// 4. Start finality loop (pending queue -> ready tasks)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.finalityLoop(ctx)
		}()

		s.lggr.Infow("SourceReaderService2 started successfully",
			"chainSelector", s.chainSelector)

		return nil
	})
}

// Stop stops:
//   - finality loop
//   - enqueue loop
//   - reorg detector (through context cancellation)
//   - underlying SourceReaderService
func (s *SourceReaderService2) Stop() error {
	return s.sync.StopOnce("SourceReaderService2", func() error {
		s.lggr.Infow("Stopping SourceReaderService2",
			"chainSelector", s.chainSelector)

		// Signal loops to stop
		close(s.stopCh)

		// Stop underlying reader first (so its channel closes)
		if err := s.reader.Stop(); err != nil {
			s.lggr.Errorw("Failed to stop underlying SourceReaderService",
				"chainSelector", s.chainSelector,
				"error", err)
		}

		// Wait for internal goroutines
		s.wg.Wait()

		// Close ready channel
		close(s.readyTasksCh)

		s.lggr.Infow("SourceReaderService2 stopped successfully",
			"chainSelector", s.chainSelector)

		return nil
	})
}

// LatestAndFinalizedBlock delegates to underlying reader.
// Kept for compatibility / any external callers.
func (s *SourceReaderService2) LatestAndFinalizedBlock(
	ctx context.Context,
) (latest, finalized *protocol.BlockHeader, err error) {
	return s.reader.LatestAndFinalizedBlock(ctx)
}

// -----------------------------------------------------------------------------
// Internal loops
// -----------------------------------------------------------------------------

// enqueueLoop consumes raw batches from the underlying reader and pushes tasks
// into the pending queue (with curse gating).
func (s *SourceReaderService2) enqueueLoop() {
	ch := s.reader.VerificationTaskChannel()

	for {
		select {
		case <-s.stopCh:
			s.lggr.Debugw("enqueueLoop stopped via stopCh",
				"chainSelector", s.chainSelector)
			return
		case batch, ok := <-ch:
			if !ok {
				s.lggr.Infow("Underlying VerificationTaskChannel closed; enqueueLoop exiting",
					"chainSelector", s.chainSelector)
				return
			}

			// If batch is an error batch, just forward it as-is to readyTasksCh.
			if batch.Error != nil {
				s.forwardError(batch.Error)
				continue
			}

			for _, task := range batch.Items {
				s.addToPendingQueue(task)
			}
		}
	}
}

// finalityLoop periodically checks latest / finalized blocks and moves ready
// tasks from pending queue to readyTasksCh.
func (s *SourceReaderService2) finalityLoop(ctx context.Context) {
	ticker := time.NewTicker(s.finalityCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			s.lggr.Debugw("finalityLoop stopped via stopCh",
				"chainSelector", s.chainSelector)
			return
		case <-ctx.Done():
			s.lggr.Debugw("finalityLoop stopped via context cancellation",
				"chainSelector", s.chainSelector)
			return
		case <-ticker.C:
			s.processFinality(ctx)
		}
	}
}

// reorgUpdatesLoop consumes reorg / finality violation events and adjusts the
// pending queue + reader state accordingly.
func (s *SourceReaderService2) reorgUpdatesLoop(ctx context.Context, statusCh <-chan protocol.ChainStatus) {
	for {
		select {
		case <-s.stopCh:
			s.lggr.Debugw("reorgUpdatesLoop stopped via stopCh",
				"chainSelector", s.chainSelector)
			return
		case <-ctx.Done():
			s.lggr.Debugw("reorgUpdatesLoop stopped via context cancellation",
				"chainSelector", s.chainSelector)
			return
		case newStatus, ok := <-statusCh:
			if !ok {
				s.lggr.Debugw("Reorg status channel closed; reorgUpdatesLoop exiting",
					"chainSelector", s.chainSelector)
				return
			}

			switch newStatus.Type {
			case protocol.ReorgTypeNormal:
				s.handleReorg(ctx, newStatus)
			case protocol.ReorgTypeFinalityViolation:
				s.handleFinalityViolation(ctx, newStatus)
			default:
				// only abnormal statuses should be sent, but be defensive
				s.lggr.Warnw("Received unexpected chain status",
					"chainSelector", s.chainSelector,
					"type", newStatus.Type.String())
			}
		}
	}
}

// -----------------------------------------------------------------------------
// Pending queue + finality logic
// -----------------------------------------------------------------------------

// addToPendingQueue enqueues a task if the chain is not disabled and the lane
// is not cursed.
func (s *SourceReaderService2) addToPendingQueue(task VerificationTask) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.disabled {
		s.lggr.Debugw("Dropping task - chain disabled",
			"chainSelector", s.chainSelector,
			"blockNumber", task.BlockNumber)
		return
	}

	// If we have a curse detector, drop cursed lanes
	if s.curseDetector != nil {
		// Use context.TODO() since underlying implementation doesn't use context today
		if s.curseDetector.IsRemoteChainCursed(
			context.TODO(),
			task.Message.SourceChainSelector,
			task.Message.DestChainSelector,
		) {
			msgLggr := logger.With(
				s.lggr,
				"messageID", task.Message.MustMessageID(),
				"source", task.Message.SourceChainSelector,
				"dest", task.Message.DestChainSelector,
			)
			msgLggr.Warnw("Dropping task - lane is cursed",
				"blockNumber", task.BlockNumber)
			return
		}
	}

	// Set QueuedAt timestamp for finality wait duration tracking
	task.QueuedAt = time.Now()

	s.pendingTasks = append(s.pendingTasks, task)
}

// processFinality checks the pending queue against latest/finalized headers and
// emits ready tasks as a batch.
func (s *SourceReaderService2) processFinality(ctx context.Context) {
	latest, finalized, err := s.reader.LatestAndFinalizedBlock(ctx)
	if err != nil {
		s.lggr.Warnw("Failed to get latest and finalized block",
			"chainSelector", s.chainSelector,
			"error", err)
		return
	}
	if latest == nil || finalized == nil {
		s.lggr.Warnw("Latest or finalized block is nil",
			"chainSelector", s.chainSelector)
		return
	}

	latestBlock := latest.Number
	latestFinalizedBlock := finalized.Number

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.disabled {
		return
	}

	readyTasks := make([]VerificationTask, 0, len(s.pendingTasks))
	remainingTasks := s.pendingTasks[:0]

	for _, task := range s.pendingTasks {
		msgLggr := logger.With(
			s.lggr,
			"messageID", task.Message.MustMessageID(),
			"source", task.Message.SourceChainSelector,
			"dest", task.Message.DestChainSelector,
		)

		// Check curse status again at finality time
		if s.curseDetector != nil {
			if s.curseDetector.IsRemoteChainCursed(
				ctx,
				task.Message.SourceChainSelector,
				task.Message.DestChainSelector,
			) {
				msgLggr.Warnw("Dropping finalized task - lane is cursed",
					"chain", s.chainSelector)
				// Drop task
				continue
			}
		}

		ready, err := s.isMessageReadyForVerification(task, new(big.Int).SetUint64(latestBlock), new(big.Int).SetUint64(latestFinalizedBlock))
		if err != nil {
			msgLggr.Warnw("Failed to check finality for message",
				"error", err,
				"chain", s.chainSelector)
			// Keep in queue to retry later
			remainingTasks = append(remainingTasks, task)
			continue
		}

		if ready {
			readyTasks = append(readyTasks, task)
		} else {
			remainingTasks = append(remainingTasks, task)
		}
	}

	s.pendingTasks = remainingTasks

	if len(readyTasks) == 0 {
		return
	}

	s.lggr.Infow("Processing finalized messages",
		"chain", s.chainSelector,
		"readyCount", len(readyTasks),
		"remainingCount", len(remainingTasks))

	// Emit ready batch to coordinator
	batch := batcher.BatchResult[VerificationTask]{
		Items: readyTasks,
	}

	select {
	case s.readyTasksCh <- batch:
		// (Coordinator will handle verification + storage)
	case <-s.stopCh:
		s.lggr.Debugw("Dropping ready batch - service stopping",
			"chainSelector", s.chainSelector)
	}
}

// isMessageReadyForVerification implements the same logic we currently use in
// the Coordinator for default/custom finality.
func (s *SourceReaderService2) isMessageReadyForVerification(
	task VerificationTask,
	latestBlock *big.Int,
	latestFinalizedBlock *big.Int,
) (bool, error) {
	messageID, err := task.Message.MessageID()
	if err != nil {
		return false, fmt.Errorf("failed to compute message ID: %w", err)
	}

	finalityConfig := task.Message.Finality
	messageBlockNumber := new(big.Int).SetUint64(task.BlockNumber)

	ready := false

	if finalityConfig == 0 {
		// Default finality: wait for chain finalization
		ready = messageBlockNumber.Cmp(latestFinalizedBlock) <= 0
		if ready {
			s.lggr.Debugw("Message meets default finality requirement",
				"messageID", messageID,
				"messageBlock", messageBlockNumber.String(),
				"finalizedBlock", latestFinalizedBlock.String(),
			)
		}
	} else {
		// Custom finality: message_block + finality_config <= latest_block
		requiredBlock := new(big.Int).Add(
			messageBlockNumber,
			new(big.Int).SetUint64(uint64(finalityConfig)),
		)

		s.lggr.Infow("Checking custom finality requirement",
			"messageID", messageID,
			"messageBlock", messageBlockNumber.String(),
			"finalityConfig", finalityConfig,
			"requiredBlock", requiredBlock.String(),
			"latestBlock", latestBlock.String(),
		)

		ready = requiredBlock.Cmp(latestBlock) <= 0
		if ready {
			s.lggr.Debugw("Message meets custom finality requirement",
				"messageID", messageID,
				"messageBlock", messageBlockNumber.String(),
				"finalityConfig", finalityConfig,
				"requiredBlock", requiredBlock.String(),
				"latestBlock", latestBlock.String(),
			)
		}
	}

	return ready, nil
}

// -----------------------------------------------------------------------------
// Reorg / finality violation handling
// -----------------------------------------------------------------------------

// handleReorg flushes tasks above the common ancestor and resets the reader.
func (s *SourceReaderService2) handleReorg(
	ctx context.Context,
	reorgStatus protocol.ChainStatus,
) {
	commonAncestor := reorgStatus.ResetToBlock
	s.lggr.Infow("Handling reorg",
		"chain", s.chainSelector,
		"type", reorgStatus.Type.String(),
		"commonAncestor", commonAncestor)

	var flushedCount int

	s.mu.Lock()
	if s.disabled {
		s.mu.Unlock()
		return
	}

	remaining := s.pendingTasks[:0]
	for _, task := range s.pendingTasks {
		if task.BlockNumber > commonAncestor {
			flushedCount++
			continue
		}
		remaining = append(remaining, task)
	}
	s.pendingTasks = remaining

	// Reset SourceReaderService synchronously to the common ancestor
	if err := s.reader.ResetToBlock(commonAncestor); err != nil {
		s.lggr.Errorw("Failed to reset source reader after reorg",
			"error", err,
			"chain", s.chainSelector,
			"resetBlock", commonAncestor)
	} else {
		s.lggr.Infow("Source reader reset successfully after reorg",
			"chain", s.chainSelector,
			"resetBlock", commonAncestor)
	}
	s.mu.Unlock()

	s.lggr.Infow("Reorg handled successfully",
		"chain", s.chainSelector,
		"commonAncestor", commonAncestor,
		"flushedTasks", flushedCount)
}

// handleFinalityViolation disables the chain, flushes all pending tasks,
// stops the reader, and writes disabled chain status.
func (s *SourceReaderService2) handleFinalityViolation(
	ctx context.Context,
	violationStatus protocol.ChainStatus,
) {
	s.lggr.Errorw("FINALITY VIOLATION DETECTED - stopping chain reader immediately",
		"chain", s.chainSelector,
		"type", violationStatus.Type.String())

	s.mu.Lock()
	if s.disabled {
		s.mu.Unlock()
		return
	}

	flushedCount := len(s.pendingTasks)
	s.pendingTasks = nil
	s.disabled = true

	s.mu.Unlock()

	s.lggr.Errorw("Flushed ALL pending tasks due to finality violation",
		"chain", s.chainSelector,
		"flushedCount", flushedCount)

	// Stop underlying reader immediately
	if err := s.reader.Stop(); err != nil {
		s.lggr.Errorw("Failed to stop source reader after finality violation",
			"error", err,
			"chain", s.chainSelector)
	} else {
		s.lggr.Errorw("Source reader stopped due to finality violation - manual intervention required",
			"chain", s.chainSelector)
	}

	// Write disabled chain status (blockHeight=0, Disabled=true)
	if s.chainStatusManager != nil {
		blockHeight := big.NewInt(0)
		err := s.chainStatusManager.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
			{
				ChainSelector:        s.chainSelector,
				FinalizedBlockHeight: blockHeight,
				Disabled:             true,
			},
		})
		if err != nil {
			s.lggr.Errorw("Failed to write disabled chain status",
				"error", err,
				"chain", s.chainSelector)
		} else {
			s.lggr.Infow("Disabled chain status written due to finality violation",
				"chain", s.chainSelector)
		}
	}

	// After this, finalityLoop / enqueueLoop will naturally drain via stopCh / channel closure.
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func (s *SourceReaderService2) forwardError(err error) {
	batch := batcher.BatchResult[VerificationTask]{
		Error: err,
	}

	select {
	case s.readyTasksCh <- batch:
		s.lggr.Debugw("Forwarded batch error to coordinator", "error", err)
	case <-s.stopCh:
		s.lggr.Debugw("Dropping batch error - service stopping", "error", err)
	}
}
