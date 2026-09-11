package sourcereader

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sync/atomic"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/common/monitoring/tracing"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/jobqueue"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/recovery"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
)

type recoveryResetter interface {
	ApplyRecoveryReset(protocol.ChainSelector, func() error) error
}

type recoveryChunkResult struct {
	ready      []verifier.VerificationTask
	droppedIDs []string
}

type recoveryRuntime struct {
	store             *recovery.Store
	queue             *jobqueue.PostgresJobQueue[verifier.VerificationTask]
	resetter          recoveryResetter
	slots             chan struct{}
	nodeID            string
	metrics           *recovery.Metrics
	rebuildingID      string
	registered        bool
	lastHeartbeat     time.Time
	lastCleanup       time.Time
	failedAuditWrites atomic.Int64
}

// ConfigureRecovery is called before Start. All recovery and reader mutations run
// on the existing event loop; slots bound recovery concurrency across this owner.
func (r *Service) ConfigureRecovery(store *recovery.Store, queue *jobqueue.PostgresJobQueue[verifier.VerificationTask], slots chan struct{}) error {
	resetter, ok := r.chainStatusManager.(recoveryResetter)
	if !ok || store == nil || queue == nil || cap(slots) == 0 {
		return fmt.Errorf("recovery requires a store, queue, concurrency bound and synchronized checkpoint manager")
	}
	metrics, err := recovery.NewMetrics(r.verifierID, r.chainSelector.String())
	if err != nil {
		return err
	}
	node, err := os.Hostname()
	if err != nil {
		node = "unavailable"
	}
	r.recovery = &recoveryRuntime{store: store, queue: queue, resetter: resetter, slots: slots, nodeID: node, metrics: metrics}
	return nil
}

func (r *Service) recoveryHeartbeat(ctx context.Context, latest *uint64) {
	p := r.recovery
	if p == nil || time.Since(p.lastHeartbeat) < 30*time.Second {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if !p.registered {
		if err := p.store.RegisterReader(ctx, r.verifierID, r.chainSelector.String(), p.nodeID, r.disabled.Load()); err != nil {
			r.auditFailure(ctx, err)
			return
		}
		p.registered = true
	}
	if latest == nil {
		// Disabled readers advertise heads without discovering or admitting messages.
		if head, _, err := r.sourceReader.LatestAndFinalizedBlock(ctx); err == nil && head != nil {
			latest = &head.Number
		}
	}
	failures := p.failedAuditWrites.Swap(0)
	if err := p.store.Heartbeat(ctx, r.verifierID, r.chainSelector.String(), latest, r.disabled.Load(), failures); err != nil {
		p.failedAuditWrites.Add(failures)
		r.logger.Errorw("Recovery reader heartbeat failed", "error", err)
		return
	}
	p.lastHeartbeat = time.Now()
	if err := p.store.CollectMetrics(ctx, r.verifierID, r.chainSelector.String(), p.metrics); err != nil {
		r.logger.Errorw("Recovery metric collection failed", "error", err)
	}
	if time.Since(p.lastCleanup) >= time.Hour {
		if err := p.store.Cleanup(ctx, r.verifierID); err != nil {
			r.logger.Errorw("Recovery history cleanup failed", "error", err)
		} else {
			p.lastCleanup = time.Now()
		}
	}
}

// recoveryControl also runs for disabled readers, including those disabled at
// startup. An ordinary operation cannot change the disabled flag or checker.
func (r *Service) recoveryControl(ctx context.Context) {
	p := r.recovery
	if p == nil {
		return
	}
	if r.disabled.Load() {
		r.recoveryHeartbeat(ctx, nil)
	}
	ctx, cancel := context.WithTimeout(ctx, r.pollTimeout)
	defer cancel()
	activeReset, err := p.store.ActiveReset(ctx, r.verifierID, r.chainSelector.String())
	if err != nil {
		r.logger.Errorw("Cannot determine source recovery state; pausing reader", "error", err)
		p.rebuildingID = "unknown"
		return
	}
	p.rebuildingID = activeReset
	o, err := p.store.Next(ctx, r.verifierID, r.chainSelector.String())
	if errors.Is(err, sql.ErrNoRows) {
		return
	}
	if err != nil {
		r.logger.Errorw("Failed to read recovery requests", "error", err)
		return
	}
	if o.Mode == "reset-reader" && !o.ResetApplied {
		select {
		case p.slots <- struct{}{}:
			defer func() { <-p.slots }()
		default:
			return
		}
		if err := r.resetReader(ctx, o); err != nil {
			r.failRecovery(ctx, o, err)
		}
		return
	}
	if r.disabled.Load() {
		if err := p.store.Step(ctx, o.ID, func(_ *recovery.Store, current *recovery.Operation) error {
			current.State, current.LastError = "blocked", "reader disabled; an investigated reset-reader operation is required"
			return nil
		}); err != nil {
			r.logger.Errorw("Failed to record blocked recovery", "error", err)
		}
	}
}

func (r *Service) resetReader(ctx context.Context, requested recovery.Operation) error {
	if !r.disabled.Load() {
		return fmt.Errorf("reader is already enabled; submit replay for source-range recovery")
	}
	var checker protocol.FinalityViolationChecker = &NoOpFinalityViolationChecker{}
	if !r.sourceCfg.DisableFinalityChecker {
		var err error
		checker, err = NewFinalityViolationCheckerService(r.sourceReader, r.chainSelector, r.logger, r.metrics())
		if err != nil {
			return err
		}
		if err := checker.UpdateFinalized(ctx, resetBoundary(requested.FromBlock)); err != nil {
			return fmt.Errorf("read investigated boundary: %w", err)
		}
	}
	p := r.recovery
	applied := false
	err := p.resetter.ApplyRecoveryReset(r.chainSelector, func() error {
		err := p.store.Step(ctx, requested.ID, func(tx *recovery.Store, o *recovery.Operation) error {
			if o.Mode != "reset-reader" || o.ResetApplied {
				return fmt.Errorf("reset was already applied; it cannot clear a later finality block")
			}
			_, err := tx.DataSource().ExecContext(ctx, `INSERT INTO ccv_chain_statuses
				(chain_selector,verifier_id,finalized_block_height,disabled) VALUES ($1,$2,$3,FALSE)
				ON CONFLICT (chain_selector,verifier_id) DO UPDATE SET finalized_block_height=EXCLUDED.finalized_block_height,disabled=FALSE,updated_at=NOW()`,
				o.SourceChain, o.OwnerID, fmt.Sprint(resetBoundary(o.FromBlock)))
			if err != nil {
				return err
			}
			_, err = tx.DataSource().ExecContext(ctx, `UPDATE ccv_recovery_operations SET state='blocked',
				last_error='superseded by a new investigated reader reset',updated_at=NOW()
				WHERE id=(SELECT active_reset_id FROM ccv_recovery_readers WHERE owner_id=$1 AND chain_selector=$2) AND id<>$3`, o.OwnerID, o.SourceChain, o.ID)
			if err != nil {
				return err
			}
			_, err = tx.DataSource().ExecContext(ctx, "UPDATE ccv_recovery_readers SET active_reset_id=$3,disabled=FALSE WHERE owner_id=$1 AND chain_selector=$2", o.OwnerID, o.SourceChain, o.ID)
			if err != nil {
				return err
			}
			details, _ := json.Marshal(map[string]string{"operation_id": o.ID, "actor": o.Actor, "note": o.Note, "boundary": fmt.Sprint(resetBoundary(o.FromBlock))})
			block := fmt.Sprint(resetBoundary(o.FromBlock))
			if err := tx.RecordEvents(ctx, recovery.Event{
				OwnerID: o.OwnerID, NodeID: p.nodeID, SourceChain: o.SourceChain,
				SourceBlock: &block, Kind: "reader_reset", Stage: "operator", Reason: "operator_reset", Details: details,
			}); err != nil {
				return err
			}
			o.ResetApplied, applied = true, true
			return nil
		})
		if err == nil && !applied {
			return fmt.Errorf("reset request no longer active")
		}
		return err
	})
	if err != nil {
		return err
	}
	// The durable reset committed and buffered writes can no longer overwrite it.
	r.mu.Lock()
	p.rebuildingID = requested.ID
	r.finalityChecker = checker
	r.pendingTasks = make(map[string]verifier.VerificationTask)
	r.pendingSince = make(map[string]time.Time)
	r.sentTasks = make(map[string]verifier.VerificationTask)
	r.reorgTracker = NewReorgTracker(r.logger, r.metrics())
	r.lastProcessedFinalizedBlock.Store(new(big.Int).SetUint64(requested.FromBlock))
	r.finalityBlocked.Store(false)
	r.disabled.Store(false)
	r.mu.Unlock()
	r.metrics().SetVerifierFinalityViolated(ctx, r.chainSelector, false)
	r.logger.Infow("Reader re-enabled by live recovery", "operationID", requested.ID, "boundary", resetBoundary(requested.FromBlock), "actor", requested.Actor)
	return nil
}

func (r *Service) failRecovery(ctx context.Context, operation recovery.Operation, cause error) {
	r.logger.Errorw("Source recovery failed", "operationID", operation.ID, "error", cause)
	// Use a fresh bounded child of the service context when an RPC deadline expired.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := r.recovery.store.Fail(ctx, operation.ID, operation.UpdatedAt, cause); err != nil {
		r.logger.Errorw("Failed to persist recovery error; request will be retried", "operationID", operation.ID, "error", err)
	}
}

func (r *Service) recoverRange(ctx context.Context, latest, safe, finalized *protocol.BlockHeader) {
	p := r.recovery
	if p == nil || r.disabled.Load() {
		return
	}
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	default:
		return
	}
	ctx, cancel := context.WithTimeout(ctx, r.pollTimeout)
	defer cancel()
	var o recovery.Operation
	var err error
	if p.rebuildingID != "" {
		if p.rebuildingID == "unknown" {
			return
		}
		o, err = p.store.Get(ctx, p.rebuildingID)
		if err == nil && o.State != "accepted" && o.State != "running" {
			return
		}
	} else {
		o, err = p.store.Next(ctx, r.verifierID, r.chainSelector.String())
	}
	if errors.Is(err, sql.ErrNoRows) {
		return
	}
	if err != nil {
		r.logger.Errorw("Recovery lookup failed", "error", err)
		return
	}
	if o.Mode == "reset-reader" && !o.ResetApplied {
		return
	}
	var completedReset, published bool
	var committedChunk *recoveryChunkResult
	err = p.store.Step(ctx, o.ID, func(tx *recovery.Store, current *recovery.Operation) error {
		o.UpdatedAt = current.UpdatedAt
		previousAdmitted := current.Admitted
		var err error
		committedChunk, err = r.recoverChunk(ctx, tx, current, latest, safe, finalized)
		published = current.Admitted > previousAdmitted
		completedReset = err == nil && current.Mode == "reset-reader" && current.State == "completed"
		return err
	})
	if err != nil {
		r.failRecovery(ctx, o, err)
		return
	}
	// Reconcile only after commit. Keep non-finalized publications in the normal
	// reader's sent tracking so its overlapping scans do not republish them.
	r.mu.Lock()
	if committedChunk != nil {
		for _, id := range committedChunk.droppedIDs {
			delete(r.pendingTasks, id)
			delete(r.pendingSince, id)
		}
		for _, task := range committedChunk.ready {
			delete(r.pendingTasks, task.MessageID)
			delete(r.pendingSince, task.MessageID)
			if task.BlockNumber >= finalized.Number {
				r.sentTasks[task.MessageID] = task
			}
			r.reorgTracker.Remove(task.Message.DestChainSelector, task.Message.SequenceNumber)
		}
	}
	r.mu.Unlock()
	if completedReset {
		p.rebuildingID = ""
		// Clamped to finality, the same way the durable checkpoint in recoverChunk is. A range
		// that ends above the finalized head leaves an unfinalized suffix that can still reorg;
		// resuming past it would mean the canonical replacement events are never discovered,
		// and the in-memory cursor is what the next poll reads. A fully finalized range still
		// resumes at ToBlock+1.
		next := min(o.ToBlock, finalized.Number) + 1
		r.lastProcessedFinalizedBlock.Store(new(big.Int).SetUint64(next))
	}
	if published {
		p.queue.NotifyPublished()
	}
}

func (r *Service) recoverChunk(ctx context.Context, tx *recovery.Store, o *recovery.Operation, latest, safe, finalized *protocol.BlockHeader) (*recoveryChunkResult, error) {
	var active int
	if err := tx.DataSource().QueryRowxContext(ctx, "SELECT COUNT(*) FROM ccv_task_verifier_jobs WHERE owner_id=$1", r.verifierID).Scan(&active); err != nil {
		return nil, err
	}
	if active >= recovery.MaxActiveJobs {
		o.LastError = "waiting for verification queue capacity"
		return nil, nil
	}
	chunkSize := min(r.maxBlockRange, uint64(recovery.MaxChunkBlocks))
	if chunkSize == 0 {
		chunkSize = recovery.MaxChunkBlocks
	}
	end := o.NextBlock + min(chunkSize-1, o.ToBlock-o.NextBlock)
	if o.NextBlock > latest.Number {
		o.LastError = "waiting for source head to reach this chunk"
		return nil, nil
	}
	end = min(end, latest.Number)
	events, err := r.sourceReader.FetchMessageSentEvents(ctx, new(big.Int).SetUint64(o.NextBlock), new(big.Int).SetUint64(end))
	if err != nil {
		return nil, err
	}
	for _, event := range events {
		if event.BlockNumber < o.NextBlock || event.BlockNumber > end {
			return nil, fmt.Errorf("source reader returned an event outside the requested recovery chunk")
		}
	}
	if len(events) > recovery.MaxChunkMessages {
		return nil, fmt.Errorf("chunk has more than %d messages; submit a smaller source range", recovery.MaxChunkMessages)
	}
	tasks := r.tasksFromEvents(ctx, events, latest, finalized)
	defer func() {
		for _, task := range tasks {
			tracing.SpanFromContext(task.TraceContext).End()
		}
	}()
	var safeBlock *big.Int
	if safe != nil {
		safeBlock = new(big.Int).SetUint64(safe.Number)
	}
	ready := make([]verifier.VerificationTask, 0, len(tasks))
	drops := make([]recovery.Event, 0)
	droppedIDs := make([]string, 0)
	for _, task := range tasks {
		decision, reason, err := r.admission(ctx, task, new(big.Int).SetUint64(latest.Number), safeBlock, new(big.Int).SetUint64(finalized.Number))
		if err != nil || decision == admissionWait {
			o.LastError = "waiting: " + reason
			if err != nil {
				o.LastError += ": " + err.Error()
				o.Errors++
			}
			return nil, nil // Re-read this entire canonical chunk; no jobs or progress have been persisted.
		}
		if decision == admissionDrop {
			drops = append(drops, r.dropEvent(task, reason, ""))
			droppedIDs = append(droppedIDs, task.MessageID)
			continue
		}
		task.SourceBlockTimestamp = sourceBlockTimestamp(task.BlockNumber, task.SourceBlockTimestamp, latest, safe, finalized)
		task.FinalizedBlockAtReady, task.ReadyForVerificationAt = finalized.Number, latest.Timestamp
		task.PushedToVerificationQueueAt = time.Now()
		ready = append(ready, task)
	}
	if active+len(ready) > recovery.MaxActiveJobs {
		o.LastError = "waiting for verification queue capacity"
		return nil, nil
	}
	if len(drops) > 0 {
		if err := tx.RecordEvents(ctx, drops...); err != nil {
			r.auditFailure(ctx, err)
			return nil, err
		}
	}
	inserted, err := r.recovery.queue.PublishInTransaction(ctx, tx.DataSource(), ready...)
	if err != nil {
		return nil, err
	}
	o.Admitted += inserted
	o.Conflicts += int64(len(ready)) - inserted
	o.Dropped += int64(len(drops))
	o.Filtered += int64(len(events) - len(tasks))
	o.NextBlock = end + 1
	if end == o.ToBlock {
		o.State = "completed"
		if o.Mode == "reset-reader" {
			if err := r.completeReset(ctx, tx, o, min(end, finalized.Number)); err != nil {
				return nil, err
			}
		}
	}
	return &recoveryChunkResult{ready: ready, droppedIDs: droppedIDs}, nil
}

// completeReset lands an investigated reset: it advances the durable checkpoint and releases the
// reservation that has been holding normal polling back.
//
// checkpoint is already clamped to the finalized head by the caller. Anything above it can still
// reorg, so persisting it would let a restart resume past blocks whose canonical events were
// never read.
//
// The update requires the row to still be enabled. A reader an operator disabled again while the
// reset was running is left alone rather than advanced, which is why a raced reset is safe to
// investigate and retry rather than something that has already moved the checkpoint.
func (r *Service) completeReset(ctx context.Context, tx *recovery.Store, o *recovery.Operation, checkpoint uint64) error {
	result, err := tx.DataSource().ExecContext(ctx,
		"UPDATE ccv_chain_statuses SET finalized_block_height=$3,updated_at=NOW() WHERE verifier_id=$1 AND chain_selector=$2 AND NOT disabled",
		o.OwnerID, o.SourceChain, fmt.Sprint(checkpoint))
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated != 1 {
		return errors.New("reader was disabled during recovery; checkpoint was not advanced")
	}
	_, err = tx.DataSource().ExecContext(ctx,
		"UPDATE ccv_recovery_readers SET active_reset_id=NULL WHERE owner_id=$1 AND chain_selector=$2 AND active_reset_id=$3",
		o.OwnerID, o.SourceChain, o.ID)
	return err
}

func resetBoundary(from uint64) uint64 {
	if from == 0 {
		return 0
	}
	return from - 1
}
