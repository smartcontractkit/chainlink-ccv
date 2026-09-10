package sourcereader

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/recovery"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
)

func (r *Service) dropEvent(task verifier.VerificationTask, reason, incident string) recovery.Event {
	block, destination := strconv.FormatUint(task.BlockNumber, 10), task.Message.DestChainSelector.String()
	e := recovery.Event{
		OwnerID: r.verifierID, NodeID: r.recovery.nodeID, SourceChain: r.chainSelector.String(),
		DestChain: &destination, MessageID: &task.MessageID, SourceBlock: &block,
		Kind: "drop", Stage: "admission", Reason: reason,
	}
	if len(task.TxHash) > 0 {
		hash := task.TxHash.String()
		e.TxHash = &hash
	}
	if len(task.SourceBlockHash) > 0 {
		hash := task.SourceBlockHash.String()
		e.BlockHash = &hash
	}
	if incident != "" {
		e.IncidentID = &incident
		e.Stage = "pending_finality"
	}
	return e
}

func (r *Service) auditFailure(ctx context.Context, err error) {
	r.recovery.failedAuditWrites.Add(1)
	r.recovery.metrics.AuditFailure(ctx)
	r.logger.Errorw("Recovery evidence write failed; history is incomplete", "error", err)
}

// Caller has already disabled the reader. An unavailable audit database must
// never prevent blocking finality or flushing pending in-memory state.
func (r *Service) recordFinalityIncident(ctx context.Context) {
	if r.recovery == nil {
		return
	}
	id := uuid.NewString()
	var evidence *FinalityEvidence
	if checker, ok := r.finalityChecker.(interface{ Evidence() *FinalityEvidence }); ok {
		evidence = checker.Evidence()
	}
	details, _ := json.Marshal(struct {
		Evidence             *FinalityEvidence `json:"evidence"`
		PendingFlushed       int               `json:"pending_flushed"`
		SentTrackingFlushed  int               `json:"sent_tracking_flushed"`
		PublishedJobsDeleted bool              `json:"published_jobs_deleted"`
	}{evidence, len(r.pendingTasks), len(r.sentTasks), false})
	e := recovery.Event{
		EventID: id, OwnerID: r.verifierID, NodeID: r.recovery.nodeID,
		SourceChain: r.chainSelector.String(), Kind: "finality_incident", Stage: "pending_finality",
		Reason: "finality_violation", IncidentID: &id, Details: details,
	}
	if evidence != nil {
		block := strconv.FormatUint(evidence.BlockNumber, 10)
		e.SourceBlock = &block
	}
	events := []recovery.Event{e}
	for _, task := range r.pendingTasks {
		events = append(events, r.dropEvent(task, "finality_violation", id))
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := r.recovery.store.RecordEvents(ctx, events...); err != nil {
		r.auditFailure(ctx, err)
	}
}

func (r *Service) recordDrops(ctx context.Context, events []recovery.Event) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := r.recovery.store.RecordEvents(ctx, events...); err != nil {
		r.auditFailure(ctx, err)
	}
}
