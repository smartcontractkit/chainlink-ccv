package admin

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-ccv/cli/jobqueue"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/admin/views"
)

// Reschedule: preview the exact owners/jobs a reschedule affects, recheck attestation
// state before mutating (unknown ≠ needs replay), execute one owner-scoped operation
// per target, report per-target results. Every execution re-runs the archive and
// attestation gate; no path skips it.

// rescheduleTarget is one parsed `target` form field, pipe-separated as emitted by the
// message detail page: jobID|messageIDHex|queue|ownerID.
type rescheduleTarget struct {
	JobID        string
	MessageID    []byte
	MessageIDHex string
	Queue        jobqueue.QueueType
	OwnerID      string
}

func parseRescheduleTarget(raw string) (rescheduleTarget, error) {
	var t rescheduleTarget
	parts := strings.SplitN(raw, "|", 4)
	if len(parts) != 4 {
		return t, fmt.Errorf("expected jobID|messageID|queue|ownerID, got %d fields", len(parts))
	}
	t.JobID, t.OwnerID = parts[0], parts[3]
	id, err := jobqueue.ParseMessageID(parts[1])
	if err != nil || len(id) != 32 {
		return t, fmt.Errorf("invalid message ID %q: expected a full 0x-prefixed 32-byte hex ID", parts[1])
	}
	t.MessageID = id
	t.MessageIDHex = formatMessageID(id)
	t.Queue = jobqueue.QueueType(parts[2])
	if t.Queue != jobqueue.QueueTypeTaskVerifier && t.Queue != jobqueue.QueueTypeStorageWriter {
		return t, fmt.Errorf("unknown queue %q", parts[2])
	}
	if t.JobID == "" || t.OwnerID == "" {
		return t, fmt.Errorf("job ID and owner must both be non-empty")
	}
	return t, nil
}

func parseRetryDuration(raw string) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return time.Hour, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid retry_duration %q: must be a positive duration (e.g. 30m, 1h)", raw)
	}
	return d, nil
}

// jobQueueStore is a var so tests can substitute a fake without a database.
var jobQueueStore = func(s stores) jobqueue.Store { return s.JobQueue() }

func (h *handlers) registerRescheduleRoutes(r *gin.Engine) {
	r.POST("/reschedule/preview", h.reschedulePreview)
	r.POST("/reschedule/execute", h.rescheduleExecute)
}

// recheckState is the pre-mutation verdict for one target.
type recheckState string

const (
	recheckExecutable recheckState = "executable" // still failed and not attested
	recheckSkip       recheckState = "skip"       // genuinely nothing to do
	recheckUnknown    recheckState = "unknown"    // cannot prove a replay is needed
)

// recheckArchiveRow confirms the target's archive row still exists as a failed job
// belonging to the claimed owner.
func recheckArchiveRow(ctx context.Context, store jobqueue.Store, t rescheduleTarget) (recheckState, string, *jobqueue.ArchivedJob) {
	jobs, err := store.ListFailedFiltered(ctx, []jobqueue.QueueType{t.Queue}, t.OwnerID, [][]byte{t.MessageID}, 0)
	if err != nil {
		return recheckUnknown, "archive lookup failed: " + err.Error(), nil
	}
	for i := range jobs {
		if jobs[i].JobID == t.JobID && jobs[i].OwnerID == t.OwnerID {
			return recheckExecutable, "", &jobs[i]
		}
	}
	return recheckSkip, "no matching failed archive row — already rescheduled or expired", nil
}

// previewTarget carries one target plus its recheck verdict into the view model.
type previewTarget struct {
	target rescheduleTarget
	raw    string
	state  recheckState
	detail string
	job    *jobqueue.ArchivedJob
}

func (h *handlers) reschedulePreview(c *gin.Context) {
	fullPage := c.GetHeader("HX-Request") == ""
	raws := c.PostFormArray("target")
	if len(raws) == 0 {
		h.render(c, http.StatusBadRequest, views.ReschedulePreview(h.csrfToken(c), nil, "No targets submitted.", fullPage))
		return
	}
	pts := make([]previewTarget, 0, len(raws))
	for _, raw := range raws {
		pt := previewTarget{raw: raw}
		t, err := parseRescheduleTarget(raw)
		if err != nil {
			pt.state, pt.detail = recheckSkip, "invalid target: "+err.Error()
			pts = append(pts, pt)
			continue
		}
		pt.target = t
		pt.state, pt.detail, pt.job = recheckArchiveRow(c.Request.Context(), jobQueueStore(h.stores), t)
		pts = append(pts, pt)
	}
	h.recheckAttestations(c.Request.Context(), pts)
	h.render(c, http.StatusOK, views.ReschedulePreview(h.csrfToken(c), reschedulePreviewVMs(pts), "", fullPage))
}

// recheckAttestations runs the freshness check over the targets that passed the
// archive recheck. Attested targets are excluded from the executable set; unknown
// disables the target rather than proving a replay is needed.
func (h *handlers) recheckAttestations(ctx context.Context, pts []previewTarget) {
	var indexes []int
	for i := range pts {
		if pts[i].state == recheckExecutable {
			indexes = append(indexes, i)
		}
	}
	if len(indexes) == 0 {
		return
	}
	ids := make([][]byte, len(indexes))
	for j, idx := range indexes {
		ids[j] = pts[idx].target.MessageID
	}
	results := checkAttestations(ctx, h.aggregatorAddress, ids)
	for j, idx := range indexes {
		switch results[j].State {
		case AttestationAttested:
			pts[idx].state = recheckSkip
			pts[idx].detail = "already attested — nothing to do (" + results[j].Detail + ")"
		case AttestationUnknown:
			pts[idx].state = recheckUnknown
			pts[idx].detail = "attestation state unknown: " + results[j].Detail
		default:
			pts[idx].detail = results[j].Detail
		}
	}
}

func reschedulePreviewVMs(pts []previewTarget) []views.RescheduleTargetVM {
	vms := make([]views.RescheduleTargetVM, 0, len(pts))
	for _, pt := range pts {
		vm := views.RescheduleTargetVM{
			Target:    pt.raw,
			OwnerID:   pt.target.OwnerID,
			Queue:     string(pt.target.Queue),
			JobID:     pt.target.JobID,
			MessageID: pt.target.MessageIDHex,
			Detail:    pt.detail,
		}
		if pt.job != nil {
			vm.FailureCategory = pt.job.FailureCategory
		}
		switch pt.state {
		case recheckExecutable:
			vm.Executable = true
			vm.Status = "ready"
		case recheckUnknown:
			vm.Status = "unknown"
		default:
			vm.Status = "excluded"
		}
		vms = append(vms, vm)
	}
	return vms
}

// executeOutcome is one target's mutation result for the results fragment.
type executeOutcome struct {
	target  rescheduleTarget
	raw     string
	outcome string // success | failed | skipped
	detail  string
}

func (h *handlers) rescheduleExecute(c *gin.Context) {
	fullPage := c.GetHeader("HX-Request") == ""
	retryDuration, err := parseRetryDuration(c.PostForm("retry_duration"))
	if err != nil {
		h.render(c, http.StatusBadRequest, views.RescheduleResults(h.csrfToken(c), nil, "", "", err.Error(), fullPage))
		return
	}
	raws := c.PostFormArray("target")
	if len(raws) == 0 {
		h.render(c, http.StatusBadRequest, views.RescheduleResults(h.csrfToken(c), nil, "", "", "No targets selected.", fullPage))
		return
	}

	// One target at a time: the gate, the intent row, the mutation, then the
	// outcome row — so the audit log reads as adjacent intent/outcome pairs.
	var auditErrs []string
	resultVMs := make([]views.RescheduleResultVM, 0, len(raws))
	for _, raw := range raws {
		t, perr := parseRescheduleTarget(raw)
		if perr != nil {
			detail := "invalid target: " + perr.Error()
			if err := h.recordAction(c, Action{Action: "reschedule", Target: raw, Outcome: "failed", Detail: detail}); err != nil {
				auditErrs = append(auditErrs, fmt.Sprintf("%s: %v", raw, err))
			}
			resultVMs = append(resultVMs, views.RescheduleResultVM{Target: raw, Outcome: "failed", Detail: detail})
			continue
		}
		o := h.executeTarget(c.Request.Context(), c, t, raw, retryDuration)
		logTarget := o.target.MessageIDHex
		if err := h.recordAction(c, Action{
			Action: "reschedule", Target: logTarget,
			Outcome: o.outcome, Detail: o.detail,
		}); err != nil {
			auditErrs = append(auditErrs, fmt.Sprintf("%s: %v", logTarget, err))
		}
		resultVMs = append(resultVMs, views.RescheduleResultVM{
			Target: o.raw, OwnerID: o.target.OwnerID,
			Queue: string(o.target.Queue), JobID: o.target.JobID, MessageID: o.target.MessageIDHex,
			Outcome: o.outcome, Detail: o.detail,
		})
	}
	h.render(c, http.StatusOK, views.RescheduleResults(h.csrfToken(c), resultVMs, retryDuration.String(), strings.Join(auditErrs, "; "), "", fullPage))
}

// executeTarget performs one owner-scoped reschedule per target. The safety gate
// (archive row plus attestation freshness) re-runs on every execution, and the
// intent is durably logged before the mutation itself.
func (h *handlers) executeTarget(ctx context.Context, c *gin.Context, t rescheduleTarget, raw string, retryDuration time.Duration) executeOutcome {
	out := executeOutcome{target: t, raw: raw}
	store := jobQueueStore(h.stores)
	state, detail, _ := recheckArchiveRow(ctx, store, t)
	if state == recheckExecutable {
		att := checkAttestations(ctx, h.aggregatorAddress, [][]byte{t.MessageID})[0]
		switch att.State {
		case AttestationAttested:
			state, detail = recheckSkip, "already attested — nothing to do ("+att.Detail+")"
		case AttestationUnknown:
			state, detail = recheckUnknown, "attestation state unknown: "+att.Detail
		}
	}
	switch state {
	case recheckSkip:
		out.outcome, out.detail = "skipped", detail
		return out
	case recheckUnknown:
		out.outcome, out.detail = "skipped", "not executed — "+detail
		return out
	}
	// Log the intent before mutating: a mutation that cannot be logged does not
	// proceed, and a later outcome-write failure still leaves the intent visible.
	if err := h.recordAction(c, Action{
		Action: "reschedule", Target: t.MessageIDHex,
		Outcome: "started",
		Detail:  fmt.Sprintf("restoring job %s (queue %s, owner %s)", t.JobID, t.Queue, t.OwnerID),
	}); err != nil {
		out.outcome, out.detail = "failed", "not executed — action log unavailable: "+err.Error()
		return out
	}
	if err := store.RescheduleByJobID(ctx, t.Queue, t.OwnerID, t.JobID, retryDuration); err != nil {
		out.outcome, out.detail = "failed", err.Error()
		return out
	}
	out.outcome = "success"
	out.detail = fmt.Sprintf("restored archive→active; attempts reset; new retry deadline %s from now", retryDuration)
	return out
}
