package admin

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-ccv/cli/jobqueue"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/admin/views"
)

// Reschedule: preview the exact nodes/owners/jobs a reschedule affects, recheck
// attestation state before mutating (unknown ≠ needs replay), execute one owner-scoped
// operation per target, report per-target results, and retry only failed targets.

// rescheduleTarget is one parsed `target` form field, pipe-separated as emitted by the
// message detail page: nodeName|jobID|messageIDHex|queue|ownerID.
type rescheduleTarget struct {
	NodeName     string
	JobID        string
	MessageID    []byte
	MessageIDHex string
	Queue        jobqueue.QueueType
	OwnerID      string
}

func parseRescheduleTarget(raw string) (rescheduleTarget, error) {
	var t rescheduleTarget
	parts := strings.SplitN(raw, "|", 5)
	if len(parts) != 5 {
		return t, fmt.Errorf("expected nodeName|jobID|messageID|queue|ownerID, got %d fields", len(parts))
	}
	t.NodeName, t.JobID, t.OwnerID = parts[0], parts[1], parts[4]
	id, err := jobqueue.ParseMessageID(parts[2])
	if err != nil || len(id) != 32 {
		return t, fmt.Errorf("invalid message ID %q: expected a full 0x-prefixed 32-byte hex ID", parts[2])
	}
	t.MessageID = id
	t.MessageIDHex = formatMessageID(id)
	t.Queue = jobqueue.QueueType(parts[3])
	if t.Queue != jobqueue.QueueTypeTaskVerifier && t.Queue != jobqueue.QueueTypeStorageWriter {
		return t, fmt.Errorf("unknown queue %q", parts[3])
	}
	if t.NodeName == "" || t.JobID == "" || t.OwnerID == "" {
		return t, fmt.Errorf("node, job ID and owner must all be non-empty")
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

// nodeJobQueue resolves a node's job queue store. A var so tests can substitute fakes
// without a node database.
var nodeJobQueue = func(n *Node) (jobqueue.Store, error) { return n.JobQueue() }

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
		n := h.node(t.NodeName)
		if n == nil {
			pt.state, pt.detail = recheckSkip, "unknown node — not in the console configuration"
			pts = append(pts, pt)
			continue
		}
		store, err := nodeJobQueue(n)
		if err != nil {
			pt.state, pt.detail = recheckUnknown, "node unreachable: "+err.Error()
			pts = append(pts, pt)
			continue
		}
		pt.state, pt.detail, pt.job = recheckArchiveRow(c.Request.Context(), store, t)
		pts = append(pts, pt)
	}
	h.recheckAttestations(c.Request.Context(), pts)
	h.render(c, http.StatusOK, views.ReschedulePreview(h.csrfToken(c), reschedulePreviewVMs(pts), "", fullPage))
}

// recheckAttestations runs the freshness check, batched per node, over the targets
// that passed the archive recheck. Attested targets are excluded from the executable
// set; unknown disables the target rather than proving a replay is needed.
func (h *handlers) recheckAttestations(ctx context.Context, pts []previewTarget) {
	type nodeGroup struct {
		cfg     NodeConfig
		indexes []int
	}
	groups := make(map[string]*nodeGroup)
	var order []*nodeGroup
	for i := range pts {
		if pts[i].state != recheckExecutable {
			continue
		}
		g, ok := groups[pts[i].target.NodeName]
		if !ok {
			g = &nodeGroup{cfg: h.node(pts[i].target.NodeName).Config()}
			groups[pts[i].target.NodeName] = g
			order = append(order, g)
		}
		g.indexes = append(g.indexes, i)
	}
	var wg sync.WaitGroup
	for _, g := range order {
		wg.Add(1)
		go func(g *nodeGroup) {
			defer wg.Done()
			ids := make([][]byte, len(g.indexes))
			for j, idx := range g.indexes {
				ids[j] = pts[idx].target.MessageID
			}
			results := checkNodeAttestations(ctx, g.cfg, ids)
			for j, idx := range g.indexes {
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
		}(g)
	}
	wg.Wait()
}

func reschedulePreviewVMs(pts []previewTarget) []views.RescheduleTargetVM {
	vms := make([]views.RescheduleTargetVM, 0, len(pts))
	for _, pt := range pts {
		vm := views.RescheduleTargetVM{
			Target:    pt.raw,
			NodeName:  pt.target.NodeName,
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
	if !h.requireActions(c) {
		return
	}
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
	retryMode := c.PostForm("retry") == "failed"

	outcomes := make([]executeOutcome, 0, len(raws))
	for _, raw := range raws {
		t, perr := parseRescheduleTarget(raw)
		if perr != nil {
			outcomes = append(outcomes, executeOutcome{raw: raw, outcome: "failed", detail: "invalid target: " + perr.Error()})
			continue
		}
		outcomes = append(outcomes, h.executeTarget(c.Request.Context(), t, raw, retryDuration, retryMode))
	}

	var auditErrs []string
	resultVMs := make([]views.RescheduleResultVM, 0, len(outcomes))
	for _, o := range outcomes {
		logTarget := o.target.MessageIDHex
		if logTarget == "" {
			logTarget = o.raw
		}
		if err := h.recordAction(c, Action{
			Action: "reschedule", NodeName: o.target.NodeName, Target: logTarget,
			Outcome: o.outcome, Detail: o.detail,
		}); err != nil {
			auditErrs = append(auditErrs, fmt.Sprintf("%s: %v", logTarget, err))
		}
		resultVMs = append(resultVMs, views.RescheduleResultVM{
			Target: o.raw, NodeName: o.target.NodeName, OwnerID: o.target.OwnerID,
			Queue: string(o.target.Queue), JobID: o.target.JobID, MessageID: o.target.MessageIDHex,
			Outcome: o.outcome, Detail: o.detail,
		})
	}
	h.render(c, http.StatusOK, views.RescheduleResults(h.csrfToken(c), resultVMs, retryDuration.String(), strings.Join(auditErrs, "; "), "", fullPage))
}

// executeTarget performs one owner-scoped reschedule per target. In retry mode the
// rechecks re-run first: targets that no longer need a replay are skipped, never
// blindly re-executed.
func (h *handlers) executeTarget(ctx context.Context, t rescheduleTarget, raw string, retryDuration time.Duration, retryMode bool) executeOutcome {
	out := executeOutcome{target: t, raw: raw}
	n := h.node(t.NodeName)
	if n == nil {
		out.outcome, out.detail = "failed", "unknown node — not in the console configuration"
		return out
	}
	store, err := nodeJobQueue(n)
	if err != nil {
		out.outcome, out.detail = "failed", "node unreachable: "+err.Error()
		return out
	}
	if retryMode {
		state, detail, _ := recheckArchiveRow(ctx, store, t)
		if state == recheckExecutable {
			att := checkNodeAttestations(ctx, n.Config(), [][]byte{t.MessageID})[0]
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
	}
	if err := store.RescheduleByJobID(ctx, t.Queue, t.OwnerID, t.JobID, retryDuration); err != nil {
		out.outcome, out.detail = "failed", err.Error()
		return out
	}
	out.outcome = "success"
	out.detail = fmt.Sprintf("restored archive→active; attempts reset; new retry deadline %s from now", retryDuration)
	return out
}
