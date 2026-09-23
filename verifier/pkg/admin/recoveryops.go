package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	recoverycli "github.com/smartcontractkit/chainlink-ccv/cli/recovery"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/admin/views"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/chainstatus"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/recovery"
)

// Recovery (U2): live source-range replay and the investigated reader reset, with
// durable operations (progress/cancel/resume across reloads) and R4 evidence display.
// Ordinary replay must not enable a finality-blocked reader; that needs reset-reader.

// Test seams: swapped by recoveryops_test.go; production wiring goes to the node DB.
var recoveryStoreOf = func(n *Node) (recoverycli.Store, error) { return n.Recovery() }

type chainStatusLister interface {
	List(context.Context) ([]chainstatus.Row, error)
}

var chainStatusesOf = func(n *Node) (chainStatusLister, error) { return n.ChainStatuses() }

func (h *handlers) registerRecoveryRoutes(r *gin.Engine) {
	r.GET("/recovery", h.recoveryPage)
	r.GET("/recovery/evidence", h.recoveryEvidence)
	r.POST("/recovery/preview", h.recoveryPreview)
	r.POST("/recovery/submit", h.recoverySubmit)
	r.GET("/recovery/operations", h.recoveryOperations)
	r.POST("/recovery/operations/:id/cancel", h.recoveryCancel)
	r.POST("/recovery/operations/:id/resume", h.recoveryResume)
}

func (h *handlers) recoveryPage(c *gin.Context) {
	nodes := make([]views.RecoveryPageNodeVM, 0, len(h.nodes))
	for _, n := range h.nodes {
		nodes = append(nodes, views.RecoveryPageNodeVM{Name: n.Name()})
	}
	h.render(c, http.StatusOK, views.RecoveryPage(h.csrfToken(c), nodes))
}

// recoveryFormInput is the validated recovery form. A nil ToBlock means the reader's
// advertised head is captured at submission time by the node.
type recoveryFormInput struct {
	nodes     []string
	owner     string
	chain     string
	from      uint64
	to        *uint64
	mode      string
	note      string
	requestID string
}

// parseRecoveryForm validates the shared form; full=true also requires note/request ID
// for an actual submission. Block bounds mirror the store's own validation.
func parseRecoveryForm(c *gin.Context, full bool) (recoveryFormInput, error) {
	var in recoveryFormInput
	in.nodes = c.PostFormArray("nodes")
	if len(in.nodes) == 0 {
		return in, errors.New("select at least one node")
	}
	in.owner = strings.TrimSpace(c.PostForm("owner"))
	if in.owner == "" {
		return in, errors.New("verifier owner is required")
	}
	chain, err := strconv.ParseUint(strings.TrimSpace(c.PostForm("chain")), 10, 64)
	if err != nil {
		return in, fmt.Errorf("source chain must be an unsigned decimal chain selector: %w", err)
	}
	in.chain = strconv.FormatUint(chain, 10)
	from, err := strconv.ParseUint(strings.TrimSpace(c.PostForm("from_block")), 10, 64)
	if err != nil {
		return in, fmt.Errorf("from-block is required and must be an unsigned decimal block number: %w", err)
	}
	if from == math.MaxUint64 {
		return in, fmt.Errorf("from-block must be below %d", uint64(math.MaxUint64))
	}
	in.from = from
	if raw := strings.TrimSpace(c.PostForm("to_block")); raw != "" {
		to, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return in, fmt.Errorf("to-block must be an unsigned decimal block number: %w", err)
		}
		if to == math.MaxUint64 {
			return in, fmt.Errorf("to-block must be below %d", uint64(math.MaxUint64))
		}
		in.to = &to
	}
	if in.to != nil && in.from > *in.to {
		return in, fmt.Errorf("from-block (%d) must not be after to-block (%d)", in.from, *in.to)
	}
	in.mode = c.PostForm("mode")
	if in.mode != "replay" && in.mode != "reset-reader" {
		return in, fmt.Errorf("mode must be replay or reset-reader, got %q", in.mode)
	}
	if !full {
		return in, nil
	}
	in.note = strings.TrimSpace(c.PostForm("note"))
	if in.note == "" {
		return in, errors.New("a recovery note is required — record the reason and the investigated boundary evidence")
	}
	in.requestID = strings.TrimSpace(c.PostForm("request_id"))
	if in.requestID == "" {
		in.requestID = uuid.NewString()
	} else if parsed, err := uuid.Parse(in.requestID); err != nil {
		return in, fmt.Errorf("request ID must be a UUID: %w", err)
	} else {
		in.requestID = parsed.String()
	}
	return in, nil
}

// recoveryReaderInfo mirrors the per-reader JSON the store embeds in EventPage.Readers.
type recoveryReaderInfo struct {
	NodeID           string     `json:"node_id"`
	LatestBlock      *string    `json:"latest_block"`
	HeadObservedAt   *time.Time `json:"head_observed_at"`
	LastSeenAt       *time.Time `json:"last_seen_at"`
	HistoryStartedAt *time.Time `json:"history_started_at"`
	Disabled         bool       `json:"disabled"`
	ActiveResetID    *string    `json:"active_reset_id"`
	AuditFailures    string     `json:"audit_failures"`
}

// recoveryCapability is one node's capability for the selected owner/chain.
type recoveryCapability struct {
	registered         bool
	disabled           bool
	statusLookupFailed bool
	latestHead         *uint64
	headStale          bool
	reader             *recoveryReaderInfo
	finalizedHeight    *uint64
}

// recoveryCapabilityOf combines the recovery reader registry (head, reset state) with
// chain statuses (authoritative finality disablement, finalized height).
func (h *handlers) recoveryCapabilityOf(ctx context.Context, n *Node, store recoverycli.Store, owner, chain string) (recoveryCapability, error) {
	var cap recoveryCapability
	page, err := store.ListEvents(ctx, recovery.EventFilter{OwnerID: owner, SourceChain: chain, Limit: 1})
	if err != nil {
		return cap, fmt.Errorf("reader state query failed: %w", err)
	}
	var readers []recoveryReaderInfo
	if len(page.Readers) > 0 {
		if err := json.Unmarshal(page.Readers, &readers); err != nil {
			return cap, fmt.Errorf("reader metadata unreadable: %w", err)
		}
	}
	if len(readers) > 0 {
		cap.registered = true
		cap.reader = &readers[0]
		cap.disabled = readers[0].Disabled
		if readers[0].LatestBlock != nil {
			if v, perr := strconv.ParseUint(*readers[0].LatestBlock, 10, 64); perr == nil {
				cap.latestHead = &v
			}
		}
		cap.headStale = readers[0].HeadObservedAt == nil || time.Since(*readers[0].HeadObservedAt) > time.Minute
	}
	lister, err := chainStatusesOf(n)
	if err != nil {
		cap.statusLookupFailed = true
		return cap, nil
	}
	rows, err := lister.List(ctx)
	if err != nil {
		cap.statusLookupFailed = true
		return cap, nil
	}
	chainNum, _ := strconv.ParseUint(chain, 10, 64)
	for _, row := range rows {
		if row.VerifierID == owner && uint64(row.ChainSelector) == chainNum {
			cap.disabled = cap.disabled || row.Disabled
			if row.FinalizedBlockHeight != nil && row.FinalizedBlockHeight.IsUint64() {
				v := row.FinalizedBlockHeight.Uint64()
				cap.finalizedHeight = &v
			}
		}
	}
	return cap, nil
}

// recoveryModeAllowed enforces the replay/reset split: replay never runs against a
// finality-blocked reader, and reset-reader exists only for one.
func recoveryModeAllowed(mode string, cap recoveryCapability) (bool, string) {
	if !cap.registered {
		return false, "No reader is registered for this owner/chain on this node; the node would reject the submission."
	}
	switch mode {
	case "replay":
		if cap.disabled {
			return false, "The reader is disabled (finality-blocked): ordinary replay will not run. Investigate the finality incident and use reset-reader instead."
		}
		if cap.statusLookupFailed {
			return false, "Chain-status lookup failed, so finality disablement cannot be ruled out; replay is refused on the safe side. Retry, or investigate the node's database."
		}
		return true, ""
	case "reset-reader":
		if !cap.disabled {
			return false, "The reader is not finality-blocked; reset-reader is the investigated action for a disabled reader. Use replay for an ordinary range re-verification."
		}
		return true, ""
	}
	return false, "unknown mode"
}

func (h *handlers) recoveryPreview(c *gin.Context) {
	in, err := parseRecoveryForm(c, false)
	if err != nil {
		h.render(c, http.StatusBadRequest, views.RecoveryPreviewError(err.Error()))
		return
	}
	vm := views.RecoveryPreviewVM{Mode: in.mode, SubmitEnabled: true}
	for _, name := range in.nodes {
		nvm := h.recoveryPreviewNode(c.Request.Context(), name, in)
		if !nvm.Allowed {
			vm.SubmitEnabled = false
		}
		vm.Nodes = append(vm.Nodes, nvm)
	}
	h.render(c, http.StatusOK, views.RecoveryPreview(vm))
}

func (h *handlers) recoveryPreviewNode(ctx context.Context, name string, in recoveryFormInput) views.RecoveryPreviewNodeVM {
	vm := views.RecoveryPreviewNodeVM{NodeName: name, LatestHead: "unknown", FinalizedHeight: "unknown"}
	n := h.node(name)
	if n == nil {
		vm.Error = "unknown node; it is not in this console's configuration"
		return vm
	}
	store, err := recoveryStoreOf(n)
	if err != nil {
		vm.Error = "node database unavailable: " + err.Error()
		return vm
	}
	cap, err := h.recoveryCapabilityOf(ctx, n, store, in.owner, in.chain)
	if err != nil {
		vm.Error = err.Error()
		return vm
	}
	vm.Registered = cap.registered
	vm.ReaderDisabled = cap.disabled
	if cap.latestHead != nil {
		vm.LatestHead = strconv.FormatUint(*cap.latestHead, 10)
	}
	vm.HeadStale = cap.registered && cap.headStale
	if cap.finalizedHeight != nil {
		vm.FinalizedHeight = strconv.FormatUint(*cap.finalizedHeight, 10)
	}
	if cap.reader != nil && cap.reader.ActiveResetID != nil {
		vm.ActiveResetID = *cap.reader.ActiveResetID
	}
	vm.RangeText = recoveryRangeText(in)
	vm.Warnings = recoveryWarnings(in, cap)
	vm.Allowed, vm.BlockedReason = recoveryModeAllowed(in.mode, cap)
	return vm
}

func recoveryRangeText(in recoveryFormInput) string {
	if in.to == nil {
		return fmt.Sprintf("From block %d; to-block omitted: the reader's advertised head is captured at submission (it must be under a minute old) and never follows the chain afterwards.", in.from)
	}
	size := *in.to - in.from + 1
	chunks := (size + recovery.MaxChunkBlocks - 1) / recovery.MaxChunkBlocks
	return fmt.Sprintf("Blocks %d–%d: %d block(s), processed as %d chunk(s) of at most %d blocks / %d events.",
		in.from, *in.to, size, chunks, recovery.MaxChunkBlocks, recovery.MaxChunkMessages)
}

func recoveryWarnings(in recoveryFormInput, cap recoveryCapability) []string {
	var warnings []string
	if cap.finalizedHeight != nil && in.from < *cap.finalizedHeight {
		warnings = append(warnings, fmt.Sprintf(
			"From-block %d is below the current finalized height %d: this range may revisit already-attested traffic, and it covers every lane on this source chain, not one message.",
			in.from, *cap.finalizedHeight))
	}
	if in.to == nil && cap.registered && cap.headStale {
		warnings = append(warnings, "The reader's last advertised head is stale or missing, so an omitted to-block will be rejected; set an explicit to-block.")
	}
	if cap.reader != nil && cap.reader.ActiveResetID != nil {
		warnings = append(warnings, "An applied reset ("+*cap.reader.ActiveResetID+") owns normal polling until it completes; a new investigated reset marks it superseded.")
	}
	if cap.statusLookupFailed {
		warnings = append(warnings, "Chain-status lookup failed on this node; finalized height and the authoritative disabled flag are unavailable.")
	}
	if cap.reader != nil && cap.reader.AuditFailures != "" && cap.reader.AuditFailures != "0" {
		warnings = append(warnings, "This reader reports "+cap.reader.AuditFailures+" failed evidence writes; retained history below may have gaps.")
	}
	return warnings
}

func (h *handlers) recoverySubmit(c *gin.Context) {
	if !h.requireActions(c) {
		return
	}
	in, err := parseRecoveryForm(c, true)
	if err != nil {
		h.render(c, http.StatusBadRequest, views.RecoverySubmitError(err.Error()))
		return
	}
	results := make([]views.RecoverySubmitNodeVM, len(in.nodes))
	for i, name := range in.nodes {
		results[i] = h.recoverySubmitNode(c, name, in)
	}
	h.render(c, http.StatusOK, views.RecoverySubmitResult(results, in.requestID))
}

// recoverySubmitNode submits to exactly one node and always writes an action-log row;
// a refused or failed node never blocks the others and is never silently retried.
func (h *handlers) recoverySubmitNode(c *gin.Context, name string, in recoveryFormInput) views.RecoverySubmitNodeVM {
	res := views.RecoverySubmitNodeVM{NodeName: name}
	target := recoveryTarget(in)
	fail := func(detail string) {
		res.Error = detail
		if err := h.recordAction(c, Action{Action: "recovery-submit", NodeName: name, Target: target, Outcome: "failed", Detail: detail}); err != nil {
			res.Error += " (action log write failed: " + err.Error() + ")"
		}
	}
	n := h.node(name)
	if n == nil {
		fail("unknown node; it is not in this console's configuration")
		return res
	}
	store, err := recoveryStoreOf(n)
	if err != nil {
		fail("node database unavailable: " + err.Error())
		return res
	}
	cap, err := h.recoveryCapabilityOf(c.Request.Context(), n, store, in.owner, in.chain)
	if err != nil {
		fail(err.Error())
		return res
	}
	if allowed, reason := recoveryModeAllowed(in.mode, cap); !allowed {
		fail(reason)
		return res
	}
	op, err := store.Submit(c.Request.Context(), recovery.SubmitRequest{
		ID: in.requestID, OwnerID: in.owner, SourceChain: in.chain, Mode: in.mode,
		FromBlock: in.from, ToBlock: in.to, Actor: h.actor(c), Note: in.note,
	})
	if err != nil {
		fail("submission rejected by the node: " + err.Error())
		return res
	}
	res.OperationID = op.ID
	res.State = op.State
	res.ToBlock = strconv.FormatUint(op.ToBlock, 10)
	detail := fmt.Sprintf("mode=%s state=%s to_block=%d", op.Mode, op.State, op.ToBlock)
	if err := h.recordAction(c, Action{
		Action: "recovery-submit", NodeName: name, Target: target,
		OperationID: op.ID, Outcome: "success", Detail: detail,
	}); err != nil {
		res.Error = "operation " + op.ID + " was created but the action log write failed: " + err.Error()
	}
	return res
}

func recoveryTarget(in recoveryFormInput) string {
	to := "auto"
	if in.to != nil {
		to = strconv.FormatUint(*in.to, 10)
	}
	return fmt.Sprintf("owner=%s chain=%s blocks=%s-%s mode=%s", in.owner, in.chain, strconv.FormatUint(in.from, 10), to, in.mode)
}

func (h *handlers) recoveryOperations(c *gin.Context) {
	owner := strings.TrimSpace(c.Query("owner"))
	chain := strings.TrimSpace(c.Query("chain"))
	if chain != "" {
		if _, err := strconv.ParseUint(chain, 10, 64); err != nil {
			h.render(c, http.StatusBadRequest, views.RecoveryPreviewError("chain filter must be an unsigned decimal chain selector: "+err.Error()))
			return
		}
	}
	var vm views.RecoveryOperationsVM
	for _, n := range h.nodes {
		nvm := views.RecoveryOpsNodeVM{NodeName: n.Name()}
		store, err := recoveryStoreOf(n)
		if err != nil {
			nvm.Error = "node database unavailable: " + err.Error()
		} else if ops, err := store.List(c.Request.Context(), owner, chain, 25); err != nil {
			nvm.Error = err.Error()
		} else {
			for _, op := range ops {
				nvm.Ops = append(nvm.Ops, recoveryOperationVM(op))
				if op.State == "accepted" || op.State == "running" {
					vm.InFlight = true
				}
			}
		}
		vm.Nodes = append(vm.Nodes, nvm)
	}
	h.render(c, http.StatusOK, views.RecoveryOperations(vm, h.csrfToken(c)))
}

func recoveryOperationVM(o recovery.Operation) views.RecoveryOperationVM {
	vm := views.RecoveryOperationVM{
		ID: o.ID, Mode: o.Mode, State: o.State, Actor: o.Actor, Note: o.Note,
		RangeFrom: strconv.FormatUint(o.FromBlock, 10), RangeTo: strconv.FormatUint(o.ToBlock, 10),
		LastError: o.LastError, ResetApplied: o.ResetApplied, UpdatedAt: o.UpdatedAt,
		Counters: fmt.Sprintf("admitted %d · dropped %d · conflicts %d · filtered %d · errors %d",
			o.Admitted, o.Dropped, o.Conflicts, o.Filtered, o.Errors),
	}
	vm.Progress = recoveryProgress(o)
	vm.CanCancel = o.State == "accepted" || o.State == "running" || o.State == "blocked" || o.State == "failed"
	vm.CanResume = o.State == "cancelled" || o.State == "failed" || o.State == "blocked"
	return vm
}

// recoveryProgress renders NextBlock against the inclusive target range.
func recoveryProgress(o recovery.Operation) string {
	if o.State == "completed" {
		return "complete"
	}
	total := o.ToBlock - o.FromBlock + 1
	done := uint64(0)
	if o.NextBlock > o.FromBlock {
		done = min(o.NextBlock-o.FromBlock, total)
	}
	return fmt.Sprintf("next %d of %d–%d (%d%%)", o.NextBlock, o.FromBlock, o.ToBlock, done*100/total)
}

func (h *handlers) recoveryCancel(c *gin.Context) { h.recoveryChangeState(c, "cancel") }
func (h *handlers) recoveryResume(c *gin.Context) { h.recoveryChangeState(c, "resume") }

// recoveryChangeState applies cancel/resume via the durable store and re-renders the
// row; nothing about the operation is held in console memory.
func (h *handlers) recoveryChangeState(c *gin.Context, action string) {
	if !h.requireActions(c) {
		return
	}
	rowErr := func(status int, id, detail string) {
		h.render(c, status, views.RecoveryOperationRow("", views.RecoveryOperationVM{ID: id, RowError: detail}, h.csrfToken(c)))
	}
	id := c.Param("id")
	if _, err := uuid.Parse(id); err != nil {
		rowErr(http.StatusBadRequest, id, "operation ID must be a UUID.")
		return
	}
	nodeName := c.PostForm("node")
	n := h.node(nodeName)
	if n == nil {
		rowErr(http.StatusNotFound, id, "unknown node "+nodeName+"; cannot "+action+" this operation here.")
		return
	}
	store, err := recoveryStoreOf(n)
	if err != nil {
		rowErr(http.StatusServiceUnavailable, id, "node database unavailable: "+err.Error())
		return
	}
	op, err := store.ChangeState(c.Request.Context(), id, action)
	outcome, detail := "success", ""
	if err != nil {
		outcome, detail = "failed", err.Error()
	} else {
		detail = "state=" + op.State
	}
	target := op.OwnerID + "/" + op.SourceChain
	if err == nil && op.ID == "" || err != nil {
		target = id
	}
	if logErr := h.recordAction(c, Action{
		Action: "recovery-" + action, NodeName: nodeName, Target: target,
		OperationID: id, Outcome: outcome, Detail: detail,
	}); logErr != nil {
		detail += " (action log write failed: " + logErr.Error() + ")"
	}
	if err == nil {
		h.render(c, http.StatusOK, views.RecoveryOperationRow(nodeName, recoveryOperationVM(op), h.csrfToken(c)))
		return
	}
	current, getErr := store.Get(c.Request.Context(), id)
	if getErr != nil {
		rowErr(http.StatusConflict, id, action+" failed: "+detail)
		return
	}
	vm := recoveryOperationVM(current)
	vm.LastError = strings.TrimSpace(vm.LastError + " " + action + " failed: " + detail)
	h.render(c, http.StatusConflict, views.RecoveryOperationRow(nodeName, vm, h.csrfToken(c)))
}

func (h *handlers) recoveryEvidence(c *gin.Context) {
	filter, nodeNames, err := parseRecoveryEvidenceQuery(c)
	if err != nil {
		h.render(c, http.StatusBadRequest, views.RecoveryPreviewError(err.Error()))
		return
	}
	nodes := make([]views.RecoveryEvidenceNodeVM, 0, len(nodeNames))
	for _, name := range nodeNames {
		nodes = append(nodes, h.recoveryEvidenceNode(c.Request.Context(), name, filter))
	}
	h.render(c, http.StatusOK, views.RecoveryEvidence(nodes))
}

func parseRecoveryEvidenceQuery(c *gin.Context) (recovery.EventFilter, []string, error) {
	nodeNames := c.QueryArray("nodes")
	if len(nodeNames) == 0 {
		return recovery.EventFilter{}, nil, errors.New("select at least one node in the form above")
	}
	filter := recovery.EventFilter{
		OwnerID: strings.TrimSpace(c.Query("owner")), SourceChain: strings.TrimSpace(c.Query("chain")),
		FromBlock: strings.TrimSpace(c.Query("from_block")), ToBlock: strings.TrimSpace(c.Query("to_block")),
		BeforeID: strings.TrimSpace(c.Query("before_id")), Limit: 100,
	}
	for _, raw := range []string{filter.SourceChain, filter.FromBlock, filter.ToBlock, filter.BeforeID} {
		if raw != "" {
			if _, err := strconv.ParseUint(raw, 10, 64); err != nil {
				return filter, nil, fmt.Errorf("evidence filters (chain, blocks, cursor) must be unsigned decimal integers: %w", err)
			}
		}
	}
	if filter.FromBlock != "" && filter.ToBlock != "" {
		from, _ := strconv.ParseUint(filter.FromBlock, 10, 64)
		to, _ := strconv.ParseUint(filter.ToBlock, 10, 64)
		if from > to {
			return filter, nil, fmt.Errorf("from-block (%d) must not be after to-block (%d)", from, to)
		}
	}
	return filter, nodeNames, nil
}

func (h *handlers) recoveryEvidenceNode(ctx context.Context, name string, filter recovery.EventFilter) views.RecoveryEvidenceNodeVM {
	vm := views.RecoveryEvidenceNodeVM{NodeName: name}
	n := h.node(name)
	if n == nil {
		vm.Error = "unknown node; it is not in this console's configuration"
		return vm
	}
	store, err := recoveryStoreOf(n)
	if err != nil {
		vm.Error = "node database unavailable: " + err.Error()
		return vm
	}
	page, err := store.ListEvents(ctx, filter)
	if err != nil {
		vm.Error = err.Error()
		return vm
	}
	vm.Coverage = page.Coverage
	vm.RetainedSince = page.RetainedSince.UTC().Format(time.RFC3339)
	vm.NextCursor = page.NextCursor
	vm.Readers = recoveryReaderVMs(page.Readers)
	for _, e := range page.Events {
		vm.Events = append(vm.Events, recoveryEventVM(e))
	}
	return vm
}

func recoveryReaderVMs(raw json.RawMessage) []views.RecoveryReaderVM {
	var readers []recoveryReaderInfo
	if len(raw) == 0 || json.Unmarshal(raw, &readers) != nil {
		return nil
	}
	vms := make([]views.RecoveryReaderVM, 0, len(readers))
	for _, r := range readers {
		vms = append(vms, views.RecoveryReaderVM{
			NodeID: r.NodeID, Disabled: strconv.FormatBool(r.Disabled),
			LatestBlock:      recoveryDeref(r.LatestBlock),
			HeadObservedAt:   recoveryTimeVM(r.HeadObservedAt),
			LastSeenAt:       recoveryTimeVM(r.LastSeenAt),
			HistoryStartedAt: recoveryTimeVM(r.HistoryStartedAt),
			ActiveResetID:    recoveryDeref(r.ActiveResetID),
			AuditFailures:    r.AuditFailures,
		})
	}
	return vms
}

func recoveryEventVM(e recovery.Event) views.RecoveryEventVM {
	return views.RecoveryEventVM{
		Kind: e.Kind, Stage: e.Stage, Reason: e.Reason,
		SourceBlock: recoveryDeref(e.SourceBlock), MessageID: recoveryDeref(e.MessageID),
		TxHash: recoveryDeref(e.TxHash), BlockHash: recoveryDeref(e.BlockHash), IncidentID: recoveryDeref(e.IncidentID),
		Observations:  e.Observations,
		FirstObserved: e.FirstObservedAt.UTC().Format(time.RFC3339),
		LastObserved:  e.LastObservedAt.UTC().Format(time.RFC3339),
		Expires:       e.ExpiresAt.UTC().Format(time.RFC3339),
	}
}

func recoveryDeref(s *string) string {
	if s == nil || *s == "" {
		return "—"
	}
	return *s
}

func recoveryTimeVM(t *time.Time) string {
	if t == nil {
		return "—"
	}
	return t.UTC().Format(time.RFC3339)
}
