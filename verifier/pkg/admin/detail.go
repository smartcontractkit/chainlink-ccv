package admin

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-ccv/cli/jobqueue"
	recoverycli "github.com/smartcontractkit/chainlink-ccv/cli/recovery"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/admin/views"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/chainstatus"
	recoverystore "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/recovery"
)

// Detail: per-message page — failure stage/reason, queue, owner, archive age/expiry,
// attempts, trace/indexer links, and the durable drop/incident evidence (R4),
// distinguishing an absent archive row from observed pre-admission drops.
func (h *handlers) registerDetailRoutes(r *gin.Engine) {
	r.GET("/nodes/:node/messages/:messageID", h.detailPage)
}

// detailChainLister is the chain-status read surface the detail page needs; the
// postgres store satisfies it and tests fake it.
type detailChainLister interface {
	List(ctx context.Context) ([]chainstatus.Row, error)
}

// detailSources bundles the per-node stores. A nil store with its error set renders
// that section as unavailable — never as an empty result.
type detailSources struct {
	jq       jobqueue.Store
	jqErr    error
	rec      recoverycli.Store
	recErr   error
	chain    detailChainLister
	chainErr error
}

func (h *handlers) detailPage(c *gin.Context) {
	n := h.node(c.Param("node"))
	if n == nil {
		h.render(c, http.StatusNotFound, views.ErrorPage("Message detail", "No configured node named "+strconv.Quote(c.Param("node"))+"."))
		return
	}
	ids, err := jobqueue.ParseMessageIDs([]string{c.Param("messageID")})
	if err != nil {
		h.render(c, http.StatusBadRequest, views.ErrorPage("Message detail", err.Error()))
		return
	}
	var src detailSources
	src.jq, src.jqErr = n.JobQueue()
	src.rec, src.recErr = n.Recovery()
	if cs, err := n.ChainStatuses(); err != nil {
		src.chainErr = err
	} else {
		src.chain = cs
	}
	h.renderDetail(c, n, src, ids[0])
}

// renderDetail runs the lookups against the given stores and renders the page. It is
// split from detailPage so tests can drive it with fake stores and no database.
func (h *handlers) renderDetail(c *gin.Context, n *Node, src detailSources, msgID []byte) {
	vm := views.DetailVM{
		NodeName:   n.Name(),
		MessageID:  formatMessageID(msgID),
		TraceURL:   n.Config().TraceURL,
		IndexerURL: n.Config().IndexerURL,
	}
	if src.jq == nil {
		vm.UnreachableDetail = detailErrText(src.jqErr, "node database unavailable")
		h.render(c, http.StatusOK, views.DetailPage(h.csrfToken(c), vm))
		return
	}
	// verifier/pkg/jobqueue has no active-queue listing by message ID, so queued/processing
	// rows can't be shown; a conflicting active job fails the restore safely at reschedule time.
	ctx := c.Request.Context()
	if jobs, err := src.jq.ListFailedFiltered(ctx, nil, "", [][]byte{msgID}, 0); err != nil {
		vm.ArchiveDetail = err.Error()
	} else {
		for _, j := range jobs {
			vm.Failed = append(vm.Failed, toArchivedJobVM(n.Name(), j))
		}
	}
	h.addDetailEvents(ctx, &vm, src)
	h.addDetailChainStatus(ctx, &vm, src)
	h.render(c, http.StatusOK, views.DetailPage(h.csrfToken(c), vm))
}

func (h *handlers) addDetailEvents(ctx context.Context, vm *views.DetailVM, src detailSources) {
	if src.rec == nil {
		vm.EventsDetail = detailErrText(src.recErr, "recovery store unavailable")
		return
	}
	page, err := src.rec.ListEvents(ctx, recoverystore.EventFilter{MessageIDs: []string{vm.MessageID}, Limit: 100})
	if err != nil {
		vm.EventsDetail = err.Error()
		return
	}
	for _, e := range page.Events {
		vm.Events = append(vm.Events, toDropEventVM(e))
	}
	vm.RetainedSince = page.RetainedSince
	vm.Coverage = page.Coverage
}

// addDetailChainStatus derives the message's source chain from its archive rows or
// events, then shows this node's chain-status rows for that chain.
func (h *handlers) addDetailChainStatus(ctx context.Context, vm *views.DetailVM, src detailSources) {
	switch {
	case len(vm.Failed) > 0:
		vm.SourceChain = strconv.FormatUint(vm.Failed[0].Job.ChainSelector, 10)
	case len(vm.Events) > 0:
		vm.SourceChain = vm.Events[0].SourceChain
	}
	if vm.SourceChain == "" {
		return
	}
	if src.chain == nil {
		vm.ChainDetail = detailErrText(src.chainErr, "chain status store unavailable")
		return
	}
	rows, err := src.chain.List(ctx)
	if err != nil {
		vm.ChainDetail = err.Error()
		return
	}
	for _, r := range rows {
		if strconv.FormatUint(uint64(r.ChainSelector), 10) == vm.SourceChain {
			vm.Chains = append(vm.Chains, toChainStatusVM(r))
		}
	}
}

// toArchivedJobVM maps one archive row and builds the reschedule-preview target
// contract: nodeName|jobID|messageIDHex|queue|ownerID.
func toArchivedJobVM(nodeName string, j jobqueue.ArchivedJob) views.ArchivedJobVM {
	label := "Ask the policy endpoint again (re-verify)"
	if j.Queue == jobqueue.QueueTypeStorageWriter {
		label = "Retry delivering the saved result"
	}
	return views.ArchivedJobVM{
		Job:         j,
		ButtonLabel: label,
		RescheduleTarget: strings.Join(
			[]string{nodeName, j.JobID, formatMessageID(j.MessageID), string(j.Queue), j.OwnerID}, "|"),
	}
}

func toDropEventVM(e recoverystore.Event) views.DropEventVM {
	return views.DropEventVM{
		Kind: e.Kind, Stage: e.Stage, Reason: e.Reason, OwnerID: e.OwnerID,
		SourceChain: e.SourceChain, SourceBlock: detailDeref(e.SourceBlock),
		TxHash: detailDeref(e.TxHash), IncidentID: detailDeref(e.IncidentID),
		Observations:  e.Observations,
		FirstObserved: e.FirstObservedAt, LastObserved: e.LastObservedAt, ExpiresAt: e.ExpiresAt,
	}
}

func toChainStatusVM(r chainstatus.Row) views.ChainStatusVM {
	height := "—"
	if r.FinalizedBlockHeight != nil {
		height = r.FinalizedBlockHeight.String()
	}
	return views.ChainStatusVM{
		ChainSelector:   strconv.FormatUint(uint64(r.ChainSelector), 10),
		VerifierID:      r.VerifierID,
		FinalizedHeight: height,
		Disabled:        r.Disabled,
		UpdatedAt:       r.UpdatedAt,
	}
}

func detailErrText(err error, fallback string) string {
	if err != nil {
		return err.Error()
	}
	return fallback
}

func detailDeref(s *string) string {
	if s == nil {
		return "—"
	}
	return *s
}
