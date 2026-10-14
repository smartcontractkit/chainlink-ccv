package admin

import (
	"context"
	"encoding/hex"
	"net/http"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-ccv/cli/jobqueue"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/admin/views"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/recovery"
)

const recentFailedBrowseLimit = 50

// Search is the console entry point: find one or several message IDs in this
// verifier's failed-job archive. A failed lookup is never rendered as an empty result.
func (h *handlers) registerSearchRoutes(r *gin.Engine) {
	r.GET("/search", h.searchPage)
	r.POST("/search", h.searchResults)
}

func (h *handlers) searchPage(c *gin.Context) {
	if c.Query("browse") == "recent" {
		failed, err := h.listRecentFailed(c.Request.Context(), recentFailedBrowseLimit)
		vm := views.SearchResultsVM{Jobs: failed, IsRecentBrowse: true}
		if err != nil {
			vm.UnreachableDetail = "archive lookup failed: " + err.Error()
		}
		h.render(c, http.StatusOK, views.SearchPage(h.csrfToken(c), &vm, "", ""))
		return
	}
	h.render(c, http.StatusOK, views.SearchPage(h.csrfToken(c), nil, "", ""))
}

func (h *handlers) searchResults(c *gin.Context) {
	raw := c.PostForm("message_ids")
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		failed, err := h.listRecentFailed(c.Request.Context(), recentFailedBrowseLimit)
		vm := views.SearchResultsVM{Jobs: failed, IsRecentBrowse: true}
		if err != nil {
			vm.UnreachableDetail = "archive lookup failed: " + err.Error()
		}
		h.render(c, http.StatusOK, views.SearchPage(h.csrfToken(c), &vm, raw, ""))
		return
	}

	messageIDs, err := jobqueue.ParseMessageIDs(strings.Fields(raw))
	if err != nil {
		h.render(c, http.StatusBadRequest, views.SearchPage(h.csrfToken(c), nil, raw, "Invalid message ID format: "+err.Error()))
		return
	}

	failed, err := h.stores.JobQueue().ListFailedFiltered(c.Request.Context(), nil, "", messageIDs, 0)
	vm := views.SearchResultsVM{Jobs: failed}
	if err != nil {
		vm.UnreachableDetail = "archive lookup failed: " + err.Error()
	}

	foundIDs := make(map[string]bool)
	for _, j := range failed {
		foundIDs[strings.ToLower(formatMessageID(j.MessageID))] = true
	}

	var missingHex []string
	for _, id := range messageIDs {
		hexID := formatMessageID(id)
		if !foundIDs[strings.ToLower(hexID)] {
			missingHex = append(missingHex, hexID)
		}
	}

	if len(missingHex) > 0 {
		h.searchMissingEvents(c.Request.Context(), &vm, missingHex, foundIDs)
	}

	if vm.UnreachableDetail == "" {
		for _, id := range messageIDs {
			hexID := formatMessageID(id)
			if !foundIDs[strings.ToLower(hexID)] {
				vm.NotFoundIDs = append(vm.NotFoundIDs, hexID)
			}
		}
	}

	h.render(c, http.StatusOK, views.SearchPage(h.csrfToken(c), &vm, raw, ""))
}

func (h *handlers) searchMissingEvents(ctx context.Context, vm *views.SearchResultsVM, missingHex []string, foundIDs map[string]bool) {
	if h.stores.Recovery() == nil {
		return
	}
	var beforeID string
	for {
		page, err := h.stores.Recovery().ListEvents(ctx, recovery.EventFilter{
			MessageIDs: missingHex,
			BeforeID:   beforeID,
			Limit:      recovery.MaxPageSize,
		})
		if err != nil {
			appendUnreachable(vm, "recovery event lookup failed: "+err.Error())
			return
		}
		for _, e := range page.Events {
			vm.Events = append(vm.Events, toDropEventVM(e))
			if e.MessageID != nil {
				foundIDs[strings.ToLower(*e.MessageID)] = true
			}
		}
		if page.NextCursor == "" || page.NextCursor == beforeID || len(page.Events) == 0 {
			return
		}
		beforeID = page.NextCursor
	}
}

func appendUnreachable(vm *views.SearchResultsVM, detail string) {
	if vm.UnreachableDetail == "" {
		vm.UnreachableDetail = detail
		return
	}
	vm.UnreachableDetail += "; " + detail
}

// listRecentFailed merges the per-queue archive results in global CreatedAt/JobID order and caps at limit.
func (h *handlers) listRecentFailed(ctx context.Context, limit int) ([]jobqueue.ArchivedJob, error) {
	failed, err := h.stores.JobQueue().ListFailedFiltered(ctx, nil, "", nil, limit)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(failed, func(a, b jobqueue.ArchivedJob) int {
		if c := b.CreatedAt.Compare(a.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(b.JobID, a.JobID)
	})
	if limit > 0 && len(failed) > limit {
		failed = failed[:limit]
	}
	return failed, nil
}

func formatMessageID(id []byte) string { return "0x" + hex.EncodeToString(id) }
