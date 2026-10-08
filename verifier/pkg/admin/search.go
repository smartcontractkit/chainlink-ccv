package admin

import (
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-ccv/cli/jobqueue"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/admin/views"
)

// Search is the console entry point: find one or several message IDs in this
// verifier's failed-job archive. A failed lookup is never rendered as an empty result.
func (h *handlers) registerSearchRoutes(r *gin.Engine) {
	r.GET("/search", h.searchPage)
	r.POST("/search", h.searchResults)
}

func (h *handlers) searchPage(c *gin.Context) {
	h.render(c, http.StatusOK, views.SearchPage(h.csrfToken(c), nil, nil, ""))
}

func (h *handlers) searchResults(c *gin.Context) {
	messageIDs, err := jobqueue.ParseMessageIDs(strings.Fields(c.PostForm("message_ids")))
	if err != nil {
		// A plain browser POST: render the full page with the error, not a fragment.
		h.render(c, http.StatusBadRequest, views.SearchPage(h.csrfToken(c), nil, nil, err.Error()))
		return
	}
	if len(messageIDs) == 0 {
		h.render(c, http.StatusOK, views.SearchPage(h.csrfToken(c), &views.SearchResultsVM{}, messageIDs, ""))
		return
	}

	failed, err := h.stores.JobQueue().ListFailedFiltered(c.Request.Context(), nil, "", messageIDs, 0)
	vm := views.SearchResultsVM{Jobs: failed}
	if err != nil {
		vm.UnreachableDetail = "archive lookup failed: " + err.Error()
	}
	h.render(c, http.StatusOK, views.SearchPage(h.csrfToken(c), &vm, messageIDs, ""))
}

func formatMessageID(id []byte) string { return "0x" + hex.EncodeToString(id) }
