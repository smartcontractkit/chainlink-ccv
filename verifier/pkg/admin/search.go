package admin

import (
	"context"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-ccv/cli/jobqueue"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/admin/views"
)

// Search is the console entry point: find one or several message IDs across all
// configured nodes. Each node's status renders separately; an unreachable node or a
// failed lookup is never rendered as an empty result.

type searchNodeResult struct {
	Node   NodeConfig
	State  NodeState // unreachable when set; detail in Err
	Err    string
	Failed []jobqueue.ArchivedJob
}

func (h *handlers) registerSearchRoutes(r *gin.Engine) {
	r.GET("/search", h.searchPage)
	r.POST("/search", h.searchResults)
}

func (h *handlers) searchPage(c *gin.Context) {
	h.render(c, http.StatusOK, views.SearchPage(h.csrfToken(c), nil, nil))
}

func (h *handlers) searchResults(c *gin.Context) {
	messageIDs, err := jobqueue.ParseMessageIDs(strings.Fields(c.PostForm("message_ids")))
	if err != nil {
		h.render(c, http.StatusBadRequest, views.SearchResults(nil, err.Error()))
		return
	}
	if len(messageIDs) == 0 {
		h.render(c, http.StatusOK, views.SearchResults(nil, ""))
		return
	}

	results := make([]searchNodeResult, len(h.nodes))
	var wg sync.WaitGroup
	for i, n := range h.nodes {
		wg.Go(func() {
			results[i] = h.searchNode(c.Request.Context(), n, messageIDs)
		})
	}
	wg.Wait()
	vms := make([]views.SearchNodeVM, 0, len(results))
	for _, r := range results {
		vm := views.SearchNodeVM{NodeName: r.Node.Name, Jobs: r.Failed}
		if r.State == NodeStateUnreachable {
			vm.UnreachableDetail = r.Err
		}
		vms = append(vms, vm)
	}
	h.render(c, http.StatusOK, views.SearchPage(h.csrfToken(c), vms, messageIDs))
}

// searchNode queries one node's archive tables. A store error marks the node
// unreachable-with-detail rather than empty.
func (h *handlers) searchNode(ctx context.Context, n *Node, messageIDs [][]byte) searchNodeResult {
	res := searchNodeResult{Node: n.Config(), State: NodeStateReady}
	store, err := n.JobQueue()
	if err != nil {
		res.State = NodeStateUnreachable
		res.Err = err.Error()
		return res
	}
	failed, err := store.ListFailedFiltered(ctx, nil, "", messageIDs, 0)
	if err != nil {
		res.State = NodeStateUnreachable
		res.Err = "archive lookup failed: " + err.Error()
		return res
	}
	res.Failed = failed
	return res
}

func formatMessageID(id []byte) string { return "0x" + hex.EncodeToString(id) }
