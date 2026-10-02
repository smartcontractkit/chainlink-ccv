package admin

import (
	"net/http"
	"strconv"
	"sync"

	"github.com/a-h/templ"
	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/admin/views"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// handlers holds the shared dependencies every route group uses. Route registration is
// split per feature (search.go, detail.go, reschedule.go, recoveryops.go, backfill.go);
// this file carries the struct, the helpers, and the core pages (nodes, action log).
type handlers struct {
	cfg     *Config
	lggr    logger.Logger
	nodes   []*Node
	actions *ActionLog
}

func (h *handlers) node(name string) *Node {
	for _, n := range h.nodes {
		if n.Name() == name {
			return n
		}
	}
	return nil
}

func (h *handlers) actor(c *gin.Context) string {
	if v, ok := c.Get("actor"); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return "local"
}

func (h *handlers) csrfToken(c *gin.Context) string {
	if v, ok := c.Get("csrfToken"); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func (h *handlers) render(c *gin.Context, status int, component templ.Component) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(status)
	if err := component.Render(c.Request.Context(), c.Writer); err != nil {
		h.lggr.Errorw("failed to render page", "error", err)
	}
}

// requireActions refuses mutations when the console has no database (read-only mode).
func (h *handlers) requireActions(c *gin.Context) bool {
	if h.actions == nil {
		h.render(c, http.StatusServiceUnavailable, views.ErrorPage(
			"Read-only mode",
			"The console database is not configured, so mutations are disabled. Set [db].url in the console secrets file.",
		))
		return false
	}
	return true
}

// recordAction writes one action-log entry. Logging failure fails the mutation: an
// unaudited privileged action must not proceed silently.
func (h *handlers) recordAction(c *gin.Context, a Action) error {
	if h.actions == nil {
		return nil
	}
	a.Actor = h.actor(c)
	return h.actions.Record(c.Request.Context(), a)
}

func (h *handlers) registerCoreRoutes(r *gin.Engine) {
	r.GET("/healthz", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) })
	r.GET("/", h.nodesPage)
	r.GET("/actions", h.actionsPage)
}

func (h *handlers) nodesPage(c *gin.Context) {
	type probeResult struct {
		state  NodeState
		detail string
	}
	results := make([]probeResult, len(h.nodes))
	var wg sync.WaitGroup
	for i, n := range h.nodes {
		wg.Go(func() {
			state, detail := n.State(c.Request.Context())
			results[i] = probeResult{state, detail}
		})
	}
	wg.Wait()
	rows := make([]views.NodeRow, 0, len(h.nodes))
	for i, n := range h.nodes {
		cfg := n.Config()
		rows = append(rows, views.NodeRow{
			Name: n.Name(), Ready: results[i].state == NodeStateReady, Detail: results[i].detail,
			HasAgg: cfg.AggregatorAddress != "", HasIdx: cfg.IndexerURL != "", HasBack: cfg.IndexerConfigPath != "",
		})
	}
	h.render(c, http.StatusOK, views.NodesPage(rows, h.cfg.ListenAddress, h.actions == nil))
}

func (h *handlers) actionsPage(c *gin.Context) {
	if h.actions == nil {
		h.render(c, http.StatusOK, views.ErrorPage("Action log", "The console database is not configured; no action history is kept."))
		return
	}
	before, _ := strconv.ParseInt(c.Query("before"), 10, 64)
	actions, err := h.actions.List(c.Request.Context(), 100, before)
	if err != nil {
		h.render(c, http.StatusInternalServerError, views.ErrorPage("Action log", err.Error()))
		return
	}
	vms := make([]views.ActionVM, 0, len(actions))
	for _, a := range actions {
		vms = append(vms, views.ActionVM{
			Actor: a.Actor, Action: a.Action, NodeName: a.NodeName, Target: a.Target,
			OperationID: a.OperationID, Outcome: a.Outcome, Detail: a.Detail, CreatedAt: a.CreatedAt,
		})
	}
	h.render(c, http.StatusOK, views.ActionsPage(vms))
}
