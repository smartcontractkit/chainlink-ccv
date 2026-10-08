package admin

import (
	"net/http"
	"strconv"

	"github.com/a-h/templ"
	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/admin/views"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// handlers holds the shared dependencies every route group uses. Route registration is
// split per feature (search.go, detail.go, reschedule.go, recoveryops.go);
// this file carries the struct, the helpers, and the core pages.
type handlers struct {
	cfg               *Config
	lggr              logger.Logger
	stores            stores
	actions           *ActionLog
	aggregatorAddress string
	dialer            ResultsDialer
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

// recordAction appends one session-audit entry with the request's actor.
func (h *handlers) recordAction(c *gin.Context, a Action) {
	a.Actor = h.actor(c)
	h.actions.Record(a)
}

func (h *handlers) registerCoreRoutes(r *gin.Engine) {
	r.GET("/healthz", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) })
	r.GET("/", func(c *gin.Context) { c.Redirect(http.StatusFound, "/search") })
	r.GET("/actions", h.actionsPage)
}

func (h *handlers) actionsPage(c *gin.Context) {
	before, _ := strconv.ParseInt(c.Query("before"), 10, 64)
	actions := h.actions.List(100, before)
	vms := make([]views.ActionVM, 0, len(actions))
	for _, a := range actions {
		vms = append(vms, views.ActionVM{
			ID: a.ID, Actor: a.Actor, Action: a.Action, Target: a.Target,
			OperationID: a.OperationID, Outcome: a.Outcome, Detail: a.Detail, CreatedAt: a.CreatedAt,
		})
	}
	// A full page means older rows may exist; the last row's ID is the next cursor.
	more := int64(0)
	if len(vms) == 100 {
		more = vms[len(vms)-1].ID
	}
	h.render(c, http.StatusOK, views.ActionsPage(vms, more))
}
