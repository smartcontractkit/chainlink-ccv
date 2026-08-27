// Package policy is a fake of the operator-owned policy endpoint the committee verifier calls.
//
// It serves the v1 contract published in verifier/policy_hook_openapi_v1.yaml, plus a control
// surface tests drive to change what the endpoint does mid-run: switch the default verdict,
// reject one message by ID, or make the endpoint fail outright so the verifier's retry path can
// be exercised without stopping a container.
//
// The fake is written against the published spec rather than the verifier's Go types. An
// operator builds their endpoint from the spec, not from verifier code, and the fake does the
// same: it reads the two request fields it acts on and answers with the documented response
// shape. That also keeps the fakes module free of the verifier's dependency graph.
package policy

import (
	"maps"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/fake"
)

const (
	// EvaluatePath is the endpoint a verifier is pointed at with policy_hook.endpoint_url.
	EvaluatePath = "/policy/v1/evaluate"
	// ControlPath is the test-only control surface. It is not part of the published contract.
	ControlPath = "/policy/v1/control"
	// CallsPath reports what the endpoint has been asked, so a test can assert that the
	// verifier really retried rather than inferring it from a message never arriving.
	CallsPath = "/policy/v1/control/calls"

	// schemaVersion is the only contract version this fake serves. A request carrying any
	// other version is answered with 400, which the verifier reads as an endpoint error and
	// retries, so a contract drift shows up as a test whose message never attests rather than
	// as one that passes by accident.
	schemaVersion = "v1"
	decisionPass  = "PASS"
	decisionFail  = "FAIL"
)

// evaluateRequest is the subset of the v1 EvaluateRequest the fake acts on. Fields it does not
// list are accepted and ignored, as the spec allows the verifier to send the full message.
type evaluateRequest struct {
	SchemaVersion string `json:"schema_version" binding:"required"`
	MessageID     string `json:"message_id"     binding:"required"`
}

// evaluateResponse is the v1 EvaluateResponse.
type evaluateResponse struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
}

// ControlRequest sets the fake's behavior. DefaultDecision and Reason keep their current value
// when empty; Reject adds to the current set; ForceStatus is always applied, so omitting it
// clears a previously forced status.
type ControlRequest struct {
	// DefaultDecision is the verdict for any message with no per-message override: PASS or FAIL.
	DefaultDecision string `json:"default_decision"`
	// Reason is returned alongside a FAIL.
	Reason string `json:"reason"`
	// Reject lists message IDs to answer FAIL for regardless of DefaultDecision.
	Reject []string `json:"reject"`
	// ForceStatus makes every call return this HTTP status instead of a verdict, which is how
	// a test drives the "endpoint unavailable" path. Zero clears it.
	ForceStatus int `json:"force_status"`
	// Reset clears the per-message overrides, the forced status, and the call log before the
	// rest of this request is applied.
	Reset bool `json:"reset"`
}

// ControlResponse echoes the fake's state after a control request.
type ControlResponse struct {
	DefaultDecision string   `json:"default_decision"`
	Reason          string   `json:"reason"`
	Rejected        []string `json:"rejected"`
	ForceStatus     int      `json:"force_status"`
	Calls           int      `json:"calls"`
}

// CallsResponse reports the endpoint's call log.
type CallsResponse struct {
	// Total is how many evaluate calls the fake has served, including forced failures.
	Total int `json:"total"`
	// PerMessage counts calls per message ID. A count above one for a message means the
	// verifier retried it.
	PerMessage map[string]int `json:"per_message"`
}

// API is the fake policy endpoint.
type API struct {
	rejected        map[string]struct{}
	perMessage      map[string]int
	defaultDecision string
	reason          string
	forceStatus     int
	total           int
	mu              sync.RWMutex
}

// NewAPI returns a fake that passes every message, which is the behavior a devenv with the hook
// enabled needs by default so unrelated tests are unaffected.
func NewAPI() *API {
	return &API{
		defaultDecision: decisionPass,
		rejected:        make(map[string]struct{}),
		perMessage:      make(map[string]int),
	}
}

// Register wires the fake's routes into the shared fake data provider.
func (a *API) Register() error {
	if err := fake.Func("POST", EvaluatePath, a.handleEvaluate); err != nil {
		return err
	}
	if err := fake.Func("POST", ControlPath, a.handleControl); err != nil {
		return err
	}
	return fake.Func("GET", CallsPath, a.handleCalls)
}

func (a *API) handleEvaluate(ctx *gin.Context) {
	var req evaluateRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.SchemaVersion != schemaVersion {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "unsupported schema_version " + req.SchemaVersion + ", this endpoint serves " + schemaVersion,
		})
		return
	}

	a.mu.Lock()
	a.total++
	a.perMessage[req.MessageID]++
	forceStatus := a.forceStatus
	_, rejected := a.rejected[req.MessageID]
	decision := a.defaultDecision
	reason := a.reason
	a.mu.Unlock()

	if forceStatus != 0 {
		ctx.JSON(forceStatus, gin.H{"error": "policy endpoint forced into failure by test control"})
		return
	}
	if rejected {
		decision = decisionFail
	}

	resp := evaluateResponse{Decision: decision}
	if decision == decisionFail {
		resp.Reason = reason
		if resp.Reason == "" {
			resp.Reason = "rejected by devenv fake policy endpoint"
		}
	}
	ctx.JSON(http.StatusOK, resp)
}

func (a *API) handleControl(ctx *gin.Context) {
	var req ControlRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if req.Reset {
		a.rejected = make(map[string]struct{})
		a.perMessage = make(map[string]int)
		a.total = 0
		a.forceStatus = 0
		a.reason = ""
		a.defaultDecision = decisionPass
	}
	if req.DefaultDecision != "" {
		if req.DefaultDecision != decisionPass && req.DefaultDecision != decisionFail {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "default_decision must be PASS or FAIL"})
			return
		}
		a.defaultDecision = req.DefaultDecision
	}
	if req.Reason != "" {
		a.reason = req.Reason
	}
	for _, id := range req.Reject {
		a.rejected[id] = struct{}{}
	}
	a.forceStatus = req.ForceStatus

	ctx.JSON(http.StatusOK, a.stateLocked())
}

func (a *API) handleCalls(ctx *gin.Context) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	ctx.JSON(http.StatusOK, CallsResponse{Total: a.total, PerMessage: maps.Clone(a.perMessage)})
}

// stateLocked builds the control response. Callers hold a.mu.
func (a *API) stateLocked() ControlResponse {
	rejected := make([]string, 0, len(a.rejected))
	for id := range a.rejected {
		rejected = append(rejected, id)
	}
	return ControlResponse{
		DefaultDecision: a.defaultDecision,
		Reason:          a.reason,
		Rejected:        rejected,
		ForceStatus:     a.forceStatus,
		Calls:           a.total,
	}
}
