package admin

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"

	recoverycli "github.com/smartcontractkit/chainlink-ccv/cli/recovery"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/chainstatus"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/recovery"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// recoveryStoreStub implements recoverycli.Store with per-method hooks.
type recoveryStoreStub struct {
	submitFn      func(context.Context, recovery.SubmitRequest) (recovery.Operation, error)
	getFn         func(context.Context, string) (recovery.Operation, error)
	listFn        func(context.Context, string, string, int) ([]recovery.Operation, error)
	changeStateFn func(context.Context, string, string) (recovery.Operation, error)
	listEventsFn  func(context.Context, recovery.EventFilter) (recovery.EventPage, error)
}

func (f *recoveryStoreStub) Submit(ctx context.Context, r recovery.SubmitRequest) (recovery.Operation, error) {
	if f.submitFn == nil {
		return recovery.Operation{}, errors.New("unexpected Submit call")
	}
	return f.submitFn(ctx, r)
}

func (f *recoveryStoreStub) Get(ctx context.Context, id string) (recovery.Operation, error) {
	if f.getFn == nil {
		return recovery.Operation{}, errors.New("unexpected Get call")
	}
	return f.getFn(ctx, id)
}

func (f *recoveryStoreStub) List(ctx context.Context, owner, chain string, limit int) ([]recovery.Operation, error) {
	if f.listFn == nil {
		return nil, errors.New("unexpected List call")
	}
	return f.listFn(ctx, owner, chain, limit)
}

func (f *recoveryStoreStub) ChangeState(ctx context.Context, id, action string) (recovery.Operation, error) {
	if f.changeStateFn == nil {
		return recovery.Operation{}, errors.New("unexpected ChangeState call")
	}
	return f.changeStateFn(ctx, id, action)
}

func (f *recoveryStoreStub) ListEvents(ctx context.Context, filter recovery.EventFilter) (recovery.EventPage, error) {
	if f.listEventsFn == nil {
		return recovery.EventPage{}, errors.New("unexpected ListEvents call")
	}
	return f.listEventsFn(ctx, filter)
}

type recoveryChainStatusesStub struct {
	rows []chainstatus.Row
	err  error
}

func (f recoveryChainStatusesStub) List(context.Context) ([]chainstatus.Row, error) {
	return f.rows, f.err
}

// captureSQLConnector is a minimal in-memory driver.Conn source so ActionLog writes
// can be asserted without a database.
type captureSQLConnector struct {
	mu      sync.Mutex
	execs   [][]driver.NamedValue
	execErr error
}

func (c *captureSQLConnector) Connect(context.Context) (driver.Conn, error) {
	return captureSQLConn{c}, nil
}
func (c *captureSQLConnector) Driver() driver.Driver { return captureSQLDriver{} }

type captureSQLDriver struct{}

func (captureSQLDriver) Open(string) (driver.Conn, error) { return nil, errors.New("use Connector") }

type captureSQLConn struct{ c *captureSQLConnector }

func (captureSQLConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("no prepare") }
func (captureSQLConn) Close() error                        { return nil }
func (captureSQLConn) Begin() (driver.Tx, error)           { return nil, errors.New("no tx") }

func (c captureSQLConn) ExecContext(_ context.Context, _ string, args []driver.NamedValue) (driver.Result, error) {
	c.c.mu.Lock()
	defer c.c.mu.Unlock()
	if c.c.execErr != nil {
		return nil, c.c.execErr
	}
	c.c.execs = append(c.c.execs, append([]driver.NamedValue(nil), args...))
	return driver.RowsAffected(1), nil
}

func (c *captureSQLConnector) execValues(t *testing.T, i int) []any {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	require.Less(t, i, len(c.execs), "expected at least %d recorded execs", i+1)
	vals := make([]any, 0, len(c.execs[i]))
	for _, a := range c.execs[i] {
		vals = append(vals, a.Value)
	}
	return vals
}

func newCaptureActionLog(t *testing.T) (*ActionLog, *captureSQLConnector) {
	t.Helper()
	conn := &captureSQLConnector{}
	db := sql.OpenDB(conn)
	t.Cleanup(func() { _ = db.Close() })
	return NewActionLog(sqlx.NewDb(db, "postgres")), conn
}

// readerPageJSON mirrors the ccv_recovery_readers jsonb the store embeds in EventPage.
func readerPageJSON(disabled bool) json.RawMessage {
	now := time.Now().UTC().Format(time.RFC3339)
	return json.RawMessage(fmt.Sprintf(`[{"owner_id":"owner-1","source_chain_selector":"1","node_id":"host-a",`+
		`"latest_block":"2000","head_observed_at":%q,"last_seen_at":%q,"history_started_at":%q,`+
		`"disabled":%t,"active_reset_id":null,"audit_failures":"0","last_audit_failure_at":null}]`, now, now, now, disabled))
}

func enabledChainStatuses() recoveryChainStatusesStub {
	return recoveryChainStatusesStub{rows: []chainstatus.Row{{
		ChainSelector: protocol.ChainSelector(1), VerifierID: "owner-1",
		FinalizedBlockHeight: big.NewInt(1500), Disabled: false, UpdatedAt: time.Now(),
	}}}
}

func newRecoveryTestRouter(t *testing.T, store recoverycli.Store, statuses chainStatusLister, actions *ActionLog) *gin.Engine {
	t.Helper()
	oldStore, oldStatuses := recoveryStoreOf, chainStatusesOf
	recoveryStoreOf = func(*Node) (recoverycli.Store, error) { return store, nil }
	chainStatusesOf = func(*Node) (chainStatusLister, error) { return statuses, nil }
	t.Cleanup(func() { recoveryStoreOf, chainStatusesOf = oldStore, oldStatuses })

	gin.SetMode(gin.TestMode)
	n := NewNode(NodeConfig{Name: "node-a", SecretsPath: "/nonexistent/secrets.toml"}, logger.Test(t))
	h := &handlers{cfg: &Config{}, lggr: logger.Test(t), nodes: []*Node{n}, actions: actions}
	r := gin.New()
	h.registerRecoveryRoutes(r)
	return r
}

func postForm(r *gin.Engine, path string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func recoverySubmitForm(mode string) url.Values {
	return url.Values{
		"nodes":      {"node-a"},
		"owner":      {"owner-1"},
		"chain":      {"1"},
		"from_block": {"100"},
		"to_block":   {"200"},
		"mode":       {mode},
		"note":       {"canonical headers checked through 99; incident INC-7"},
	}
}

func TestRecoveryReplayBlockedWhenReaderDisabled(t *testing.T) {
	actions, captured := newCaptureActionLog(t)
	submitCalls := 0
	store := &recoveryStoreStub{
		listEventsFn: func(context.Context, recovery.EventFilter) (recovery.EventPage, error) {
			return recovery.EventPage{Readers: readerPageJSON(true), RetainedSince: time.Now()}, nil
		},
		submitFn: func(context.Context, recovery.SubmitRequest) (recovery.Operation, error) {
			submitCalls++
			return recovery.Operation{ID: "11111111-1111-1111-1111-111111111111", State: "accepted", Mode: "reset-reader", ToBlock: 200}, nil
		},
	}
	r := newRecoveryTestRouter(t, store, enabledChainStatuses(), actions)

	rec := postForm(r, "/recovery/submit", recoverySubmitForm("replay"))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "reset-reader")
	require.Contains(t, rec.Body.String(), "finality-blocked")
	require.Zero(t, submitCalls, "replay must be refused before touching the store")

	// The refusal is audited as a failed recovery-submit.
	vals := captured.execValues(t, 0)
	require.Equal(t, "recovery-submit", vals[1])
	require.Equal(t, "failed", vals[5])

	// reset-reader is the allowed investigated action for the same disabled reader.
	rec = postForm(r, "/recovery/submit", recoverySubmitForm("reset-reader"))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "11111111-1111-1111-1111-111111111111")
	require.Equal(t, 1, submitCalls)
}

func TestRecoverySubmitRecordsActionLogWithOperationID(t *testing.T) {
	actions, captured := newCaptureActionLog(t)
	opID := "22222222-2222-2222-2222-222222222222"
	var gotReq recovery.SubmitRequest
	store := &recoveryStoreStub{
		listEventsFn: func(context.Context, recovery.EventFilter) (recovery.EventPage, error) {
			return recovery.EventPage{Readers: readerPageJSON(false), RetainedSince: time.Now()}, nil
		},
		submitFn: func(_ context.Context, req recovery.SubmitRequest) (recovery.Operation, error) {
			gotReq = req
			return recovery.Operation{ID: opID, OwnerID: req.OwnerID, SourceChain: req.SourceChain, State: "accepted", Mode: req.Mode, ToBlock: 200}, nil
		},
	}
	r := newRecoveryTestRouter(t, store, enabledChainStatuses(), actions)

	rec := postForm(r, "/recovery/submit", recoverySubmitForm("replay"))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), opID)

	require.Equal(t, "owner-1", gotReq.OwnerID)
	require.Equal(t, "1", gotReq.SourceChain)
	require.Equal(t, uint64(100), gotReq.FromBlock)
	require.NotNil(t, gotReq.ToBlock)
	require.Equal(t, uint64(200), *gotReq.ToBlock)
	require.Equal(t, "local", gotReq.Actor)
	require.NotEmpty(t, gotReq.Note)
	require.NotEmpty(t, gotReq.ID, "fresh request ID generated when none resubmitted")

	vals := captured.execValues(t, 0)
	require.Equal(t, "local", vals[0])
	require.Equal(t, "recovery-submit", vals[1])
	require.Equal(t, "node-a", vals[2])
	require.Equal(t, opID, vals[4])
	require.Equal(t, "success", vals[5])
}

func TestRecoveryCancelResumeMapToChangeStateAndLog(t *testing.T) {
	actions, captured := newCaptureActionLog(t)
	opID := "33333333-3333-3333-3333-333333333333"
	var gotID, gotAction string
	store := &recoveryStoreStub{
		changeStateFn: func(_ context.Context, id, action string) (recovery.Operation, error) {
			gotID, gotAction = id, action
			state := "cancelled"
			if action == "resume" {
				state = "accepted"
			}
			return recovery.Operation{ID: id, OwnerID: "owner-1", SourceChain: "1", FromBlock: 100, ToBlock: 200, State: state}, nil
		},
	}
	r := newRecoveryTestRouter(t, store, enabledChainStatuses(), actions)

	rec := postForm(r, "/recovery/operations/"+opID+"/cancel", url.Values{"node": {"node-a"}})
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "cancelled")
	require.Equal(t, opID, gotID)
	require.Equal(t, "cancel", gotAction)
	vals := captured.execValues(t, 0)
	require.Equal(t, "recovery-cancel", vals[1])
	require.Equal(t, opID, vals[4])
	require.Equal(t, "success", vals[5])

	rec = postForm(r, "/recovery/operations/"+opID+"/resume", url.Values{"node": {"node-a"}})
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "accepted")
	require.Equal(t, "resume", gotAction)
	vals = captured.execValues(t, 1)
	require.Equal(t, "recovery-resume", vals[1])
	require.Equal(t, opID, vals[4])
}

func TestRecoveryOperationsReadsOnlyStoreState(t *testing.T) {
	opID := "44444444-4444-4444-4444-444444444444"
	store := &recoveryStoreStub{
		listFn: func(_ context.Context, owner, chain string, limit int) ([]recovery.Operation, error) {
			return []recovery.Operation{{
				ID: opID, OwnerID: "owner-1", SourceChain: "1", FromBlock: 100, ToBlock: 200, NextBlock: 150,
				Mode: "replay", State: "running", Admitted: 7, UpdatedAt: time.Now(),
			}}, nil
		},
	}

	// Two independent handler instances (a "reload") render identically: operation
	// state comes only from the store, never from console memory.
	for i := range 2 {
		r := newRecoveryTestRouter(t, store, enabledChainStatuses(), nil)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/recovery/operations", nil)
		r.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code, "iteration %d", i)
		body := rec.Body.String()
		require.Contains(t, body, opID, "iteration %d", i)
		require.Contains(t, body, "running", "iteration %d", i)
		require.Contains(t, body, "next 150 of 100–200", "iteration %d", i)
	}
}

func TestRecoverySubmitRejectsFromAfterTo(t *testing.T) {
	actions, _ := newCaptureActionLog(t)
	store := &recoveryStoreStub{
		submitFn: func(context.Context, recovery.SubmitRequest) (recovery.Operation, error) {
			t.Fatal("Submit must not be called for an inverted range")
			return recovery.Operation{}, nil
		},
	}
	r := newRecoveryTestRouter(t, store, enabledChainStatuses(), actions)

	form := recoverySubmitForm("replay")
	form.Set("from_block", "300")
	rec := postForm(r, "/recovery/submit", form)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "must not be after")

	form = recoverySubmitForm("replay")
	form.Set("note", "")
	rec = postForm(r, "/recovery/submit", form)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "note is required")
}

func TestRecoveryEvidenceRendersCoverageGapText(t *testing.T) {
	store := &recoveryStoreStub{
		listEventsFn: func(_ context.Context, f recovery.EventFilter) (recovery.EventPage, error) {
			require.Equal(t, "owner-1", f.OwnerID)
			require.Equal(t, "1", f.SourceChain)
			return recovery.EventPage{
				Events:        nil,
				RetainedSince: time.Now().Add(-recovery.HistoryRetention),
				Coverage:      "Observed events only. Empty results do not prove no affected traffic.",
				Readers:       readerPageJSON(false),
			}, nil
		},
	}
	r := newRecoveryTestRouter(t, store, enabledChainStatuses(), nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/recovery/evidence?nodes=node-a&owner=owner-1&chain=1", nil)
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	require.Contains(t, body, "Observed events only")
	require.Contains(t, body, "You may still scope and submit a manual range")
	require.Contains(t, body, "Absence of evidence never proves")

	// The page itself carries the "evidence is not the earliest affected block" guidance.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/recovery", nil)
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "not automatically the earliest affected block")
}

func TestRecoveryPreviewCapabilityView(t *testing.T) {
	store := &recoveryStoreStub{
		listEventsFn: func(context.Context, recovery.EventFilter) (recovery.EventPage, error) {
			return recovery.EventPage{Readers: readerPageJSON(true), RetainedSince: time.Now()}, nil
		},
	}
	r := newRecoveryTestRouter(t, store, enabledChainStatuses(), nil)

	form := recoverySubmitForm("replay")
	form.Set("to_block", "249") // 150 blocks → 2 chunks of ≤100
	rec := postForm(r, "/recovery/preview", form)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	require.Contains(t, body, "150 block(s), processed as 2 chunk(s)")
	require.Contains(t, body, "may revisit already-attested traffic") // from 100 < finalized 1500
	require.Contains(t, body, "disabled (finality-blocked)")
	require.Contains(t, body, "Submit unavailable")
	require.NotContains(t, body, `hx-post="/recovery/submit"`, "no enabled submit path when blocked")
}
