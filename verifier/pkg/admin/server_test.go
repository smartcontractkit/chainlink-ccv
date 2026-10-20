package admin

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// fakeSQLDriver backs a *sqlx.DB without a database: ExecContext calls are
// captured, anything else errors, so server-construction tests need no real DB.
type fakeSQLDriver struct {
	mu    sync.Mutex
	execs [][]driver.NamedValue
	err   error
}

func (d *fakeSQLDriver) Open(string) (driver.Conn, error)             { return &fakeSQLConn{d}, nil }
func (d *fakeSQLDriver) Connect(context.Context) (driver.Conn, error) { return &fakeSQLConn{d}, nil }
func (d *fakeSQLDriver) Driver() driver.Driver                        { return d }

type fakeSQLConn struct{ d *fakeSQLDriver }

func (c *fakeSQLConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("no statements") }
func (c *fakeSQLConn) Close() error                        { return nil }
func (c *fakeSQLConn) Begin() (driver.Tx, error)           { return nil, errors.New("no transactions") }

func (c *fakeSQLConn) ExecContext(_ context.Context, _ string, args []driver.NamedValue) (driver.Result, error) {
	c.d.mu.Lock()
	defer c.d.mu.Unlock()
	if c.d.err != nil {
		return nil, c.d.err
	}
	c.d.execs = append(c.d.execs, args)
	return driver.RowsAffected(1), nil
}

var fakeDriverSeq atomic.Int64

// newFakeSQLDB returns a *sqlx.DB that needs no database (Deps.DB is still
// required: the console's stores live in the verifier's application DB).
func newFakeSQLDB(t *testing.T) *sqlx.DB {
	t.Helper()
	drv := &fakeSQLDriver{}
	name := fmt.Sprintf("ccv-admin-fake-%d", fakeDriverSeq.Add(1))
	sql.Register(name, drv)
	db := sqlx.NewDb(sql.OpenDB(drv), "postgres")
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func newTestServer(t *testing.T, cfgBody string, auth *BasicAuth) *Server {
	t.Helper()
	cfg, err := LoadConfig(writeConfig(t, cfgBody))
	require.NoError(t, err)
	srv, err := NewServer(cfg, Deps{DB: newFakeSQLDB(t), Auth: auth}, logger.Test(t))
	require.NoError(t, err)
	return srv
}

func TestServerHealthz(t *testing.T) {
	srv := newTestServer(t, "", nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://localhost:8105/healthz", nil)
	srv.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestServerRootRedirectsToSearch(t *testing.T) {
	srv := newTestServer(t, "", nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://localhost:8105/", nil)
	srv.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusFound, rec.Code)
	require.Equal(t, "/search", rec.Header().Get("Location"))
}

func TestServerRequiresDatabase(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, ""))
	require.NoError(t, err)
	_, err = NewServer(cfg, Deps{}, logger.Test(t))
	require.ErrorContains(t, err, "database")
}

func TestServerCSRFFlow(t *testing.T) {
	srv := newTestServer(t, "", nil)

	// Unsafe method without a token: forbidden.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://localhost:8105/search", strings.NewReader("message_ids=0x00"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	srv.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusForbidden, rec.Code)

	// A GET sets the cookie; echoing it as the form field lets the POST through.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "http://localhost:8105/search", nil)
	srv.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var token string
	for _, c := range rec.Result().Cookies() {
		if c.Name == csrfCookieName {
			token = c.Value
		}
	}
	require.NotEmpty(t, token)

	form := url.Values{"csrf_token": {token}, "message_ids": {"0x0000000000000000000000000000000000000000000000000000000000000000"}}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "http://localhost:8105/search", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: token})
	srv.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "Lookup unavailable") // the fake driver answers no queries
}

func TestServerActorResolution(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Without [admin_ui] the actor is "local" (the loopback personal-tool default).
	srv := newTestServer(t, "", nil)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/search", nil)
	srv.basicAuthMiddleware(c)
	require.False(t, c.IsAborted())
	actor, ok := c.Get("actor")
	require.True(t, ok)
	require.Equal(t, "local", actor)

	// With [admin_ui] the credential gates the request and the username is the actor.
	srv = newTestServer(t, "", &BasicAuth{Username: "operator", Password: "s3cret"})
	c, _ = gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/search", nil)
	srv.basicAuthMiddleware(c)
	require.True(t, c.IsAborted(), "unauthenticated requests are rejected when [admin_ui] is set")

	c, _ = gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/search", nil)
	c.Request.SetBasicAuth("operator", "s3cret")
	srv.basicAuthMiddleware(c)
	require.False(t, c.IsAborted())
	actor, ok = c.Get("actor")
	require.True(t, ok)
	require.Equal(t, "operator", actor)
}

func TestServerHostAllowlist(t *testing.T) {
	t.Run("no basic auth: only loopback hosts are served", func(t *testing.T) {
		srv := newTestServer(t, "", nil)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		req.Host = "evil.example.com"
		srv.router.ServeHTTP(rec, req)
		require.Equal(t, http.StatusForbidden, rec.Code)

		for _, host := range []string{"localhost", "localhost:8105", "127.0.0.1:8105", "::1", "[::1]:8105"} {
			rec = httptest.NewRecorder()
			req = httptest.NewRequest(http.MethodGet, "/healthz", nil)
			req.Host = host
			srv.router.ServeHTTP(rec, req)
			require.Equal(t, http.StatusOK, rec.Code, host)
		}
	})

	t.Run("with basic auth any host reaches the credential gate", func(t *testing.T) {
		srv := newTestServer(t, "", &BasicAuth{Username: "operator", Password: "s3cret"})

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/search", nil)
		req.Host = "evil.example.com"
		srv.router.ServeHTTP(rec, req)
		require.Equal(t, http.StatusUnauthorized, rec.Code)

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = "evil.example.com"
		req.SetBasicAuth("operator", "s3cret")
		srv.router.ServeHTTP(rec, req)
		require.Equal(t, http.StatusFound, rec.Code)
	})
}

func csrfCookieFrom(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == csrfCookieName {
			return c
		}
	}
	t.Fatal("no CSRF cookie set")
	return nil
}

func TestServerCSRFCookieSecureFlag(t *testing.T) {
	srv := newTestServer(t, "", nil)

	// A forwarded-proto header does not mark the cookie Secure on a plain-HTTP request.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://localhost:8105/search", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	srv.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.False(t, csrfCookieFrom(t, rec).Secure)

	// A TLS request does.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "https://localhost:8105/search", nil)
	srv.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.True(t, csrfCookieFrom(t, rec).Secure)
}

func TestServerBodySizeLimit(t *testing.T) {
	srv := newTestServer(t, "", nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://localhost:8105/search", nil)
	srv.router.ServeHTTP(rec, req)
	token := csrfCookieFrom(t, rec).Value

	post := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "http://localhost:8105/recovery/preview", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-CSRF-Token", token)
		req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: token})
		srv.router.ServeHTTP(rec, req)
		return rec
	}

	// A well-formed small form parses and reaches the handler (the fake DB degrades
	// the lookup, but the request itself succeeds).
	small := url.Values{"owner": {"owner-1"}, "chain": {"1"}, "from_block": {"1"}, "mode": {"replay"}}
	require.Equal(t, http.StatusOK, post(small.Encode()).Code)

	// A body past the 1 MiB cap cannot be parsed and is rejected.
	oversized := "owner=" + strings.Repeat("a", 1<<20)
	require.Equal(t, http.StatusBadRequest, post(oversized).Code)
}
