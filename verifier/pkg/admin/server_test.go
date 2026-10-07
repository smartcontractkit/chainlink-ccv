package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// newFakeSQLDB returns a *sqlx.DB backed by the fake driver: ExecContext is captured,
// anything else errors, so no real database is needed for server-construction tests.
func newFakeSQLDB(t *testing.T) *sqlx.DB {
	t.Helper()
	db, _ := newFakeActionLog(nil)
	return db.ds
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
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	srv.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestServerRootRedirectsToSearch(t *testing.T) {
	srv := newTestServer(t, "", nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
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
	req := httptest.NewRequest(http.MethodPost, "/search", strings.NewReader("message_ids=0x00"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	srv.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusForbidden, rec.Code)

	// A GET sets the cookie; echoing it as the form field lets the POST through.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/search", nil)
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
	req = httptest.NewRequest(http.MethodPost, "/search", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: token})
	srv.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "Lookup unavailable") // the fake driver answers no queries
}

func TestServerActorResolution(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, `listen_address = "127.0.0.1:8105"
[access]
actor_header = "X-Remote-User"
`))
	require.NoError(t, err)
	require.Equal(t, "X-Remote-User", cfg.Access.ActorHeader)
}
