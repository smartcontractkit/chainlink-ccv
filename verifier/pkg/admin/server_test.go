package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func newTestServer(t *testing.T, cfgBody string) *Server {
	t.Helper()
	t.Setenv(SecretsPathEnv, nonexistentSecretsPath(t))
	cfg, err := LoadConfig(writeConfig(t, cfgBody))
	require.NoError(t, err)
	srv, err := NewServer(cfg, logger.Test(t))
	require.NoError(t, err)
	t.Cleanup(srv.Close)
	return srv
}

// nonexistentSecretsPath points console secrets resolution at a path that never exists,
// so tests always run in read-only mode regardless of the host environment.
func nonexistentSecretsPath(t *testing.T) string {
	return t.TempDir() + "/no-console-secrets.toml"
}

func TestServerHealthz(t *testing.T) {
	srv := newTestServer(t, validNode)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	srv.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestServerNodesPageListsConfiguredNodes(t *testing.T) {
	srv := newTestServer(t, validNode)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	srv.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "verifier-1")
	require.Contains(t, rec.Body.String(), "unreachable") // secrets file does not exist in tests
	require.Contains(t, rec.Body.String(), "Read-only mode")
}

func TestServerCSRFFlow(t *testing.T) {
	srv := newTestServer(t, validNode)

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
	require.Contains(t, rec.Body.String(), "Lookup unavailable") // node DB does not exist in tests
}

func TestServerActorResolution(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, `listen_address = "127.0.0.1:8105"
[access]
actor_header = "X-Remote-User"
`+validNode))
	require.NoError(t, err)
	require.Equal(t, "X-Remote-User", cfg.Access.ActorHeader)
}
