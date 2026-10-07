package admin

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vsecrets"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func writeSecrets(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secrets.toml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

func TestBasicAuthFromSecrets(t *testing.T) {
	t.Run("nil secrets and absent table both mean no auth", func(t *testing.T) {
		auth, err := BasicAuthFromSecrets(nil)
		require.NoError(t, err)
		require.Nil(t, auth)

		secrets, err := vsecrets.Load(writeSecrets(t, `[db]
url = "postgres://demo:demo@localhost/db"
`))
		require.NoError(t, err)
		auth, err = BasicAuthFromSecrets(secrets)
		require.NoError(t, err)
		require.Nil(t, auth)
	})

	t.Run("a full pair enables basic auth", func(t *testing.T) {
		secrets, err := vsecrets.Load(writeSecrets(t, `[admin_ui]
username = "operator"
password = "s3cret"
`))
		require.NoError(t, err)
		auth, err := BasicAuthFromSecrets(secrets)
		require.NoError(t, err)
		require.Equal(t, &BasicAuth{Username: "operator", Password: "s3cret"}, auth)
	})

	t.Run("a half-supplied pair is a startup error, not a silent downgrade", func(t *testing.T) {
		for _, body := range []string{
			"[admin_ui]\nusername = \"operator\"\n",
			"[admin_ui]\npassword = \"s3cret\"\n",
		} {
			secrets, err := vsecrets.Load(writeSecrets(t, body))
			require.NoError(t, err)
			_, err = BasicAuthFromSecrets(secrets)
			require.ErrorContains(t, err, "[admin_ui] requires both username and password")
		}
	})
}

func TestValidateAccessPolicy(t *testing.T) {
	cfg := func(addr, header string) *Config {
		return &Config{ListenAddress: addr, Access: AccessConfig{ActorHeader: header}}
	}
	auth := &BasicAuth{Username: "u", Password: "p"}

	// Loopback needs nothing; a wildcard bind counts as non-loopback.
	for _, addr := range []string{"127.0.0.1:8105", "localhost:8105", "[::1]:8105"} {
		require.NoError(t, ValidateAccessPolicy(cfg(addr, ""), nil), addr)
	}
	for _, addr := range []string{"0.0.0.0:8105", ":8105", "10.0.0.5:8105"} {
		require.ErrorContains(t, ValidateAccessPolicy(cfg(addr, ""), nil), "identity source", addr)
		require.NoError(t, ValidateAccessPolicy(cfg(addr, "X-Remote-User"), nil), addr)
		require.NoError(t, ValidateAccessPolicy(cfg(addr, ""), auth), addr)
	}
}

// newTestServerWithSecrets builds a server with basic auth parsed from a secrets file
// carrying the given content, so the full [admin_ui] gate is exercisable.
func newTestServerWithSecrets(t *testing.T, cfgBody, secretsBody string) *Server {
	t.Helper()
	secrets, err := vsecrets.Load(writeSecrets(t, secretsBody))
	require.NoError(t, err)
	auth, err := BasicAuthFromSecrets(secrets)
	require.NoError(t, err)
	return newTestServer(t, cfgBody, auth)
}

func TestServerBasicAuth(t *testing.T) {
	srv := newTestServerWithSecrets(t, "", `[admin_ui]
username = "operator"
password = "s3cret"
`)

	t.Run("unauthenticated requests are rejected with a challenge", func(t *testing.T) {
		for _, path := range []string{"/", "/search", "/actions"} {
			rec := httptest.NewRecorder()
			srv.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			require.Equal(t, http.StatusUnauthorized, rec.Code, path)
			require.Equal(t, `Basic realm="ccv-admin"`, rec.Header().Get("WWW-Authenticate"))
		}
	})

	t.Run("healthz stays open for probes", func(t *testing.T) {
		rec := httptest.NewRecorder()
		srv.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("wrong credentials are rejected", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.SetBasicAuth("operator", "wrong")
		srv.router.ServeHTTP(rec, req)
		require.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("the authenticated username becomes the actor", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodGet, "/search", nil)
		c.Request.SetBasicAuth("operator", "s3cret")
		srv.basicAuthMiddleware(c)
		require.False(t, c.IsAborted())
		actor, ok := c.Get("actor")
		require.True(t, ok)
		require.Equal(t, "operator", actor)
	})
}

func TestServerBasicAuthStartupRules(t *testing.T) {
	t.Run("half-supplied pair fails startup", func(t *testing.T) {
		secrets, err := vsecrets.Load(writeSecrets(t, "[admin_ui]\nusername = \"operator\"\n"))
		require.NoError(t, err)
		_, err = BasicAuthFromSecrets(secrets)
		require.ErrorContains(t, err, "[admin_ui]")
	})

	t.Run("basic auth satisfies the non-loopback identity rule", func(t *testing.T) {
		cfg, err := LoadConfig(writeConfig(t, `listen_address = "0.0.0.0:8105"`+"\n"))
		require.NoError(t, err)
		_, err = NewServer(cfg, Deps{DB: newFakeSQLDB(t), Auth: &BasicAuth{Username: "u", Password: "p"}}, logger.Test(t))
		require.NoError(t, err)
	})

	t.Run("non-loopback without any identity source fails startup", func(t *testing.T) {
		cfg, err := LoadConfig(writeConfig(t, `listen_address = "0.0.0.0:8105"`+"\n"))
		require.NoError(t, err)
		_, err = NewServer(cfg, Deps{DB: newFakeSQLDB(t)}, logger.Test(t))
		require.ErrorContains(t, err, "identity source")
	})
}
