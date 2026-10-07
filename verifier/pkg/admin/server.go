package admin

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/api/middleware"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/admin/views"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const csrfCookieName = "ccv_admin_csrf"

// Deps are the in-process dependencies the console needs from the verifier it runs
// beside: its application database (migrations already applied) and its secrets.
type Deps struct {
	// DB is the verifier's application database. The action log is written here too.
	DB *sqlx.DB
	// Auth is the basic-auth credential from the verifier secrets file's [admin_ui]
	// table; nil serves without basic auth (the loopback personal-tool default).
	Auth *BasicAuth
	// AggregatorAddress (host:port) enables attestation freshness checks; empty
	// disables them and reschedule execution stays blocked on "unknown".
	AggregatorAddress string
}

// Server is the admin console HTTP server.
type Server struct {
	cfg       *Config
	lggr      logger.Logger
	stores    stores
	actions   *ActionLog
	basicAuth *BasicAuth
	router    *gin.Engine
	httpSrv   *http.Server
}

// NewServer builds the console over the verifier's own database. The access policy
// (non-loopback needs an identity source) is enforced here, where the secrets-derived
// credential is available.
func NewServer(cfg *Config, deps Deps, lggr logger.Logger) (*Server, error) {
	if cfg == nil {
		return nil, errors.New("config is required")
	}
	if deps.DB == nil {
		return nil, errors.New("the verifier application database is required")
	}
	if err := ValidateAccessPolicy(cfg, deps.Auth); err != nil {
		return nil, err
	}
	s := &Server{
		cfg:       cfg,
		lggr:      logger.With(lggr, "component", "AdminConsole"),
		stores:    stores{db: deps.DB, lggr: lggr},
		actions:   NewActionLog(deps.DB),
		basicAuth: deps.Auth,
	}
	s.router = s.buildRouter(deps.AggregatorAddress)
	return s, nil
}

func (s *Server) buildRouter(aggregatorAddress string) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(middleware.GinLogger(s.lggr), middleware.SecureRecovery(s.lggr), s.securityHeaders, s.actorMiddleware, s.basicAuthMiddleware, s.csrfMiddleware)

	h := &handlers{cfg: s.cfg, lggr: s.lggr, stores: s.stores, actions: s.actions, aggregatorAddress: aggregatorAddress}
	staticSub, err := fs.Sub(views.StaticFS, "static")
	if err != nil {
		s.lggr.Errorw("failed to mount static assets", "error", err)
	} else {
		r.StaticFS("/static", http.FS(staticSub))
	}
	h.registerCoreRoutes(r)
	h.registerSearchRoutes(r)
	h.registerDetailRoutes(r)
	h.registerRescheduleRoutes(r)
	h.registerRecoveryRoutes(r)
	return r
}

// Run serves until ctx is canceled, then shuts down gracefully.
func (s *Server) Run(ctx context.Context) error {
	s.httpSrv = &http.Server{
		Addr:              s.cfg.ListenAddress,
		Handler:           s.router,
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		s.lggr.Infow("admin console listening", "address", s.cfg.ListenAddress)
		if err := s.httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.httpSrv.Shutdown(shutdownCtx)
	}
}

// actorMiddleware resolves the per-request actor: the configured proxy header on shared
// hosting, or "local" on loopback. The action log trusts only this value. Basic auth
// overrides it: an authenticated username is verified by the console itself.
func (s *Server) actorMiddleware(c *gin.Context) {
	actor := "local"
	if header := s.cfg.Access.ActorHeader; header != "" {
		if value := c.GetHeader(header); value != "" {
			actor = value
		} else {
			actor = "unknown"
		}
	}
	c.Set("actor", actor)
	c.Next()
}

// basicAuthMiddleware gates every route except /healthz when the verifier secrets file
// carries an [admin_ui] credential. Both comparisons are constant-time. The
// authenticated username becomes the actor (outranking the proxy header).
func (s *Server) basicAuthMiddleware(c *gin.Context) {
	if s.basicAuth == nil || c.Request.URL.Path == "/healthz" {
		c.Next()
		return
	}
	user, pass, ok := c.Request.BasicAuth()
	if !ok ||
		subtle.ConstantTimeCompare([]byte(user), []byte(s.basicAuth.Username)) != 1 ||
		subtle.ConstantTimeCompare([]byte(pass), []byte(s.basicAuth.Password)) != 1 {
		c.Header("WWW-Authenticate", `Basic realm="ccv-admin"`)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	c.Set("actor", user)
	c.Next()
}

// csrfMiddleware protects browser-originated mutations: every unsafe method must carry
// the per-browser token as a form field or header matching the cookie.
func (s *Server) csrfMiddleware(c *gin.Context) {
	token := ""
	if cookie, err := c.Cookie(csrfCookieName); err == nil {
		token = cookie
	}
	if token == "" || len(token) > 128 {
		token = newCSRFToken()
		// Secure only over TLS or an https-forwarding proxy: the default
		// loopback deployment is plain HTTP and must still receive the token.
		secure := c.Request.TLS != nil || strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https")
		c.SetCookie(csrfCookieName, token, 0, "/", "", secure, true)
	}
	c.Set("csrfToken", token)

	switch c.Request.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		c.Next()
		return
	}
	provided := c.PostForm("csrf_token")
	if provided == "" {
		provided = c.GetHeader("X-CSRF-Token")
	}
	if provided == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	c.Next()
}

func (s *Server) securityHeaders(c *gin.Context) {
	c.Header("X-Frame-Options", "DENY")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Referrer-Policy", "no-referrer")
	c.Header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'")
	c.Next()
}

func newCSRFToken() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("failed to generate CSRF token: %v", err))
	}
	return hex.EncodeToString(buf)
}
