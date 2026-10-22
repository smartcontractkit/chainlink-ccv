package admin

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/api/middleware"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/admin/views"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	csrfCookieName = "ccv_admin_csrf"
	// maxRequestBodyBytes caps non-GET/HEAD request bodies at 1 MiB.
	maxRequestBodyBytes = 1 << 20
)

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
	// ResultsDialer overrides how freshness checks reach the aggregator. Nil dials the
	// real aggregator; the demo harness injects a canned client.
	ResultsDialer ResultsDialer
}

// Server is the admin console HTTP server.
type Server struct {
	cfg       *Config
	lggr      logger.Logger
	stores    stores
	actions   *ActionLog
	basicAuth *BasicAuth
	dialer    ResultsDialer
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
	dialer := deps.ResultsDialer
	if dialer == nil {
		dialer = dialVerifierClient
	}
	s := &Server{
		cfg:       cfg,
		lggr:      logger.With(lggr, "component", "AdminConsole"),
		stores:    stores{db: deps.DB, lggr: lggr},
		actions:   NewActionLog(),
		basicAuth: deps.Auth,
		dialer:    dialer,
	}
	s.router = s.buildRouter(deps.AggregatorAddress)
	return s, nil
}

func (s *Server) buildRouter(aggregatorAddress string) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(s.hostAllowlistMiddleware, middleware.GinLogger(s.lggr), middleware.SecureRecovery(s.lggr), s.securityHeaders, s.basicAuthMiddleware, s.maxBodyBytesMiddleware, s.csrfMiddleware)

	h := &handlers{cfg: s.cfg, lggr: s.lggr, stores: s.stores, actions: s.actions, aggregatorAddress: aggregatorAddress, dialer: s.dialer}
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
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
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

// hostAllowlistMiddleware confines the no-basic-auth mode (the loopback personal-tool
// default) to requests addressing the console by a loopback hostname; with [admin_ui]
// configured the credential already gates access and any host is accepted.
func (s *Server) hostAllowlistMiddleware(c *gin.Context) {
	if s.basicAuth != nil {
		c.Next()
		return
	}
	host := c.Request.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	switch host {
	case "localhost", "127.0.0.1", "::1", "[::1]":
		c.Next()
	default:
		c.AbortWithStatus(http.StatusForbidden)
	}
}

// maxBodyBytesMiddleware rejects non-GET/HEAD bodies over 1 MiB with 413 before
// dispatch; the body is read up front because gin's form helpers swallow
// MaxBytesReader errors, so wrapping alone would not stop mutations.
func (s *Server) maxBodyBytesMiddleware(c *gin.Context) {
	if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead {
		c.Next()
		return
	}
	if c.Request.ContentLength > maxRequestBodyBytes {
		c.AbortWithStatus(http.StatusRequestEntityTooLarge)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, maxRequestBodyBytes))
	_ = c.Request.Body.Close()
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			c.AbortWithStatus(http.StatusRequestEntityTooLarge)
			return
		}
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(body))
	c.Request.ContentLength = int64(len(body))
	c.Next()
}

// basicAuthMiddleware gates every route except /healthz when the verifier secrets file
// carries an [admin_ui] credential. Both comparisons are constant-time. The
// authenticated username becomes the actor; without it the actor is "local" (the
// loopback personal-tool default).
func (s *Server) basicAuthMiddleware(c *gin.Context) {
	c.Set("actor", "local")
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
		// Secure over TLS, or on plain HTTP when secure_cookies says a fronting
		// proxy terminates TLS; the loopback default keeps the cookie usable.
		secure := c.Request.TLS != nil || s.cfg.SecureCookies
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
