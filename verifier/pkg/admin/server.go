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
	"time"

	"github.com/gin-gonic/gin"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/api/middleware"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/admin/views"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const csrfCookieName = "ccv_admin_csrf" //nolint:gosec // G101: cookie name, not a credential

// Server is the admin console HTTP server.
type Server struct {
	cfg     *Config
	lggr    logger.Logger
	nodes   []*Node
	actions *ActionLog // nil in read-only mode
	router  *gin.Engine
	httpSrv *http.Server
}

// NewServer builds the console. Node databases connect lazily on first use; the console
// database connects eagerly so read-only mode is known at startup.
func NewServer(cfg *Config, lggr logger.Logger) (*Server, error) {
	if cfg == nil {
		return nil, errors.New("config is required")
	}
	consoleDB, err := openConsoleDB(lggr, cfg.ResolveConsoleSecretsPath())
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, lggr: logger.With(lggr, "component", "AdminConsole")}
	for _, nc := range cfg.Nodes {
		s.nodes = append(s.nodes, NewNode(nc, lggr))
	}
	if consoleDB != nil {
		s.actions = NewActionLog(consoleDB)
	}
	s.router = s.buildRouter()
	return s, nil
}

// ReadOnly reports whether the console has no action-log database and therefore
// refuses mutations.
func (s *Server) ReadOnly() bool { return s.actions == nil }

func (s *Server) buildRouter() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(middleware.GinLogger(s.lggr), middleware.SecureRecovery(s.lggr), s.securityHeaders, s.actorMiddleware, s.csrfMiddleware)

	h := &handlers{cfg: s.cfg, lggr: s.lggr, nodes: s.nodes, actions: s.actions}
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
	h.registerBackfillRoutes(r)
	return r
}

// Run serves until ctx is cancelled, then shuts down gracefully.
func (s *Server) Run(ctx context.Context) error {
	s.httpSrv = &http.Server{
		Addr:              s.cfg.ListenAddress,
		Handler:           s.router,
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		s.lggr.Infow("admin console listening", "address", s.cfg.ListenAddress, "readOnly", s.ReadOnly())
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

func (s *Server) Close() {
	for _, n := range s.nodes {
		n.Close()
	}
}

// actorMiddleware resolves the per-request actor: the configured proxy header on shared
// hosting, or "local" on loopback. The action log trusts only this value.
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

// csrfMiddleware protects browser-originated mutations: every unsafe method must carry
// the per-browser token as a form field or header matching the cookie.
func (s *Server) csrfMiddleware(c *gin.Context) {
	token := ""
	if cookie, err := c.Cookie(csrfCookieName); err == nil {
		token = cookie
	}
	if token == "" || len(token) > 128 {
		token = newCSRFToken()
		c.SetCookie(csrfCookieName, token, 0, "/", "", false, true)
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
