// Package infoserver provides an HTTP server that exposes verifier information.
package infoserver

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// InfoResponse is the response format for the /info endpoint.
type InfoResponse struct {
	SigningAddress string `json:"signing_address"`
	CSAPublicKey   string `json:"csa_public_key"`
}

// HealthResponse is the response format for the /health endpoint.
type HealthResponse struct {
	Status string `json:"status"`
	Phase  string `json:"phase"`
}

// Phase represents the current lifecycle phase of the verifier.
type Phase string

const (
	PhaseInit   Phase = "init"
	PhaseReady  Phase = "ready"
	PhaseActive Phase = "active"
)

// Server is an HTTP server that exposes verifier information.
type Server struct {
	httpServer *http.Server
	lggr       logger.Logger
	info       InfoResponse

	mu    sync.RWMutex
	phase Phase
}

// New creates a new info server.
func New(addr string, signingAddr string, csaPubKey []byte, lggr logger.Logger) *Server {
	s := &Server{
		info: InfoResponse{
			SigningAddress: signingAddr,
			CSAPublicKey:   hex.EncodeToString(csaPubKey),
		},
		phase: PhaseReady,
		lggr:  lggr,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/info", s.handleInfo)
	mux.HandleFunc("/health", s.handleHealth)

	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	return s
}

// Start starts the HTTP server. This is a blocking call.
func (s *Server) Start() error {
	s.lggr.Infow("Starting info server", "addr", s.httpServer.Addr)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.lggr.Infow("Shutting down info server")
	return s.httpServer.Shutdown(ctx)
}

// SetPhase updates the current lifecycle phase.
func (s *Server) SetPhase(phase Phase) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.phase = phase
}

// GetPhase returns the current lifecycle phase.
func (s *Server) GetPhase() Phase {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.phase
}

// handleInfo handles the /info endpoint.
func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(s.info); err != nil {
		s.lggr.Errorw("Failed to encode info response", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// handleHealth handles the /health endpoint.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp := HealthResponse{
		Status: "ok",
		Phase:  string(s.GetPhase()),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.lggr.Errorw("Failed to encode health response", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// Addr returns the server's address.
func (s *Server) Addr() string {
	return s.httpServer.Addr
}
