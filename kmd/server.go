package kmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	ks "github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	shutdownTimeout = 10 * time.Second

	CreateEndpoint  = "/admin/createkeys"
	SignEndpoint    = "/signer/sign"
	GetKeysEndpoint = "/reader/getkeys"
)

// Server is an HTTP server for the KMD server.
// Not all key operations are exposed through the HTTP API.
// For admin-level operations, the keystore CLI can be used directly.
type Server struct {
	keyStore ks.Keystore
	port     int
	wg       sync.WaitGroup
	lggr     logger.Logger
	srv      *http.Server
}

// NewServer creates a new Server.
func NewServer(keyStore ks.Keystore, port int, lggr logger.Logger) *Server {
	return &Server{
		keyStore: keyStore,
		port:     port,
		lggr:     lggr,
	}
}

// Start starts the Server.
func (s *Server) Start() error {
	mux := http.NewServeMux()
	// Only expose functionality that CCIP apps are expected to use.
	// Verifiers and executors sign messages.
	// JD clients also sign messages as part of JD comms. They also need the CSA public key.
	mux.HandleFunc(SignEndpoint, s.handleSign)
	mux.HandleFunc(GetKeysEndpoint, s.handleGetKeys)
	mux.HandleFunc(CreateEndpoint, s.handleCreateKeys)
	s.srv = &http.Server{
		Addr:              fmt.Sprintf(":%d", s.port),
		Handler:           mux,
		ReadHeaderTimeout: 1 * time.Second, // Slowloris not really a concern here, but setting anyway to alleviate G112.
	}
	s.wg.Go(func() {
		if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.lggr.Errorw("failed to start HTTP server", "error", err)
		}
	})
	return nil
}

func (s *Server) handleCreateKeys(w http.ResponseWriter, r *http.Request) {
	s.lggr.Infow("create keys request received")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer r.Body.Close() //nolint:errcheck

	var req ks.CreateKeysRequest
	if err := json.Unmarshal(body, &req); err != nil {
		s.lggr.Errorw("failed to unmarshal create keys request", "error", err, "body", string(body))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.lggr.Infow("create keys request parsed", "request", req)

	createResponse, err := s.keyStore.CreateKeys(r.Context(), req)
	if err != nil {
		s.lggr.Errorw("failed to create keys", "error", err, "request", req)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.lggr.Infow("create keys response", "response", createResponse)

	// Return the keys in the response.
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(createResponse); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (s *Server) handleGetKeys(w http.ResponseWriter, r *http.Request) {
	s.lggr.Infow("get keys request received")

	// Parse body, should be JSON with KeyNames field.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer r.Body.Close() //nolint:errcheck

	var req ks.GetKeysRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.lggr.Infow("get keys request parsed", "request", req)

	keysResponse, err := s.keyStore.GetKeys(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.lggr.Infow("get keys response", "response", keysResponse)

	// Return the keys in the response.
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(keysResponse); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// handleSign handles the sign request.
func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	// Parse body, should be JSON with KeyName and Data fields.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer r.Body.Close() //nolint:errcheck

	var req ks.SignRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Call ks.Sign() with the KeyName and Data.
	signResponse, err := s.keyStore.Sign(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return the signature in the response.
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(signResponse); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// Stop stops the Server.
func (s *Server) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	err := s.srv.Shutdown(ctx)
	if err != nil {
		return fmt.Errorf("failed to shutdown HTTP server: %w", err)
	}
	s.wg.Wait()
	return nil
}
