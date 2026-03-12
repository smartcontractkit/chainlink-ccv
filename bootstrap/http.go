package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

const (
	GetKeysEndpoint = "/keystore/reader/getkeys"
	HealthEndpoint  = "/health"
)

type infoServer struct {
	services.StateMachine

	srv        *http.Server
	lggr       logger.Logger
	listenPort int

	wg sync.WaitGroup

	keyStore keystore.Keystore
}

func newInfoServer(lggr logger.Logger, keyStore keystore.Keystore, listenPort int) *infoServer {
	return &infoServer{
		lggr:       lggr,
		listenPort: listenPort,
		keyStore:   keyStore,
	}
}

func (s *infoServer) Start(ctx context.Context) error {
	return s.StartOnce("InfoServer", func() error {
		s.lggr.Infow("Starting HTTP server", "listen_port", s.listenPort)

		mux := http.NewServeMux()
		mux.HandleFunc(GetKeysEndpoint, s.handleGetKeys)
		mux.HandleFunc(HealthEndpoint, s.handleHealth)

		s.srv = &http.Server{
			Addr:              fmt.Sprintf(":%d", s.listenPort),
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		}

		s.wg.Go(func() {
			if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				s.lggr.Errorw("HTTP server error", "error", err)
			}
		})

		return nil
	})
}

func (s *infoServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.lggr.Infow("health request received")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
		s.lggr.Errorw("failed to encode health response", "error", err)
	}
}

func (s *infoServer) handleGetKeys(w http.ResponseWriter, r *http.Request) {
	s.lggr.Infow("get keys request received")

	// Parse body, should be JSON with KeyNames field.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer r.Body.Close() //nolint:errcheck

	var req keystore.GetKeysRequest
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

func (s *infoServer) Stop(ctx context.Context) error {
	return s.StopOnce("InfoServer", func() error {
		s.lggr.Infow("Stopping HTTP server", "listen_port", s.listenPort)
		err := s.srv.Shutdown(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			return fmt.Errorf("failed to shutdown HTTP server: %w", err)
		}
		s.wg.Wait()
		s.lggr.Infow("HTTP server stopped", "listen_port", s.listenPort)
		return nil
	})
}
