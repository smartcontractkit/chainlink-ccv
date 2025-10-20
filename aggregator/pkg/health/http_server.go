package health

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type HTTPHealthServer struct {
	manager *HealthManager
	logger  logger.SugaredLogger
	server  *http.Server
}

func NewHTTPHealthServer(manager *HealthManager, port string, logger logger.SugaredLogger) *HTTPHealthServer {
	mux := http.NewServeMux()

	h := &HTTPHealthServer{
		manager: manager,
		logger:  logger,
		server: &http.Server{
			Addr:         ":" + port,
			Handler:      mux,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		},
	}

	mux.HandleFunc("/health/live", h.handleLiveness)
	mux.HandleFunc("/health/ready", h.handleReadiness)
	mux.HandleFunc("/health", h.handleReadiness)

	return h
}

func (h *HTTPHealthServer) handleLiveness(w http.ResponseWriter, r *http.Request) {
	liveness := h.manager.CheckLiveness(r.Context())

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(liveness)
}

func (h *HTTPHealthServer) handleReadiness(w http.ResponseWriter, r *http.Request) {
	status, components := h.manager.CheckReadiness(r.Context())

	response := map[string]interface{}{
		"status":     string(status),
		"components": components,
		"timestamp":  time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")

	switch status {
	case common.HealthStatusHealthy:
		w.WriteHeader(http.StatusOK)
	case common.HealthStatusDegraded:
		w.WriteHeader(http.StatusOK)
		h.logger.Warnw("Service degraded", "components", components)
	case common.HealthStatusUnhealthy:
		w.WriteHeader(http.StatusServiceUnavailable)
		h.logger.Errorw("Service unhealthy", "components", components)
	}

	json.NewEncoder(w).Encode(response)
}

func (h *HTTPHealthServer) Start() error {
	h.logger.Infow("Starting HTTP health server", "addr", h.server.Addr)
	return h.server.ListenAndServe()
}

func (h *HTTPHealthServer) Stop(ctx context.Context) error {
	h.logger.Info("Stopping HTTP health server")
	return h.server.Shutdown(ctx)
}
