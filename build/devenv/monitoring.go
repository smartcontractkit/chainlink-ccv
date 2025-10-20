package ccv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

/*
Loki labels
*/
const (
	LokiCCIPMessageSentLabel       = "on-chain-sent"
	LokiExecutionStateChangedLabel = "on-chain-exec"
)

/*
This file includes common monitoring utilities that work with Loki/Prometheus/Tempo
This package should not define any particular product metrics but provide clients and common wrappers for products to use
*/

var (
	metricsServer *http.Server
	serverMutex   sync.Mutex
)

// ExposePrometheusMetricsFor temporarily exposes Prometheus endpoint so metrics can be scraped.
func ExposePrometheusMetricsFor(reg *prometheus.Registry, interval time.Duration) error {
	serverMutex.Lock()
	defer serverMutex.Unlock()
	if metricsServer != nil {
		Plog.Info().Msg("Shutting down previous metrics server...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := metricsServer.Shutdown(ctx); err != nil {
			Plog.Warn().Err(err).Msg("Failed to gracefully shutdown previous metrics server")
		}
		metricsServer = nil
	}

	// Create new mux to avoid conflicts with global http.Handle and run
	mux := http.NewServeMux()
	mux.Handle("/on-chain-metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	metricsServer = &http.Server{
		Addr:    ":9112",
		Handler: mux,
	}
	go func() {
		Plog.Info().Msg("Starting new Prometheus metrics server on :9112")
		if err := metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			Plog.Error().Err(err).Msg("Metrics server error")
		}
	}()
	Plog.Info().Msgf("Exposing Prometheus metrics for %s seconds...", interval.String())
	time.Sleep(interval)
	return nil
}

type IndexerClient struct {
	logger     zerolog.Logger
	url        string
	httpClient *http.Client
}

// NewIndexerClient creates a new IndexerClient with a default HTTP client.
func NewIndexerClient(logger zerolog.Logger, url string) *IndexerClient {
	return &IndexerClient{
		logger: logger,
		url:    url,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// TODO: this should probably be exported by the indexer package?
type GetVerificationsForMessageIDResponse struct {
	Success         bool               `json:"success"`
	VerifierResults []protocol.CCVData `json:"verifierResults"`
	MessageID       string             `json:"messageID"`
}

func (i *IndexerClient) WaitForVerificationsForMessageID(
	ctx context.Context,
	messageID [32]byte,
	tickInterval time.Duration,
	timeout time.Duration,
) (GetVerificationsForMessageIDResponse, error) {
	msgIDHex := common.BytesToHash(messageID[:]).Hex()
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, timeout)
	defer timeoutCancel()

	for {
		select {
		case <-timeoutCtx.Done():
			return GetVerificationsForMessageIDResponse{}, fmt.Errorf("context cancelled: %w", ctx.Err())
		case <-ticker.C:
			response, err := i.GetVerificationsForMessageID(ctx, messageID)
			if err != nil {
				i.logger.Error().Err(err).Msgf("failed to get verifications for messageID: %s, retrying", msgIDHex)
				continue
			}
			if response.Success && len(response.VerifierResults) > 0 {
				i.logger.Info().
					Str("messageID", msgIDHex).
					Int("verifierResultsLen", len(response.VerifierResults)).
					Msg("found verifications for messageID in indexer")
				return response, nil
			}
			i.logger.Error().Msgf("no verifications found for messageID: %s, retrying", msgIDHex)
		}
	}
}

// GetVerificationsForMessageID fetches the verifications for a given messageID from the indexer.
func (i *IndexerClient) GetVerificationsForMessageID(ctx context.Context, messageID [32]byte) (GetVerificationsForMessageIDResponse, error) {
	msgIDHex := common.BytesToHash(messageID[:]).Hex()
	url := fmt.Sprintf("%s/v1/messageid/%s", i.url, msgIDHex)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return GetVerificationsForMessageIDResponse{}, fmt.Errorf("failed to create request: %w", err)
	}
	resp, err := i.httpClient.Do(req)
	if err != nil {
		return GetVerificationsForMessageIDResponse{}, fmt.Errorf("failed to make request: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return GetVerificationsForMessageIDResponse{}, fmt.Errorf("non-200 status: %d, %+v", resp.StatusCode, resp.Body)
	}

	defer resp.Body.Close()
	var response GetVerificationsForMessageIDResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return GetVerificationsForMessageIDResponse{}, fmt.Errorf("failed to decode response into struct: %w", err)
	}

	if response.MessageID != msgIDHex {
		return GetVerificationsForMessageIDResponse{}, fmt.Errorf("messageID mismatch: got %s, wanted %s", response.MessageID, msgIDHex)
	}

	return response, nil
}
