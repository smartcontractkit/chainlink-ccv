package ccv

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"

	v1 "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api/handlers/v1"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/client"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

/*
Loki labels.
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

type IndexerMonitor struct {
	logger        zerolog.Logger
	indexerClient *client.IndexerClient
}

// NewIndexerMonitor creates a new IndexerMonitor with a default HTTP client.
func NewIndexerMonitor(logger zerolog.Logger, indexerClient *client.IndexerClient) (*IndexerMonitor, error) {
	return &IndexerMonitor{
		logger:        logger,
		indexerClient: indexerClient,
	}, nil
}

type GetVerificationsForMessageIDResponse struct {
	v1.VerifierResultsByMessageIDResponse
}

func (g GetVerificationsForMessageIDResponse) SourceVerifierAddresses() []protocol.UnknownAddress {
	sourceVerifierAddresses := make([]protocol.UnknownAddress, 0, len(g.Results))
	for _, verifierResult := range g.Results {
		sourceVerifierAddresses = append(sourceVerifierAddresses, verifierResult.VerifierResult.VerifierSourceAddress)
	}
	return sourceVerifierAddresses
}

func (i *IndexerMonitor) WaitForVerificationsForMessageID(
	ctx context.Context,
	messageID [32]byte,
	tickInterval time.Duration,
	expectedVerifierResults int,
) (GetVerificationsForMessageIDResponse, error) {
	msgIDHex := common.BytesToHash(messageID[:]).Hex()
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return GetVerificationsForMessageIDResponse{}, fmt.Errorf("context cancelled: %w", ctx.Err())
		case <-ticker.C:
			response, err := i.GetVerificationsForMessageID(ctx, messageID)
			if err != nil {
				i.logger.Error().Err(err).Msgf("failed to get verifications for messageID: %s, retrying", msgIDHex)
				continue
			}
			if response.Success && len(response.Results) == expectedVerifierResults {
				i.logger.Info().
					Str("messageID", msgIDHex).
					Int("verifierResultsLen", len(response.Results)).
					Any("verifierAddresses", response.SourceVerifierAddresses()).
					Int("expectedVerifierResults", expectedVerifierResults).
					Msg("found verifications for messageID in indexer")
				return response, nil
			}
			i.logger.Error().Msgf("not enough verifications found for messageID: %s, expected %d, got %d, retrying", msgIDHex, expectedVerifierResults, len(response.Results))
		}
	}
}

// GetVerificationsForMessageID fetches the verifications for a given messageID from the indexer.
func (i *IndexerMonitor) GetVerificationsForMessageID(ctx context.Context, messageID protocol.Bytes32) (GetVerificationsForMessageIDResponse, error) {
	status, resp, err := i.indexerClient.VerifierResultsByMessageID(ctx, v1.VerifierResultsByMessageIDInput{
		MessageID: messageID.String(),
	})
	if err != nil {
		return GetVerificationsForMessageIDResponse{}, fmt.Errorf("failed to get verifications for messageID: %w", err)
	}
	if status != http.StatusOK {
		return GetVerificationsForMessageIDResponse{}, fmt.Errorf("non-200 status: %d, response: %+v", status, resp)
	}

	return GetVerificationsForMessageIDResponse{
		VerifierResultsByMessageIDResponse: resp,
	}, nil
}
