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
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
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

type GetVerificationsForMessageIDResponse struct {
	protocol.MessageIDV1Response
}

func (g GetVerificationsForMessageIDResponse) SourceVerifierAddresses() []protocol.UnknownAddress {
	sourceVerifierAddresses := make([]protocol.UnknownAddress, 0, len(g.Results))
	for _, verifierResult := range g.Results {
		sourceVerifierAddresses = append(sourceVerifierAddresses, verifierResult.VerifierResult.VerifierSourceAddress)
	}
	return sourceVerifierAddresses
}

func (i *IndexerClient) WaitForVerificationsForMessageID(
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

	if response.MessageID.String() != msgIDHex {
		return GetVerificationsForMessageIDResponse{}, fmt.Errorf("messageID mismatch: got %s, wanted %s", response.MessageID, msgIDHex)
	}

	return response, nil
}

type AggregatorClient struct {
	logger               zerolog.Logger
	addr                 string
	aggregatorClient     pb.CommitteeVerifierClient
	verifierResultClient pb.VerifierResultAPIClient
	conn                 *grpc.ClientConn
}

// NewAggregatorClient creates a new AggregatorClient without authentication.
func NewAggregatorClient(logger zerolog.Logger, addr string) (*AggregatorClient, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to aggregator: %w", err)
	}

	return &AggregatorClient{
		logger:               logger,
		addr:                 addr,
		aggregatorClient:     pb.NewCommitteeVerifierClient(conn),
		verifierResultClient: pb.NewVerifierResultAPIClient(conn),
		conn:                 conn,
	}, nil
}

func (a *AggregatorClient) Close() error {
	if a.conn != nil {
		return a.conn.Close()
	}
	return nil
}

func (a *AggregatorClient) WaitForVerifierResultForMessage(
	ctx context.Context,
	messageID [32]byte,
	tickInterval time.Duration,
) (*pb.VerifierResult, error) {
	msgIDHex := common.BytesToHash(messageID[:]).Hex()
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("context cancelled: %w", ctx.Err())
		case <-ticker.C:
			result, err := a.GetVerifierResultForMessage(ctx, messageID)
			if err != nil {
				a.logger.Error().Err(err).Msgf("failed to get verifier result for messageID: %s, retrying", msgIDHex)
				continue
			}
			if result != nil && len(result.CcvData) > 0 {
				a.logger.Info().
					Str("messageID", msgIDHex).
					Int("ccvDataLen", len(result.CcvData)).
					Msg("found verifier result for messageID in aggregator")
				return result, nil
			}
			a.logger.Error().Msgf("no verifier result found for messageID: %s, retrying", msgIDHex)
		}
	}
}

func (a *AggregatorClient) GetVerifierResultForMessage(ctx context.Context, messageID [32]byte) (*pb.VerifierResult, error) {
	resp, err := a.verifierResultClient.GetVerifierResultsForMessage(ctx, &pb.GetVerifierResultsForMessageRequest{
		MessageIds: [][]byte{messageID[:]},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get verifier result: %w", err)
	}

	// Check for errors in the batch response
	if len(resp.Errors) > 0 && resp.Errors[0].Code != 0 {
		return nil, fmt.Errorf("verifier result error: %s", resp.Errors[0].Message)
	}

	// Return the first (and only) result
	if len(resp.Results) > 0 {
		return resp.Results[0], nil
	}

	return nil, fmt.Errorf("no verifier result found")
}
