package verifier

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	heartbeatpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/heartbeat/v1"
)

const (
	// DefaultHeartbeatInterval is how often to send heartbeat with chain statuses to aggregator.
	DefaultHeartbeatInterval = 10 * time.Second
)

// HeartbeatReporter periodically reads chain statuses and sends them to the aggregator via heartbeat.
type HeartbeatReporter struct {
	services.StateMachine
	stopCh services.StopChan
	wg     sync.WaitGroup

	logger             logger.Logger
	chainStatusManager protocol.ChainStatusManager
	heartbeatClient    heartbeatpb.HeartbeatServiceClient
	allSelectors       []protocol.ChainSelector
	verifierID         string
	interval           time.Duration
}

// NewHeartbeatReporter creates a new heartbeat reporter service.
func NewHeartbeatReporter(
	lggr logger.Logger,
	chainStatusManager protocol.ChainStatusManager,
	heartbeatClient heartbeatpb.HeartbeatServiceClient,
	allSelectors []protocol.ChainSelector,
	verifierID string,
	interval time.Duration,
) (*HeartbeatReporter, error) {
	if lggr == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}
	if chainStatusManager == nil {
		return nil, fmt.Errorf("chainStatusManager cannot be nil")
	}
	if heartbeatClient == nil {
		return nil, fmt.Errorf("heartbeatClient cannot be nil")
	}
	if len(allSelectors) == 0 {
		return nil, fmt.Errorf("allSelectors cannot be empty")
	}
	if verifierID == "" {
		return nil, fmt.Errorf("verifierID cannot be empty")
	}

	if interval == 0 {
		interval = DefaultHeartbeatInterval
	}

	return &HeartbeatReporter{
		stopCh:             make(chan struct{}),
		logger:             lggr,
		chainStatusManager: chainStatusManager,
		heartbeatClient:    heartbeatClient,
		allSelectors:       allSelectors,
		verifierID:         verifierID,
		interval:           interval,
	}, nil
}

// Start begins the heartbeat reporter service.
func (hr *HeartbeatReporter) Start(ctx context.Context) error {
	return hr.StartOnce(hr.Name(), func() error {
		hr.logger.Infow("Starting heartbeat reporter", "interval", hr.interval)
		hr.wg.Add(1)
		go hr.reportLoop(ctx)
		return nil
	})
}

// Close stops the heartbeat reporter service.
func (hr *HeartbeatReporter) Close() error {
	return hr.StopOnce(hr.Name(), func() error {
		hr.logger.Infow("Stopping heartbeat reporter")
		close(hr.stopCh)
		hr.wg.Wait()
		hr.logger.Infow("Heartbeat reporter stopped")
		return nil
	})
}

// Name returns the name of the service.
func (hr *HeartbeatReporter) Name() string {
	return fmt.Sprintf("verifier.HeartbeatReporter[%s]", hr.verifierID)
}

// HealthReport returns a health report for the heartbeat reporter.
func (hr *HeartbeatReporter) HealthReport() map[string]error {
	report := make(map[string]error)
	report[hr.Name()] = hr.Ready()
	return report
}

// reportLoop is the main loop that periodically sends heartbeats with chain statuses.
func (hr *HeartbeatReporter) reportLoop(ctx context.Context) {
	defer hr.wg.Done()

	ticker := time.NewTicker(hr.interval)
	defer ticker.Stop()

	// Send initial heartbeat immediately.
	hr.sendHeartbeat(ctx)

	for {
		select {
		case <-hr.stopCh:
			hr.logger.Infow("Heartbeat reporter loop stopped")
			return
		case <-ctx.Done():
			hr.logger.Infow("Heartbeat reporter context cancelled")
			return
		case <-ticker.C:
			hr.sendHeartbeat(ctx)
		}
	}
}

// sendHeartbeat reads chain statuses and sends them to the aggregator.
func (hr *HeartbeatReporter) sendHeartbeat(ctx context.Context) {
	// Read chain statuses for all selectors.
	statusMap, err := hr.chainStatusManager.ReadChainStatuses(ctx, hr.allSelectors)
	if err != nil {
		hr.logger.Errorw("Failed to read chain statuses", "error", err)
		return
	}

	// Build block heights map for heartbeat.
	blockHeightsByChain := make(map[uint64]uint64)
	for _, selector := range hr.allSelectors {
		status, ok := statusMap[selector]
		if !ok {
			hr.logger.Debugw("Chain status not found", "chainSelector", selector)
			continue
		}

		// Add block height for this chain if available.
		// TODO: change to use latest seen block height instead of finalized when available.
		if status.FinalizedBlockHeight != nil {
			blockHeightsByChain[uint64(selector)] = status.FinalizedBlockHeight.Uint64()
		}
	}

	// Create and send heartbeat request.
	req := &heartbeatpb.HeartbeatRequest{
		SendTimestamp: time.Now().Unix(),
		ChainDetails: &heartbeatpb.ChainHealthDetails{
			BlockHeightsByChain: blockHeightsByChain,
		},
	}

	resp, err := hr.heartbeatClient.SendHeartbeat(ctx, req)
	if err != nil {
		hr.logger.Errorw("Failed to send heartbeat", "error", err)
		return
	}

	hr.logger.Infow("Heartbeat sent successfully",
		"verifierId", hr.verifierID,
		"aggregatorId", resp.AggregatorId,
		"chainCount", len(blockHeightsByChain),
	)
	hr.logger.Debugw("Heartbeat details",
		"verifierId", hr.verifierID,
		"blockHeightsByChain", blockHeightsByChain,
		"chainBenchmarks", resp.ChainBenchmarks,
		"aggregatorId", resp.AggregatorId,
		"respTimestamp", resp.Timestamp,
	)
}

var _ services.Service = (*HeartbeatReporter)(nil)
