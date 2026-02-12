package chainstatus

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
)

var _ protocol.ChainStatusManager = (*MonitoredChainStatusManager)(nil)

// MonitoredChainStatusManager is a decorator that adds monitoring to ChainStatusManager operations.
type MonitoredChainStatusManager struct {
	manager protocol.ChainStatusManager
	metrics verifier.MetricLabeler
}

// NewMonitoredChainStatusManager creates a new MonitoredChainStatusManager decorator.
func NewMonitoredChainStatusManager(manager protocol.ChainStatusManager, metrics verifier.MetricLabeler) *MonitoredChainStatusManager {
	return &MonitoredChainStatusManager{
		manager: manager,
		metrics: metrics,
	}
}

// WriteChainStatuses writes chain statuses and records query duration with method "writeChainStatus".
func (m *MonitoredChainStatusManager) WriteChainStatuses(ctx context.Context, statuses []protocol.ChainStatusInfo) error {
	start := time.Now()
	err := m.manager.WriteChainStatuses(ctx, statuses)
	duration := time.Since(start)

	m.metrics.RecordStorageQueryDuration(ctx, "writeChainStatus", duration)

	return err
}

// ReadChainStatuses reads chain statuses and records query duration with method "readChainStatus".
func (m *MonitoredChainStatusManager) ReadChainStatuses(ctx context.Context, chainSelectors []protocol.ChainSelector) (map[protocol.ChainSelector]*protocol.ChainStatusInfo, error) {
	start := time.Now()
	result, err := m.manager.ReadChainStatuses(ctx, chainSelectors)
	duration := time.Since(start)

	m.metrics.RecordStorageQueryDuration(ctx, "readChainStatus", duration)

	return result, err
}
