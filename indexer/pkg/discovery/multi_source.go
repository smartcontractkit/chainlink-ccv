package discovery

import (
	"context"
	"errors"
	"sync"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

var _ common.MessageDiscovery = (*MultiSourceMessageDiscovery)(nil)

// MultiSourceMessageDiscovery starts and stops several MessageDiscovery sources together.
// Each source waits discoveryPriority*priorityStagger after its read before it persists, so the primary writes first.
// The insert uses ON CONFLICT (message_id) DO NOTHING, so a message that more sources find makes one row.
type MultiSourceMessageDiscovery struct {
	logger  logger.Logger
	sources []common.MessageDiscovery
	once    sync.Once
}

// NewMultiSourceMessageDiscovery builds a MultiSourceMessageDiscovery from the given sources.
func NewMultiSourceMessageDiscovery(lggr logger.Logger, sources []common.MessageDiscovery) (common.MessageDiscovery, error) {
	m := &MultiSourceMessageDiscovery{
		logger:  lggr,
		sources: sources,
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *MultiSourceMessageDiscovery) validate() error {
	if len(m.sources) < 1 {
		return errors.New("at least one discovery source is required")
	}
	for _, src := range m.sources {
		if src == nil {
			return errors.New("source is nil")
		}
	}
	if m.logger == nil {
		return errors.New("logger is required")
	}
	return nil
}

// Start starts all source discoveries.
func (m *MultiSourceMessageDiscovery) Start(ctx context.Context) {
	m.once.Do(func() {
		for _, src := range m.sources {
			src.Start(ctx)
		}
		m.logger.Info("MultiSourceMessageDiscovery started")
	})
}

// Close stops all source discoveries.
func (m *MultiSourceMessageDiscovery) Close() error {
	for i, src := range m.sources {
		if err := src.Close(); err != nil {
			m.logger.Warnw("source discovery Close returned error", "source", i, "error", err)
		}
	}
	m.logger.Info("MultiSourceMessageDiscovery stopped")
	return nil
}
