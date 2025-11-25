package monitoring

import (
	"context"
	"time"

	"github.com/patrickmn/go-cache"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	DefaultE2ELatencyCacheExpiration      = 2 * time.Hour
	DefaultE2ELatencyCacheCleanupInterval = 5 * time.Minute
)

type inmemoryMessageLatencyTracker struct {
	lggr       logger.Logger
	verifierID string
	monitoring verifier.Monitoring
	// Timestamp tracking for E2E latency measurement
	messageTimestamps *cache.Cache
}

func NewMessageLatencyTracker(
	lggr logger.Logger,
	verifierID string,
	monitoring verifier.Monitoring,
) verifier.MessageLatencyTracker {
	return &inmemoryMessageLatencyTracker{
		lggr:       lggr,
		verifierID: verifierID,
		monitoring: monitoring,
		messageTimestamps: cache.New(
			DefaultE2ELatencyCacheExpiration,
			DefaultE2ELatencyCacheCleanupInterval,
		),
	}
}

func (m *inmemoryMessageLatencyTracker) MarkMessageAsSeen(task *verifier.VerificationTask) {
	messageID, err := task.Message.MessageID()
	if err != nil {
		m.lggr.Errorw("Failed to compute message ID for latency tracking", "error", err)
		return
	}

	// Track message creation time for E2E latency measurement
	if task.FirstSeenAt.IsZero() {
		// If FirstSeenAt was not set by source reader, set it now
		task.FirstSeenAt = time.Now()
	}

	// Make it idempotent, don't overwrite existing timestamp if it's already in the cache
	if _, ok := m.messageTimestamps.Get(messageID.String()); ok {
		return
	}
	m.messageTimestamps.SetDefault(messageID.String(), task.FirstSeenAt)
}

func (m *inmemoryMessageLatencyTracker) TrackMessageLatencies(ctx context.Context, messages []protocol.VerifierNodeResult) {
	for _, ccvNodeData := range messages {
		messageID := ccvNodeData.MessageID.String()

		if rawSeenAt, exists := m.messageTimestamps.Get(messageID); exists {
			seenAt, ok1 := rawSeenAt.(time.Time)
			if !ok1 {
				m.lggr.Errorw("Invalid timestamp type in cache for message")
				continue
			}
			m.monitoring.Metrics().
				With("source_chain", ccvNodeData.Message.SourceChainSelector.String(), "verifier_id", m.verifierID).
				RecordMessageE2ELatency(ctx, time.Since(seenAt))
			m.messageTimestamps.Delete(messageID)
		}
	}
}
