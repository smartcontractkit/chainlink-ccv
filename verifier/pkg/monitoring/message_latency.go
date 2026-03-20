package monitoring

import (
	"context"
	"time"

	"github.com/patrickmn/go-cache"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"

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
	messageID := task.MessageID

	// Track message ready time for E2E latency measurement using block timestamp when finalized
	var trackingTime time.Time
	if !task.ReadyForVerificationAt.IsZero() {
		trackingTime = task.ReadyForVerificationAt
	} else {
		// If timestamp is not set, use current time as fallback
		trackingTime = time.Now()
	}

	// Make it idempotent, don't overwrite existing timestamp if it's already in the cache
	if _, ok := m.messageTimestamps.Get(messageID); ok {
		return
	}
	m.messageTimestamps.SetDefault(messageID, trackingTime)
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

			latency := time.Since(seenAt)
			// Protect against negative latencies due to clock drift between blockchain and node
			if latency < 0 {
				m.lggr.Warnw("Negative E2E latency detected due to clock drift - reporting as zero",
					"messageID", messageID,
					"blockTimestamp", seenAt,
					"now", time.Now(),
					"drift", latency,
				)
				latency = 0
			}

			m.monitoring.Metrics().
				With("source_chain", ccvNodeData.Message.SourceChainSelector.String(), "source_chain_name", ccvNodeData.Message.SourceChainSelector.Name(), "verifier_id", m.verifierID).
				RecordMessageE2ELatency(ctx, latency)
			m.messageTimestamps.Delete(messageID)
		}
	}
}
