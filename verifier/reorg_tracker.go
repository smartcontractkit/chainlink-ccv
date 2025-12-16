package verifier

import (
	"context"
	"strconv"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// ReorgTracker tracks sequence numbers that were affected by shallow reorgs.
// Messages with tracked seqNums must wait for full finalization before verification,
// ignoring any custom "faster-than-finality" settings.
//
// Tracking is per destination chain since sequence numbers are scoped by (source, dest) lane.
type ReorgTracker struct {
	reorgedSeqNums map[protocol.ChainSelector]map[protocol.SequenceNumber]struct{}
	logger         logger.Logger
	metrics        MetricLabeler
}

func NewReorgTracker(lggr logger.Logger, metrics MetricLabeler) *ReorgTracker {
	return &ReorgTracker{
		reorgedSeqNums: make(map[protocol.ChainSelector]map[protocol.SequenceNumber]struct{}),
		logger:         lggr,
		metrics:        metrics,
	}
}

// Track adds a reorged seqNum for a specific destination lane.
// Called when a message's messageID disappears from query results (indicating reorg).
func (t *ReorgTracker) Track(destChain protocol.ChainSelector, seqNum protocol.SequenceNumber) {
	if t.reorgedSeqNums[destChain] == nil {
		t.reorgedSeqNums[destChain] = make(map[protocol.SequenceNumber]struct{})
	}

	if _, exists := t.reorgedSeqNums[destChain][seqNum]; exists {
		return
	}

	t.reorgedSeqNums[destChain][seqNum] = struct{}{}

	count := len(t.reorgedSeqNums[destChain])

	t.logger.Infow("Tracking reorged sequence number",
		"destChain", destChain,
		"seqNum", seqNum,
		"trackedCount", count,
	)

	t.metrics.With("destChain", strconv.FormatUint(uint64(destChain), 10)).
		RecordReorgTrackedSeqNums(context.Background(), int64(count))
}

// RequiresFinalization returns true if the seqNum was reorged for the given destination.
// Messages returning true must wait for full finalization.
func (t *ReorgTracker) RequiresFinalization(destChain protocol.ChainSelector, seqNum protocol.SequenceNumber) bool {
	destSet, ok := t.reorgedSeqNums[destChain]
	if !ok {
		return false
	}
	_, exists := destSet[seqNum]
	return exists
}

// Remove removes a seqNum from tracking for the given destination.
// Called when a message with a reorged seqNum is finalized and sent for verification.
func (t *ReorgTracker) Remove(destChain protocol.ChainSelector, seqNum protocol.SequenceNumber) {
	destSet, ok := t.reorgedSeqNums[destChain]
	if !ok {
		return
	}

	if _, exists := destSet[seqNum]; !exists {
		return
	}

	delete(destSet, seqNum)

	newCount := len(destSet)
	if newCount == 0 {
		delete(t.reorgedSeqNums, destChain)
	}

	t.logger.Infow("Removed reorged sequence number from tracking",
		"destChain", destChain,
		"seqNum", seqNum,
		"trackedCount", newCount,
	)

	t.metrics.With("destChain", strconv.FormatUint(uint64(destChain), 10)).
		RecordReorgTrackedSeqNums(context.Background(), int64(newCount))
}
