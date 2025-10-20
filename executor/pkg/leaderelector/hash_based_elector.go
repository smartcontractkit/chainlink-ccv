package leaderelector

import (
	"encoding/binary"
	"slices"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// HashBasedLeaderElector implements deterministic leader election based on message ID hash
// and executor position in a sorted list of executor IDs.
type HashBasedLeaderElector struct {
	lggr              logger.Logger
	executorIDs       []string
	thisExecutorID    string
	executionInterval time.Duration
	minWaitPeriod     time.Duration
	executorIndex     int
}

// NewHashBasedLeaderElector creates a new hash-based leader elector.
func NewHashBasedLeaderElector(
	lggr logger.Logger,
	executorIDs []string,
	thisExecutorID string,
	executionInterval time.Duration,
	minWaitPeriod time.Duration,
) *HashBasedLeaderElector {
	// Create a sorted copy of executor IDs for deterministic ordering
	sortedExecutorIDs := make([]string, len(executorIDs))
	copy(sortedExecutorIDs, executorIDs)
	slices.Sort(sortedExecutorIDs)

	// Find this executor's position in the sorted array
	executorIndex := -1
	for i, id := range sortedExecutorIDs {
		if id == thisExecutorID {
			executorIndex = i
			break
		}
	}

	return &HashBasedLeaderElector{
		lggr:              lggr,
		executorIDs:       sortedExecutorIDs,
		thisExecutorID:    thisExecutorID,
		executionInterval: executionInterval,
		minWaitPeriod:     minWaitPeriod,
		executorIndex:     executorIndex,
	}
}

// GetReadyTimestamp implements the LeaderElector interface.
// It returns: baseTimestamp + (arrayIndex * executionInterval) + minWaitPeriod.
func (h *HashBasedLeaderElector) GetReadyTimestamp(
	messageID protocol.Bytes32,
	baseTimestamp int64,
) int64 {
	if h.executorIndex == -1 {
		// This executor is not in the list, should not happen if config is validated
		return baseTimestamp + int64(h.minWaitPeriod.Seconds())
	}

	// Convert first 8 bytes of hash to uint64 for consistent ordering
	hashValue := binary.BigEndian.Uint64(messageID[:8])

	// Calculate position in execution order for this message
	// This creates a message-specific ordering of executors
	startIndex := int(hashValue % uint64(len(h.executorIDs))) //nolint:gosec // G115: modulo will result in positive

	delayMultiplier := getSliceIncreasingDistance(len(h.executorIDs), startIndex, h.executorIndex)

	// Calculate ready timestamp: baseTimestamp + (arrayIndex * executionInterval) + minWaitPeriod
	delaySeconds := delayMultiplier*int64(h.executionInterval.Seconds()) + int64(h.minWaitPeriod.Seconds())

	h.lggr.Debugf("using delay of minWait(%d) + indexDistance(%d) * executionMultipler(%s) = %d seconds", h.minWaitPeriod, delayMultiplier, h.executionInterval, delaySeconds)
	return baseTimestamp + delaySeconds
}

func getSliceIncreasingDistance(sliceLen, startIndex, selectedIndex int) int64 {
	if sliceLen == 0 {
		return 0
	}
	if sliceLen < 0 {
		return 0
	}
	if startIndex < 0 || startIndex >= sliceLen {
		return 0
	}
	if selectedIndex < 0 || selectedIndex >= sliceLen {
		return 0
	}

	if selectedIndex == startIndex {
		return 0
	} else if selectedIndex < startIndex {
		// if selectedIndex is lower, we cycle
		return int64(sliceLen - startIndex + selectedIndex)
	}
	return int64(selectedIndex - startIndex)
}
