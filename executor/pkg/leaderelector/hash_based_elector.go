package leaderelector

import (
	"encoding/binary"
	"slices"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// HashBasedLeaderElector implements deterministic leader election based on message ID hash
// and executor position in a sorted list of executor IDs.
type HashBasedLeaderElector struct {
	executorIds       []string
	thisExecutorId    string
	executionInterval time.Duration
	minWaitPeriod     time.Duration
	executorIndex     int
}

// NewHashBasedLeaderElector creates a new hash-based leader elector.
func NewHashBasedLeaderElector(
	executorIds []string,
	thisExecutorId string,
	executionInterval time.Duration,
	minWaitPeriod time.Duration,
) *HashBasedLeaderElector {
	// Create a sorted copy of executor IDs for deterministic ordering
	sortedExecutorIds := make([]string, len(executorIds))
	copy(sortedExecutorIds, executorIds)
	slices.Sort(sortedExecutorIds)

	// Find this executor's position in the sorted array
	executorIndex := -1
	for i, id := range sortedExecutorIds {
		if id == thisExecutorId {
			executorIndex = i
			break
		}
	}

	return &HashBasedLeaderElector{
		executorIds:       sortedExecutorIds,
		thisExecutorId:    thisExecutorId,
		executionInterval: executionInterval,
		minWaitPeriod:     minWaitPeriod,
		executorIndex:     executorIndex,
	}
}

// GetReadyTimestamp implements the LeaderElector interface.
// It returns: baseTimestamp + (arrayIndex * executionInterval) + minWaitPeriod
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
	executorIndex := int64(hashValue % uint64(len(h.executorIds)))

	// Calculate ready timestamp: baseTimestamp + (arrayIndex * executionInterval) + minWaitPeriod
	delaySeconds := executorIndex*int64(h.executionInterval.Seconds()) + int64(h.minWaitPeriod.Seconds())

	return baseTimestamp + delaySeconds
}
