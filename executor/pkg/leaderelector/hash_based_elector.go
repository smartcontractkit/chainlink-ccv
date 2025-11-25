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
	lggr               logger.Logger
	executorIDs        map[protocol.ChainSelector][]string
	thisExecutorID     string
	executionIntervals map[protocol.ChainSelector]time.Duration
	executorIndices    map[protocol.ChainSelector]int
}

// NewHashBasedLeaderElector creates a new hash-based leader elector.
// This component is used to determine the turn order for node executions based on chain selector and messageID.
// We consider the chain selector here because not all executors will support all destination chains.
func NewHashBasedLeaderElector(
	lggr logger.Logger,
	executorIDs map[protocol.ChainSelector][]string,
	thisExecutorID string,
	executionIntervals map[protocol.ChainSelector]time.Duration,
) *HashBasedLeaderElector {
	// Create a sorted copy of executor IDs for deterministic ordering
	sortedExecutorIDs := make(map[protocol.ChainSelector][]string, len(executorIDs))
	executorIndices := make(map[protocol.ChainSelector]int, len(executorIDs))
	for chainSel, ids := range executorIDs {
		sortedExecutorIDs[chainSel] = make([]string, len(ids))
		copy(sortedExecutorIDs[chainSel], ids)
		slices.Sort(sortedExecutorIDs[chainSel])

		// Find this executor's position in the sorted array
		executorIndices[chainSel] = slices.Index(sortedExecutorIDs[chainSel], thisExecutorID)
	}

	return &HashBasedLeaderElector{
		lggr:               lggr,
		executorIDs:        sortedExecutorIDs,
		thisExecutorID:     thisExecutorID,
		executionIntervals: executionIntervals,
		executorIndices:    executorIndices,
	}
}

// GetReadyTimestamp implements the LeaderElector interface.
// It returns: baseTimestamp + (arrayIndex * executionInterval).
// TODO: Support using time.Time instead of int64 for checking timestamps.
func (h *HashBasedLeaderElector) GetReadyTimestamp(
	messageID protocol.Bytes32,
	chainSel protocol.ChainSelector,
	baseTimestamp int64,
) int64 {
	execIndex := h.executorIndices[chainSel]
	execPool := h.executorIDs[chainSel]
	if execIndex == -1 {
		// This executor is not in the list, should not happen if config is validated
		return baseTimestamp
	}

	// Convert first 8 bytes of hash to uint64 for consistent ordering
	// todo: Use a real sha256 hash based on messsageID and node set
	hashValue := binary.BigEndian.Uint64(messageID[:8])

	// Calculate position in execution order for this message
	// This creates a message-specific ordering of executors
	startIndex := int(hashValue % uint64(len(execPool))) //nolint:gosec // G115: modulo will result in positive

	// todo: this will result in a static relative order, we can remap against the sorted array if necessary
	delayMultiplier := getSliceIncreasingDistance(len(execPool), startIndex, execIndex)

	// Calculate ready timestamp: baseTimestamp + (arrayIndex * executionInterval)
	delaySeconds := delayMultiplier * int64(h.executionIntervals[chainSel].Seconds())

	h.lggr.Debugf("messageID %s using delay of indexDistance(%d) * executionMultipler(%s) = %d seconds", messageID.String(), delayMultiplier, h.executionIntervals[chainSel], delaySeconds)
	// todo: base timestamp comes from the indexer, is it safe to use here?
	return baseTimestamp + delaySeconds
}

func getSliceIncreasingDistance(sliceLen, startIndex, selectedIndex int) int64 {
	// invalid inputs, return 0
	if sliceLen <= 0 ||
		startIndex < 0 || startIndex >= sliceLen ||
		selectedIndex < 0 || selectedIndex >= sliceLen {
		return 0
	}

	// calculate distance in a circular manner
	if selectedIndex == startIndex {
		return 0
	} else if selectedIndex < startIndex {
		// if selectedIndex is lower, we cycle
		return int64(sliceLen - startIndex + selectedIndex)
	}
	return int64(selectedIndex - startIndex)
}

func (h *HashBasedLeaderElector) GetRetryDelay(sel protocol.ChainSelector) int64 {
	return int64(len(h.executorIDs[sel])) * int64(h.executionIntervals[sel].Seconds())
}
