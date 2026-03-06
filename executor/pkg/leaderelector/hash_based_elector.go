package leaderelector

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// Ensure HashBasedLeaderElector implements the LeaderElector interface.
var _ executor.LeaderElector = &HashBasedLeaderElector{}

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
) (*HashBasedLeaderElector, error) {
	if err := validateElectorInputs(executorIDs, thisExecutorID, executionIntervals); err != nil {
		return nil, err
	}

	sortedExecutorIDs := make(map[protocol.ChainSelector][]string, len(executorIDs))
	executorIndices := make(map[protocol.ChainSelector]int, len(executorIDs))
	for chainSel, ids := range executorIDs {
		sortedExecutorIDs[chainSel] = make([]string, len(ids))
		copy(sortedExecutorIDs[chainSel], ids)
		slices.Sort(sortedExecutorIDs[chainSel])
		executorIndices[chainSel] = slices.Index(sortedExecutorIDs[chainSel], thisExecutorID)
	}

	return &HashBasedLeaderElector{
		lggr:               lggr,
		executorIDs:        sortedExecutorIDs,
		thisExecutorID:     thisExecutorID,
		executionIntervals: executionIntervals,
		executorIndices:    executorIndices,
	}, nil
}

func validateElectorInputs(
	executorIDs map[protocol.ChainSelector][]string,
	thisExecutorID string,
	executionIntervals map[protocol.ChainSelector]time.Duration,
) error {
	var errs []error
	if thisExecutorID == "" {
		errs = append(errs, errors.New("this executor ID must not be empty"))
	}
	if len(executorIDs) == 0 {
		errs = append(errs, errors.New("executor IDs map must not be empty"))
	}
	for chainSel, ids := range executorIDs {
		if len(ids) == 0 {
			errs = append(errs, fmt.Errorf("executor pool for chain %d must not be empty", chainSel))
			continue
		}
		seen := make(map[string]struct{}, len(ids))
		for _, id := range ids {
			if _, ok := seen[id]; ok {
				errs = append(errs, fmt.Errorf("executor pool for chain %d contains duplicate ID %q", chainSel, id))
				break
			}
			seen[id] = struct{}{}
		}
		if !slices.Contains(ids, thisExecutorID) {
			errs = append(errs, fmt.Errorf("this executor ID %q not found in executor pool for chain %d", thisExecutorID, chainSel))
		}
		interval, ok := executionIntervals[chainSel]
		if !ok || interval <= 0 {
			errs = append(errs, fmt.Errorf("execution interval for chain %d must be positive", chainSel))
		}
	}
	for chainSel := range executionIntervals {
		if _, ok := executorIDs[chainSel]; !ok {
			errs = append(errs, fmt.Errorf("execution interval configured for unknown chain %d", chainSel))
		}
	}
	return errors.Join(errs...)
}

// GetReadyDelay implements the LeaderElector interface.
// It returns the delay from base time until this executor's turn: arrayIndex * executionInterval.
func (h *HashBasedLeaderElector) GetReadyDelay(
	messageID protocol.Bytes32,
	chainSel protocol.ChainSelector,
) (time.Duration, error) {
	execIndex, ok := h.executorIndices[chainSel]
	if !ok {
		return 0, fmt.Errorf("executor %q has no index for chain %d", h.thisExecutorID, chainSel)
	}
	execPool, hasPool := h.executorIDs[chainSel]
	if !hasPool || len(execPool) == 0 {
		return 0, fmt.Errorf("chain %d not configured in elector", chainSel)
	}
	interval, hasInterval := h.executionIntervals[chainSel]
	if !hasInterval || interval <= 0 {
		return 0, fmt.Errorf("execution interval for chain %d not configured or invalid", chainSel)
	}

	// Convert first 8 bytes of hash to uint64 for consistent ordering
	// todo: Use a real sha256 hash based on messsageID and node set
	hashValue := binary.BigEndian.Uint64(messageID[:8])

	// Calculate position in execution order for this message
	// This creates a message-specific ordering of executors
	startIndex := int(hashValue % uint64(len(execPool))) //nolint:gosec // G115: modulo will result in positive

	// todo: this will result in a static relative order, we can remap against the sorted array if necessary
	queueSize := getSliceIncreasingDistance(len(execPool), startIndex, execIndex)

	// Calculate time until our turn again (number of executors in queue * executionInterval)
	delay := time.Duration(queueSize) * interval

	h.lggr.Debugw("calculated ready delay",
		"messageID", messageID.String(),
		"queueSize", queueSize,
		"executionInterval", interval,
		"delay", delay.String())
	return delay, nil
}

func getSliceIncreasingDistance(sliceLen, startIndex, selectedIndex int) int {
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
		return sliceLen - startIndex + selectedIndex
	}
	return selectedIndex - startIndex
}

func (h *HashBasedLeaderElector) GetRetryDelay(sel protocol.ChainSelector) (time.Duration, error) {
	pool, ok := h.executorIDs[sel]
	if !ok || len(pool) == 0 {
		return 0, fmt.Errorf("chain %d not configured for retry delay", sel)
	}
	interval, ok := h.executionIntervals[sel]
	if !ok || interval <= 0 {
		return 0, fmt.Errorf("execution interval for chain %d not configured or invalid", sel)
	}
	return time.Duration(len(pool)) * interval, nil
}
