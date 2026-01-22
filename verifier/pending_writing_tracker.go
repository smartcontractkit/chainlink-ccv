package verifier

import (
	"math"
	"sync"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// chainPendingState tracks pending writes for a single chain.
type chainPendingState struct {
	mu   sync.RWMutex
	lggr logger.Logger

	chain protocol.ChainSelector

	// finalizedBlock -> set of messageIDs
	byFinalized map[uint64]map[string]struct{}

	// Last checkpoint written (avoid redundant writes)
	lastCheckpoint uint64
}

func newChainPendingState(lggr logger.Logger, chain protocol.ChainSelector) *chainPendingState {
	return &chainPendingState{
		lggr:        lggr,
		chain:       chain,
		byFinalized: make(map[uint64]map[string]struct{}),
	}
}

func (c *chainPendingState) add(msgID string, finalizedBlock uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if message already tracked (deduplication)
	for _, msgSet := range c.byFinalized {
		if _, exists := msgSet[msgID]; exists {
			c.lggr.Debugw("Message already tracked, skipping duplicate add",
				"chain", c.chain,
				"msgID", msgID,
				"finalizedBlock", finalizedBlock)
			return
		}
	}

	if c.byFinalized[finalizedBlock] == nil {
		c.byFinalized[finalizedBlock] = make(map[string]struct{})
	}
	c.byFinalized[finalizedBlock][msgID] = struct{}{}

	c.lggr.Debugw("Message added to pending tracker",
		"chain", c.chain,
		"msgID", msgID,
		"finalizedBlock", finalizedBlock,
		"totalPendingLevels", len(c.byFinalized))
}

func (c *chainPendingState) remove(msgID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Search through all finalized blocks to find and remove the message
	for finalizedBlock, msgSet := range c.byFinalized {
		if _, exists := msgSet[msgID]; exists {
			delete(msgSet, msgID)
			levelCleared := len(msgSet) == 0
			if levelCleared {
				delete(c.byFinalized, finalizedBlock)
			}

			c.lggr.Debugw("Message removed from pending tracker",
				"chain", c.chain,
				"msgID", msgID,
				"finalizedBlock", finalizedBlock,
				"levelCleared", levelCleared,
				"totalPendingLevels", len(c.byFinalized))
			return
		}
	}

	// Message not found - this can happen for retried messages or reorgs
	c.lggr.Debugw("Message not found in pending tracker during remove",
		"chain", c.chain,
		"msgID", msgID)
}

func (c *chainPendingState) checkpointIfAdvanced() (uint64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.byFinalized) == 0 {
		c.lggr.Debugw("No pending messages, skipping checkpoint",
			"chain", c.chain,
			"lastCheckpoint", c.lastCheckpoint)
		return 0, false
	}

	// Find minimum pending level
	minLevel := uint64(math.MaxUint64)
	for level := range c.byFinalized {
		if level < minLevel {
			minLevel = level
		}
	}

	checkpoint := minLevel - 1
	if checkpoint <= c.lastCheckpoint {
		c.lggr.Debugw("Checkpoint has not advanced, skipping write",
			"chain", c.chain,
			"currentCheckpoint", checkpoint,
			"lastCheckpoint", c.lastCheckpoint,
			"minPendingLevel", minLevel,
			"totalPendingLevels", len(c.byFinalized))
		return 0, false
	}

	c.lggr.Infow("Checkpoint advanced",
		"chain", c.chain,
		"previousCheckpoint", c.lastCheckpoint,
		"newCheckpoint", checkpoint,
		"minPendingLevel", minLevel,
		"totalPendingLevels", len(c.byFinalized))

	c.lastCheckpoint = checkpoint
	return checkpoint, true
}

// PendingWritingTracker is shared between SRS, TVP, and SWP.
// It tracks messages that have been read but not yet successfully written to storage.
// This enables safe checkpoint management: checkpoints only advance once all messages
// at a given finalized block level have been written.
//
// Uses sync.Map for lock-free chain state lookup, eliminating contention between chains.
type PendingWritingTracker struct {
	lggr logger.Logger

	// chainState maps ChainSelector -> *chainPendingState
	// Using sync.Map eliminates lock contention for chain lookups
	chainState sync.Map
}

// NewPendingWritingTracker creates a new PendingWritingTracker instance.
func NewPendingWritingTracker(lggr logger.Logger) *PendingWritingTracker {
	return &PendingWritingTracker{
		lggr: logger.With(lggr, "component", "PendingWritingTracker"),
	}
}

func (t *PendingWritingTracker) getOrCreate(chain protocol.ChainSelector) *chainPendingState {
	// Fast path: load existing state
	if state, exists := t.chainState.Load(chain); exists {
		if chainState, ok := state.(*chainPendingState); ok {
			return chainState
		}
	}

	// Slow path: create new state
	// LoadOrStore handles race conditions automatically
	state := newChainPendingState(t.lggr, chain)
	actual, _ := t.chainState.LoadOrStore(chain, state)
	if chainState, ok := actual.(*chainPendingState); ok {
		return chainState
	}
	// Type assertion failed - return the newly created state as fallback
	return state
}

// Add tracks a message as pending for writing.
// This should be called when a message is first read from the chain.
// The operation is idempotent - adding the same msgID multiple times is safe.
func (t *PendingWritingTracker) Add(chain protocol.ChainSelector, msgID string, finalizedBlock uint64) {
	t.getOrCreate(chain).add(msgID, finalizedBlock)
}

// Remove stops tracking a message, indicating it has been written or dropped.
// This should be called when:
// - A message is successfully written to storage (SWP)
// - A message is reorged out (SRS)
// - A message fails verification with unretryable error (TVP).
func (t *PendingWritingTracker) Remove(chain protocol.ChainSelector, msgID string) {
	t.getOrCreate(chain).remove(msgID)
}

// CheckpointIfAdvanced computes the safe checkpoint for a chain.
// Returns (checkpoint, true) if the checkpoint has advanced since last call.
// Returns (0, false) if no checkpoint update is needed.
//
// The checkpoint is computed as minPendingFinalizedBlock - 1, ensuring we never
// checkpoint past a block that still has pending writes.
func (t *PendingWritingTracker) CheckpointIfAdvanced(chain protocol.ChainSelector) (uint64, bool) {
	return t.getOrCreate(chain).checkpointIfAdvanced()
}
