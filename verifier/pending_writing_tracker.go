package verifier

import (
	"math"
	"sync"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// chainPendingState tracks pending writes for a single chain
type chainPendingState struct {
	mu sync.RWMutex

	// finalizedBlock -> set of messageIDs
	byFinalized map[uint64]map[string]struct{}

	// Last checkpoint written (avoid redundant writes)
	lastCheckpoint uint64
}

func newChainPendingState() *chainPendingState {
	return &chainPendingState{
		byFinalized: make(map[uint64]map[string]struct{}),
	}
}

func (c *chainPendingState) add(msgID string, finalizedBlock uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, msgSet := range c.byFinalized {
		if _, exists := msgSet[msgID]; exists {
			return
		}
	}

	if c.byFinalized[finalizedBlock] == nil {
		c.byFinalized[finalizedBlock] = make(map[string]struct{})
	}
	c.byFinalized[finalizedBlock][msgID] = struct{}{}
}

func (c *chainPendingState) remove(msgID string, finalizedBlock uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if msgSet, ok := c.byFinalized[finalizedBlock]; ok {
		delete(msgSet, msgID)
		if len(msgSet) == 0 {
			delete(c.byFinalized, finalizedBlock)
		}
	}
}

func (c *chainPendingState) checkpointIfAdvanced() (uint64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.byFinalized) == 0 {
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
		return 0, false
	}

	c.lastCheckpoint = checkpoint
	return checkpoint, true
}

// PendingWritingTracker is shared between SRS, TVP, and SWP.
// It tracks messages that have been read but not yet successfully written to storage.
// This enables safe checkpoint management: checkpoints only advance once all messages
// at a given finalized block level have been written.
type PendingWritingTracker struct {
	chainStateMu sync.RWMutex
	chainState   map[protocol.ChainSelector]*chainPendingState
}

// NewPendingWritingTracker creates a new PendingWritingTracker instance.
func NewPendingWritingTracker() *PendingWritingTracker {
	return &PendingWritingTracker{
		chainState: make(map[protocol.ChainSelector]*chainPendingState),
	}
}

func (t *PendingWritingTracker) getOrCreate(chain protocol.ChainSelector) *chainPendingState {
	// Fast path: read lock
	t.chainStateMu.RLock()
	state, exists := t.chainState[chain]
	t.chainStateMu.RUnlock()

	if exists {
		return state
	}

	// Slow path: write lock to create
	t.chainStateMu.Lock()
	defer t.chainStateMu.Unlock()

	// Double-check after acquiring write lock
	if state, exists = t.chainState[chain]; exists {
		return state
	}

	state = newChainPendingState()
	t.chainState[chain] = state
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
// - A message fails verification with unretryable error (TVP)
func (t *PendingWritingTracker) Remove(chain protocol.ChainSelector, msgID string, finalizedBlock uint64) {
	t.getOrCreate(chain).remove(msgID, finalizedBlock)
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
