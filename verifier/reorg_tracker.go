package verifier

import "github.com/smartcontractkit/chainlink-ccv/protocol"

// ReorgTracker tracks sequence numbers that were affected by shallow reorgs.
// Messages with tracked seqNums must wait for full finalization before verification,
// ignoring any custom "faster-than-finality" settings.
//
// Tracking is per destination chain since sequence numbers are scoped by (source, dest) lane.
type ReorgTracker struct {
	reorgedSeqNums map[protocol.ChainSelector]map[protocol.SequenceNumber]struct{}
}

func NewReorgTracker() *ReorgTracker {
	return &ReorgTracker{
		reorgedSeqNums: make(map[protocol.ChainSelector]map[protocol.SequenceNumber]struct{}),
	}
}

// Track adds a reorged seqNum for a specific destination lane.
// Called when a message's messageID disappears from query results (indicating reorg).
func (t *ReorgTracker) Track(destChain protocol.ChainSelector, seqNum protocol.SequenceNumber) {
	if t.reorgedSeqNums[destChain] == nil {
		t.reorgedSeqNums[destChain] = make(map[protocol.SequenceNumber]struct{})
	}
	t.reorgedSeqNums[destChain][seqNum] = struct{}{}
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
	delete(destSet, seqNum)
	if len(destSet) == 0 {
		delete(t.reorgedSeqNums, destChain)
	}
}
