package chainaccess

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// HeadTracker provides access to the latest blockchain head information.
// This interface is responsible for tracking the current, finalized, and safe block states. This should take into consideration finality tags where possible.
//
// Thread-safety: All methods must be safe for concurrent calls.
type HeadTracker interface {
	// LatestAndFinalizedBlock returns the latest and finalized block headers in a single call.
	// This is more efficient than separate RPC calls and provides complete block information
	// including hashes, parent hashes, and timestamps needed for reorg detection.
	LatestAndFinalizedBlock(ctx context.Context) (latest, finalized *protocol.BlockHeader, err error)

	// LatestSafeBlock returns the latest safe block header.
	// Safe block is an intermediate safety level between latest and finalized.
	// Returns nil if the chain doesn't support safe blocks (optional feature).
	LatestSafeBlock(ctx context.Context) (safe *protocol.BlockHeader, err error)
}
