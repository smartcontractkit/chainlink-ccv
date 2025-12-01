package chainaccess

import (
	"context"
	"math/big"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type Provider struct {
	SourceReader SourceReader

	// TODO: Unused? The filter is created by the verification coordinator directly.
	// MessageFilter

	// TODO: add Executor interfaces
	// TxManager    txmgr.TxManager
}

// HeadTracker provides access to the latest blockchain head information.
// This interface is responsible for tracking the current and finalized block states.
//
// =================================================================================
// THIS MUST TAKE INTO CONSIDERATION FINALITY TAGS / FINALITY DEPTH.
// =================================================================================
// Reorg detection relies on accurate finalized block info and abstracts away chain-specific details by using this interface.
//
// The recommendation is to use HeadTracker implementations from each chain, e.g. chainlink-evm/pkg/heads.
// Thread-safety: All methods must be safe for concurrent calls.
type HeadTracker interface {
	// LatestAndFinalizedBlock returns the latest and finalized block headers in a single call.
	// This is more efficient than separate RPC calls and provides complete block information
	// including hashes, parent hashes, and timestamps needed for reorg detection.
	LatestAndFinalizedBlock(ctx context.Context) (latest, finalized *protocol.BlockHeader, err error)
}

// SourceReader defines the interface for reading CCIP message events from source chains.
// This interface abstracts polling-based access to blockchain data and provides
// the foundation for chain-agnostic message reading.
//
// Thread-safety: All methods must be safe for concurrent calls.
type SourceReader interface {
	// FetchMessageSentEvents returns MessageSentEvents in the given block range.
	// The toBlock parameter can be nil to query up to the latest block.
	FetchMessageSentEvents(ctx context.Context, fromBlock, toBlock *big.Int) ([]protocol.MessageSentEvent, error)

	// GetBlocksHeaders returns the full block headers for a batch of block numbers.
	// This is more efficient than individual calls when building the chain tail.
	// Returns error if any block doesn't exist or RPC call fails.
	GetBlocksHeaders(ctx context.Context, blockNumber []*big.Int) (map[*big.Int]protocol.BlockHeader, error)

	// HeadTracker Embed HeadTracker for blockchain head tracking functionality.
	HeadTracker

	// RMNCurseReader Embed RMNCurseReader for curse detection functionality.
	RMNCurseReader
}

// RMNCurseReader provides read-only access to RMN Remote curse state.
// Both SourceReader and DestinationReader implement this interface.
type RMNCurseReader interface {
	// GetRMNCursedSubjects queries the configured RMN Remote contract.
	// Returns cursed subjects as bytes16, which can be:
	// - Global curse constant (0x0100000000000000000000000000000001)
	// - Chain selectors as bytes16s
	GetRMNCursedSubjects(ctx context.Context) ([]protocol.Bytes16, error)
}

// MessageFilter defines an interface for filtering protocol.MessageSentEvent.
type MessageFilter interface {
	// Filter returns true if the given MessageSentEvent should be processed, false to skip it.
	Filter(msg protocol.MessageSentEvent) bool
}
