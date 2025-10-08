package verifier

import (
	"context"
	"math/big"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// MessageSigner defines the interface for signing messages using the new chain-agnostic format.
type MessageSigner interface {
	// SignMessage signs a message event and returns the signature
	SignMessage(ctx context.Context, verificationTask VerificationTask, sourceVerifierAddress protocol.UnknownAddress) ([]byte, error)

	// GetSignerAddress returns the address of the signer
	GetSignerAddress() protocol.UnknownAddress
}

// SourceReader defines the interface for reading CCIP messages from source chains.
type SourceReader interface {
	// VerificationTasks returns tasks in the given block range
	VerificationTasks(ctx context.Context, fromBlock, toBlock *big.Int) ([]VerificationTask, error)

	// BlockTime returns the timestamp of a given block.
	BlockTime(ctx context.Context, block *big.Int) (uint64, error)

	// LatestBlockHeight returns the latest block height
	LatestBlockHeight(ctx context.Context) (*big.Int, error)

	// LatestFinalizedBlockHeight returns the latest finalized block height
	LatestFinalizedBlockHeight(ctx context.Context) (*big.Int, error)
}
