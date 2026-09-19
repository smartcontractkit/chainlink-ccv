package zk

import (
	"context"
	"math/big"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// SourceProofReader reads the raw block data the witness needs from an EVM source chain.
type SourceProofReader interface {
	// HeaderByNumber returns the header of the block.
	HeaderByNumber(ctx context.Context, number uint64) (*types.Header, error)
	// BlockReceipts returns every receipt of the block in transaction order.
	BlockReceipts(ctx context.Context, number uint64) (types.Receipts, error)
}

// EVMSourceProofReader reads block data over JSON-RPC.
type EVMSourceProofReader struct {
	client *ethclient.Client
}

func NewEVMSourceProofReader(client *ethclient.Client) *EVMSourceProofReader {
	return &EVMSourceProofReader{client: client}
}

func (r *EVMSourceProofReader) HeaderByNumber(ctx context.Context, number uint64) (*types.Header, error) {
	return r.client.HeaderByNumber(ctx, new(big.Int).SetUint64(number))
}

func (r *EVMSourceProofReader) BlockReceipts(ctx context.Context, number uint64) (types.Receipts, error) {
	//nolint:gosec // G115: block numbers fit in int64
	return r.client.BlockReceipts(ctx, rpc.BlockNumberOrHashWithNumber(rpc.BlockNumber(number)))
}
