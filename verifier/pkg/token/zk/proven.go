package zk

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"
)

// ProvenBlockReader reads the light client of one lane on the destination chain.
// The implementation is chosen by the chain family of the destination chain.
type ProvenBlockReader interface {
	// LatestProvenBlockNumber returns the highest source block number the light client has proven.
	LatestProvenBlockNumber(ctx context.Context) (uint64, error)
	// ProvenBlockHashes returns the hash the light client holds for every source block from first to last,
	// both included. A zero hash means the block is not proven.
	ProvenBlockHashes(ctx context.Context, first, last uint64) ([]common.Hash, error)
}

const sp1HeliosABI = `[
	{"type":"function","name":"latestExecutionBlockNumber","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
	{"type":"function","name":"executionBlockHashes","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"bytes32"}]}
]`

var sp1Helios = mustParseABI(sp1HeliosABI)

// EVMProvenBlockReader reads an SP1Helios contract over JSON-RPC.
type EVMProvenBlockReader struct {
	client      *rpc.Client
	lightClient common.Address
}

func NewEVMProvenBlockReader(client *rpc.Client, lightClient common.Address) *EVMProvenBlockReader {
	return &EVMProvenBlockReader{client: client, lightClient: lightClient}
}

func (r *EVMProvenBlockReader) LatestProvenBlockNumber(ctx context.Context) (uint64, error) {
	data, err := sp1Helios.Pack("latestExecutionBlockNumber")
	if err != nil {
		return 0, fmt.Errorf("failed to pack latestExecutionBlockNumber: %w", err)
	}

	var out hexutil.Bytes
	if err := r.client.CallContext(ctx, &out, "eth_call", r.callArgs(data), "latest"); err != nil {
		return 0, fmt.Errorf("failed to call latestExecutionBlockNumber: %w", err)
	}

	values, err := sp1Helios.Unpack("latestExecutionBlockNumber", out)
	if err != nil {
		return 0, fmt.Errorf("failed to unpack latestExecutionBlockNumber: %w", err)
	}
	number, ok := values[0].(*big.Int)
	if !ok || !number.IsUint64() {
		return 0, fmt.Errorf("latestExecutionBlockNumber returned %v, expected a uint64", values[0])
	}
	return number.Uint64(), nil
}

func (r *EVMProvenBlockReader) ProvenBlockHashes(ctx context.Context, first, last uint64) ([]common.Hash, error) {
	if last < first {
		return nil, fmt.Errorf("invalid block range %d to %d", first, last)
	}

	count := last - first + 1
	outs := make([]hexutil.Bytes, count)
	batch := make([]rpc.BatchElem, 0, count)
	for i := range count {
		data, err := sp1Helios.Pack("executionBlockHashes", new(big.Int).SetUint64(first+i))
		if err != nil {
			return nil, fmt.Errorf("failed to pack executionBlockHashes: %w", err)
		}
		batch = append(batch, rpc.BatchElem{
			Method: "eth_call",
			Args:   []any{r.callArgs(data), "latest"},
			Result: &outs[i],
		})
	}
	if err := r.client.BatchCallContext(ctx, batch); err != nil {
		return nil, fmt.Errorf("failed to call executionBlockHashes: %w", err)
	}

	hashes := make([]common.Hash, count)
	for i, elem := range batch {
		if elem.Error != nil {
			return nil, fmt.Errorf("failed to call executionBlockHashes(%d): %w", first+uint64(i), elem.Error)
		}
		if len(outs[i]) != common.HashLength {
			return nil, fmt.Errorf("executionBlockHashes(%d) returned %d bytes, expected %d", first+uint64(i), len(outs[i]), common.HashLength)
		}
		hashes[i] = common.BytesToHash(outs[i])
	}
	return hashes, nil
}

func (r *EVMProvenBlockReader) callArgs(data []byte) map[string]any {
	return map[string]any{"to": r.lightClient, "data": hexutil.Bytes(data)}
}

func mustParseABI(s string) abi.ABI {
	parsed, err := abi.JSON(strings.NewReader(s))
	if err != nil {
		panic(fmt.Sprintf("failed to parse ABI: %v", err))
	}
	return parsed
}
