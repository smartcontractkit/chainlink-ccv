package pricereader

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"
)

// batchClient is the part of the chain client that the Fee Quoter reader needs.
type batchClient interface {
	BatchCallContext(ctx context.Context, b []rpc.BatchElem) error
	CodeAt(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error)
	LatestBlockHeight(ctx context.Context) (*big.Int, error)
}

// errRecorded stops a binding call after the batch has recorded its eth_call.
var errRecorded = errors.New("call recorded for the batch")

// callBatch sends binding calls in one RPC batch. It is the bind.ContractCaller of the bindings.
// Each added call runs twice: once to record its eth_call, and again after the batch to decode the result.
type callBatch struct {
	client batchClient
	names  []string
	calls  []func() error
	elems  []rpc.BatchElem
	// results has the result of each element.
	results []*hexutil.Bytes
	// replay is the index of the call that decodes, or -1 while the calls are recorded.
	replay int
	err    error
}

var _ bind.ContractCaller = (*callBatch)(nil)

func newCallBatch(client batchClient) *callBatch {
	return &callBatch{client: client, replay: -1}
}

// add records the eth_call of call. The call must make exactly one binding call on this batch.
func (b *callBatch) add(name string, call func() error) {
	if b.err != nil {
		return
	}
	if err := call(); !errors.Is(err, errRecorded) {
		if err == nil {
			err = errors.New("made no call")
		}
		b.err = fmt.Errorf("%s: %w", name, err)
		return
	}
	b.names = append(b.names, name)
	b.calls = append(b.calls, call)
}

// send sends all calls in one RPC batch and decodes the results. It fails on the first failed call.
func (b *callBatch) send(ctx context.Context) error {
	callErrs, err := b.sendEach(ctx)
	if err != nil {
		return err
	}
	for i, callErr := range callErrs {
		if callErr != nil {
			return fmt.Errorf("%s: %w", b.names[i], callErr)
		}
	}
	return nil
}

// sendEach sends all calls in one RPC batch and decodes the results. It returns the error of each call,
// and fails only when the batch as a whole cannot be sent.
func (b *callBatch) sendEach(ctx context.Context) ([]error, error) {
	if b.err != nil {
		return nil, b.err
	}
	if len(b.elems) == 0 {
		return nil, nil
	}
	if err := b.client.BatchCallContext(ctx, b.elems); err != nil {
		return nil, fmt.Errorf("batch call failed: %w", err)
	}
	callErrs := make([]error, len(b.elems))
	for i := range b.elems {
		if b.elems[i].Error != nil {
			callErrs[i] = b.elems[i].Error
			continue
		}
		b.replay = i
		callErrs[i] = b.calls[i]()
	}
	return callErrs, nil
}

// CallContract records the eth_call, or returns its result when the call decodes.
func (b *callBatch) CallContract(_ context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error) {
	if b.replay >= 0 {
		return *b.results[b.replay], nil
	}
	if msg.To == nil {
		return nil, errors.New("eth_call needs a destination address")
	}
	block := "latest"
	if blockNumber != nil {
		block = hexutil.EncodeBig(blockNumber)
	}
	result := new(hexutil.Bytes)
	params := map[string]any{"to": *msg.To, "data": hexutil.Bytes(msg.Data)}
	b.elems = append(b.elems, rpc.BatchElem{Method: "eth_call", Args: []any{params, block}, Result: result})
	b.results = append(b.results, result)
	return nil, errRecorded
}

// CodeAt is sent directly. A binding calls it only when a result is empty.
func (b *callBatch) CodeAt(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error) {
	return b.client.CodeAt(ctx, account, blockNumber)
}
