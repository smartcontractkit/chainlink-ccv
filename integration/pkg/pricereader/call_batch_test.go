package pricereader

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/stretchr/testify/require"
)

// fakeBatchClient answers an eth_call with the first byte of its data. It fails the calls to the failing address.
type fakeBatchClient struct {
	batches  [][]rpc.BatchElem
	batchErr error
	failing  map[common.Address]error
}

func (f *fakeBatchClient) BatchCallContext(_ context.Context, batch []rpc.BatchElem) error {
	f.batches = append(f.batches, batch)
	if f.batchErr != nil {
		return f.batchErr
	}
	for i := range batch {
		params := batch[i].Args[0].(map[string]any)
		if err, ok := f.failing[params["to"].(common.Address)]; ok {
			batch[i].Error = err
			continue
		}
		*batch[i].Result.(*hexutil.Bytes) = hexutil.Bytes{params["data"].(hexutil.Bytes)[0]}
	}
	return nil
}

func (f *fakeBatchClient) CodeAt(context.Context, common.Address, *big.Int) ([]byte, error) {
	return []byte{1}, nil
}

func (f *fakeBatchClient) LatestBlockHeight(context.Context) (*big.Int, error) {
	return big.NewInt(7), nil
}

// call acts like a binding: one CallContract, then the decoded result.
func call(b *callBatch, to common.Address, data byte, block *big.Int, out *byte) func() error {
	return func() error {
		result, err := b.CallContract(context.Background(), ethereum.CallMsg{To: &to, Data: []byte{data}}, block)
		if err != nil {
			return err
		}
		*out = result[0]
		return nil
	}
}

func TestCallBatchSendsAllCallsInOneBatchInOrder(t *testing.T) {
	client := &fakeBatchClient{}
	b := newCallBatch(client)
	to := common.HexToAddress("0x1")
	results := make([]byte, 5)
	for i := range results {
		b.add("call", call(b, to, byte(i+1), nil, &results[i]))
	}

	require.NoError(t, b.send(context.Background()))
	require.Len(t, client.batches, 1)
	require.Len(t, client.batches[0], len(results))
	for i, result := range results {
		require.Equal(t, byte(i+1), result)
		require.Equal(t, "latest", client.batches[0][i].Args[1])
	}
}

func TestCallBatchPinsTheBlockNumber(t *testing.T) {
	client := &fakeBatchClient{}
	b := newCallBatch(client)
	var out byte
	b.add("call", call(b, common.HexToAddress("0x1"), 1, big.NewInt(300), &out))

	require.NoError(t, b.send(context.Background()))
	require.Equal(t, "0x12c", client.batches[0][0].Args[1])
}

func TestCallBatchWithoutCallsSendsNothing(t *testing.T) {
	client := &fakeBatchClient{}

	require.NoError(t, newCallBatch(client).send(context.Background()))
	require.Empty(t, client.batches)
}

func TestCallBatchReturnsTheElementErrorWithTheCallName(t *testing.T) {
	broken := common.HexToAddress("0xbad")
	reverted := errors.New("execution reverted")
	client := &fakeBatchClient{failing: map[common.Address]error{broken: reverted}}
	b := newCallBatch(client)
	var a, c byte
	b.add("good", call(b, common.HexToAddress("0x1"), 1, nil, &a))
	b.add("broken", call(b, broken, 2, nil, &c))

	err := b.send(context.Background())
	require.ErrorIs(t, err, reverted)
	require.ErrorContains(t, err, "broken")
}

func TestCallBatchReturnsTheBatchError(t *testing.T) {
	down := errors.New("rpc down")
	b := newCallBatch(&fakeBatchClient{batchErr: down})
	var out byte
	b.add("call", call(b, common.HexToAddress("0x1"), 1, nil, &out))

	require.ErrorIs(t, b.send(context.Background()), down)
}

func TestCallBatchRejectsACallThatDoesNotRecord(t *testing.T) {
	client := &fakeBatchClient{}
	b := newCallBatch(client)
	packErr := errors.New("cannot pack")
	var out byte
	b.add("no call", func() error { return nil })
	b.add("pack error", func() error { return packErr })
	b.add("good", call(b, common.HexToAddress("0x1"), 1, nil, &out))

	err := b.send(context.Background())
	require.ErrorContains(t, err, "no call: made no call")
	require.Empty(t, client.batches, "a broken batch is not sent")

	b = newCallBatch(client)
	b.add("pack error", func() error { return packErr })
	require.ErrorIs(t, b.send(context.Background()), packErr)
}

func TestCallBatchRejectsACallWithoutDestination(t *testing.T) {
	b := newCallBatch(&fakeBatchClient{})
	b.add("no destination", func() error {
		_, err := b.CallContract(context.Background(), ethereum.CallMsg{}, nil)
		return err
	})

	require.ErrorContains(t, b.send(context.Background()), "destination address")
}
