package zk

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/trie"
)

var (
	testOnRamp    = common.HexToAddress("0x8dcf17f298c881A547D91ca4aA3C2AD7568C6777")
	testMessageID = common.HexToHash("0x0101010101010101010101010101010101010101010101010101010101010101")
)

// testChain is a synthetic source chain: headers from firstBlock to lastBlock chained by parent hash, and the
// receipts of one message block. Transaction 1 of that block emits CCIPMessageSent as its second log.
type testChain struct {
	headers  map[uint64]*types.Header
	receipts map[uint64]types.Receipts
	message  SentMessage
}

func newTestChain(firstBlock, lastBlock, messageBlock uint64) *testChain {
	return newTestChainForMessage(firstBlock, lastBlock, messageBlock, testMessageID)
}

func newTestChainForMessage(firstBlock, lastBlock, messageBlock uint64, messageID common.Hash) *testChain {
	receipts := types.Receipts{
		testReceipt(0, nil),
		testReceipt(1, []*types.Log{
			{Address: testOnRamp, Topics: []common.Hash{common.HexToHash("0x03")}},
			{Address: testOnRamp, Topics: []common.Hash{CCIPMessageSentTopic, common.HexToHash("0x04"), common.HexToHash("0x05"), messageID}},
		}),
		testReceipt(2, nil),
	}
	chain := &testChain{
		headers:  make(map[uint64]*types.Header),
		receipts: map[uint64]types.Receipts{messageBlock: receipts},
		message: SentMessage{
			BlockNumber: messageBlock,
			OnRamp:      testOnRamp,
			MessageID:   messageID,
		},
	}

	parentHash := common.HexToHash("0x06")
	for number := firstBlock; number <= lastBlock; number++ {
		receiptsRoot := common.HexToHash("0x07")
		if number == messageBlock {
			receiptsRoot = types.DeriveSha(receipts, trie.NewStackTrie(nil))
		}
		header := testHeader(number, parentHash, receiptsRoot)
		chain.headers[number] = header
		parentHash = header.Hash()
	}
	return chain
}

func (c *testChain) hash(number uint64) common.Hash {
	return c.headers[number].Hash()
}

func (c *testChain) HeaderByNumber(_ context.Context, number uint64) (*types.Header, error) {
	header, ok := c.headers[number]
	if !ok {
		return nil, fmt.Errorf("header %d not found", number)
	}
	return header, nil
}

func (c *testChain) BlockReceipts(_ context.Context, number uint64) (types.Receipts, error) {
	receipts, ok := c.receipts[number]
	if !ok {
		return nil, fmt.Errorf("receipts of block %d not found", number)
	}
	return receipts, nil
}

// testLightClient is a fake light client that holds the given proven block hashes and records the ranges it is asked for.
type testLightClient struct {
	latest uint64
	hashes map[uint64]common.Hash
	ranges [][2]uint64
}

func newTestLightClient(chain *testChain, provenBlocks ...uint64) *testLightClient {
	client := &testLightClient{hashes: make(map[uint64]common.Hash)}
	for _, number := range provenBlocks {
		client.hashes[number] = chain.hash(number)
		client.latest = max(client.latest, number)
	}
	return client
}

func (l *testLightClient) LatestProvenBlockNumber(context.Context) (uint64, error) {
	return l.latest, nil
}

func (l *testLightClient) ProvenBlockHashes(_ context.Context, first, last uint64) ([]common.Hash, error) {
	l.ranges = append(l.ranges, [2]uint64{first, last})
	hashes := make([]common.Hash, 0, last-first+1)
	for number := first; number <= last; number++ {
		hashes = append(hashes, l.hashes[number])
	}
	return hashes, nil
}

func testHeader(number uint64, parentHash, receiptsRoot common.Hash) *types.Header {
	return &types.Header{
		ParentHash:       parentHash,
		UncleHash:        types.EmptyUncleHash,
		Root:             common.HexToHash("0x08"),
		TxHash:           types.EmptyTxsHash,
		ReceiptHash:      receiptsRoot,
		Difficulty:       new(big.Int),
		Number:           new(big.Int).SetUint64(number),
		GasLimit:         30_000_000,
		GasUsed:          21_000,
		Time:             1_700_000_000,
		BaseFee:          big.NewInt(1_000_000_000),
		WithdrawalsHash:  &types.EmptyWithdrawalsHash,
		BlobGasUsed:      new(uint64),
		ExcessBlobGas:    new(uint64),
		ParentBeaconRoot: &common.Hash{},
		RequestsHash:     &types.EmptyRequestsHash,
	}
}

func testReceipt(txIndex uint, logs []*types.Log) *types.Receipt {
	receipt := &types.Receipt{
		Type:              types.DynamicFeeTxType,
		Status:            types.ReceiptStatusSuccessful,
		CumulativeGasUsed: 21_000 * uint64(txIndex+1),
		Logs:              logs,
		TransactionIndex:  txIndex,
	}
	receipt.Bloom = types.CreateBloom(receipt)
	return receipt
}
