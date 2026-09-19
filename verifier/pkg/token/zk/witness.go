package zk

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

// provenBlockScanBatch is how many light client entries one batched RPC call reads. Public RPC endpoints reject
// larger batches, and the operator proves a block about every 32 source blocks, so most scans need one call.
const provenBlockScanBatch = 16

var (
	// errNotProven means the light client holds no block at or above the message block yet.
	errNotProven = errors.New("message block is not proven")

	witnessArguments = mustWitnessArguments()
)

// Witness is the payload SuccinctZKVerifier.verifyMessage decodes after the version tag.
// Field names match the Solidity struct so the ABI encoder can map them.
type Witness struct {
	// ProvenBlockNumber is the source block whose hash the light client holds.
	ProvenBlockNumber *big.Int
	// Headers are RLP block headers from the proven block down to the message block, both included.
	Headers [][]byte
	// TxIndex is the index of the transaction in the message block.
	TxIndex *big.Int
	// LogIndex is the index of the CCIPMessageSent log in the receipt.
	LogIndex *big.Int
	// ProofNodes are the receipts trie nodes from the root to the receipt, root first.
	ProofNodes [][]byte
}

// SentMessage locates one CCIPMessageSent event on the source chain.
type SentMessage struct {
	BlockNumber uint64
	OnRamp      common.Address
	MessageID   common.Hash
}

// BuildWitness builds the witness for one message from public source chain data and the light client state.
// The transaction index and the log index are located in the receipts the proof is built from, so the proven
// receipt is the one that holds the message.
func BuildWitness(
	ctx context.Context,
	source SourceProofReader,
	proven ProvenBlockReader,
	message SentMessage,
) (*Witness, error) {
	receipts, err := source.BlockReceipts(ctx, message.BlockNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch receipts of block %d: %w", message.BlockNumber, err)
	}
	txIndex, logIndex, err := messageSentLocation(receipts, message)
	if err != nil {
		return nil, err
	}

	provenNumber, provenHash, err := lowestProvenBlock(ctx, proven, message.BlockNumber)
	if err != nil {
		return nil, err
	}

	headers, receiptsRoot, err := headerChain(ctx, source, provenNumber, provenHash, message.BlockNumber)
	if err != nil {
		return nil, err
	}

	proofNodes, provenReceipt, err := receiptProof(receipts, receiptsRoot, txIndex)
	if err != nil {
		return nil, err
	}
	if err := checkProvenReceipt(provenReceipt, logIndex, message); err != nil {
		return nil, err
	}

	return &Witness{
		ProvenBlockNumber: new(big.Int).SetUint64(provenNumber),
		Headers:           headers,
		TxIndex:           new(big.Int).SetUint64(txIndex),
		LogIndex:          new(big.Int).SetUint64(logIndex),
		ProofNodes:        proofNodes,
	}, nil
}

// Encode returns the version tag followed by the ABI encoded witness.
func (w *Witness) Encode(verifierVersion []byte) ([]byte, error) {
	encoded, err := witnessArguments.Pack(*w)
	if err != nil {
		return nil, fmt.Errorf("failed to encode witness: %w", err)
	}
	return append(bytes.Clone(verifierVersion), encoded...), nil
}

// messageSentLocation returns the transaction index and the log index of the CCIPMessageSent log for the message.
func messageSentLocation(receipts types.Receipts, message SentMessage) (uint64, uint64, error) {
	for txIndex, receipt := range receipts {
		for logIndex, log := range receipt.Logs {
			if !isMessageSentLog(log, message) {
				continue
			}
			if receipt.Status != types.ReceiptStatusSuccessful {
				return 0, 0, fmt.Errorf("transaction %d of block %d emitted message %s but did not succeed", txIndex, message.BlockNumber, message.MessageID)
			}
			return uint64(txIndex), uint64(logIndex), nil
		}
	}
	return 0, 0, fmt.Errorf("block %d has no CCIPMessageSent log from %s for message %s", message.BlockNumber, message.OnRamp, message.MessageID)
}

func isMessageSentLog(log *types.Log, message SentMessage) bool {
	if log.Address != message.OnRamp || len(log.Topics) != messageSentTopicCount {
		return false
	}
	return log.Topics[0] == CCIPMessageSentTopic && log.Topics[messageIDTopicIndex] == message.MessageID
}

// checkProvenReceipt checks the receipt the proof proves the way the destination verifier does: it must have
// succeeded and its log at logIndex must be the CCIPMessageSent log of the message.
func checkProvenReceipt(encoded []byte, logIndex uint64, message SentMessage) error {
	var receipt types.Receipt
	if err := receipt.UnmarshalBinary(encoded); err != nil {
		return fmt.Errorf("proven receipt does not decode: %w", err)
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		return fmt.Errorf("proven receipt did not succeed")
	}
	if logIndex >= uint64(len(receipt.Logs)) {
		return fmt.Errorf("proven receipt has %d logs, log index is %d", len(receipt.Logs), logIndex)
	}
	if !isMessageSentLog(receipt.Logs[logIndex], message) {
		return fmt.Errorf("proven receipt log %d is not the CCIPMessageSent log of message %s", logIndex, message.MessageID)
	}
	return nil
}

// lowestProvenBlock returns the lowest proven block at or above the message block. The lowest one keeps the
// header chain short.
func lowestProvenBlock(
	ctx context.Context,
	proven ProvenBlockReader,
	blockNumber uint64,
) (uint64, common.Hash, error) {
	latest, err := proven.LatestProvenBlockNumber(ctx)
	if err != nil {
		return 0, common.Hash{}, fmt.Errorf("failed to read latest proven block: %w", err)
	}
	if latest < blockNumber {
		return 0, common.Hash{}, fmt.Errorf("%w: latest proven block %d, message block %d", errNotProven, latest, blockNumber)
	}

	for first := blockNumber; first <= latest; first += provenBlockScanBatch {
		end := min(first+provenBlockScanBatch-1, latest)
		hashes, err := proven.ProvenBlockHashes(ctx, first, end)
		if err != nil {
			return 0, common.Hash{}, fmt.Errorf("failed to read proven block hashes: %w", err)
		}
		if uint64(len(hashes)) != end-first+1 {
			return 0, common.Hash{}, fmt.Errorf("light client returned %d hashes for blocks %d to %d", len(hashes), first, end)
		}
		for i, hash := range hashes {
			if hash != (common.Hash{}) {
				return first + uint64(i), hash, nil
			}
		}
	}
	return 0, common.Hash{}, fmt.Errorf("light client holds no hash for its latest proven block %d", latest)
}

// headerChain fetches the headers from the proven block down to the message block and checks that each header
// hashes to the value the header above it, or the light client, commits to. It returns the RLP headers in that
// order and the receipts root of the message block.
func headerChain(
	ctx context.Context,
	source SourceProofReader,
	provenNumber uint64,
	provenHash common.Hash,
	blockNumber uint64,
) ([][]byte, common.Hash, error) {
	expected := provenHash
	headers := make([][]byte, 0, provenNumber-blockNumber+1)
	var receiptsRoot common.Hash
	for number := provenNumber; ; number-- {
		header, err := source.HeaderByNumber(ctx, number)
		if err != nil {
			return nil, common.Hash{}, fmt.Errorf("failed to fetch header %d: %w", number, err)
		}
		if hash := header.Hash(); hash != expected {
			return nil, common.Hash{}, fmt.Errorf("header %d hashes to %s, expected %s", number, hash, expected)
		}
		encoded, err := rlp.EncodeToBytes(header)
		if err != nil {
			return nil, common.Hash{}, fmt.Errorf("failed to encode header %d: %w", number, err)
		}
		headers = append(headers, encoded)
		expected = header.ParentHash
		receiptsRoot = header.ReceiptHash
		if number == blockNumber {
			return headers, receiptsRoot, nil
		}
	}
}

// receiptProof rebuilds the receipts trie of the block and returns the proof nodes for the receipt at txIndex
// together with the receipt bytes the proof proves. There is no RPC that serves receipt proofs, so the trie is
// rebuilt from all receipts of the block.
func receiptProof(receipts types.Receipts, receiptsRoot common.Hash, txIndex uint64) ([][]byte, []byte, error) {
	if txIndex >= uint64(len(receipts)) {
		return nil, nil, fmt.Errorf("transaction index %d is out of range, block has %d receipts", txIndex, len(receipts))
	}

	receiptsTrie := trie.NewEmpty(nil)
	var buf bytes.Buffer
	for i := range receipts.Len() {
		buf.Reset()
		receipts.EncodeIndex(i, &buf)
		if err := receiptsTrie.Update(rlp.AppendUint64(nil, uint64(i)), bytes.Clone(buf.Bytes())); err != nil {
			return nil, nil, fmt.Errorf("failed to insert receipt %d: %w", i, err)
		}
	}
	if root := receiptsTrie.Hash(); root != receiptsRoot {
		return nil, nil, fmt.Errorf("receipts hash to %s, header receipts root is %s", root, receiptsRoot)
	}

	key := rlp.AppendUint64(nil, txIndex)
	nodes := &proofNodes{byHash: make(map[common.Hash][]byte)}
	if err := receiptsTrie.Prove(key, nodes); err != nil {
		return nil, nil, fmt.Errorf("failed to prove receipt %d: %w", txIndex, err)
	}
	value, err := trie.VerifyProof(receiptsRoot, key, nodes)
	if err != nil {
		return nil, nil, fmt.Errorf("receipt proof does not verify: %w", err)
	}
	return nodes.list, value, nil
}

// proofNodes collects the nodes Trie.Prove emits, in the order it emits them, which is root first.
type proofNodes struct {
	list   [][]byte
	byHash map[common.Hash][]byte
}

func (p *proofNodes) Put(key, value []byte) error {
	value = bytes.Clone(value)
	p.list = append(p.list, value)
	p.byHash[common.BytesToHash(key)] = value
	return nil
}

func (p *proofNodes) Delete([]byte) error {
	return nil
}

func (p *proofNodes) Has(key []byte) (bool, error) {
	_, ok := p.byHash[common.BytesToHash(key)]
	return ok, nil
}

func (p *proofNodes) Get(key []byte) ([]byte, error) {
	value, ok := p.byHash[common.BytesToHash(key)]
	if !ok {
		return nil, fmt.Errorf("proof node %x not found", key)
	}
	return value, nil
}

func mustWitnessArguments() abi.Arguments {
	witnessType, err := abi.NewType("tuple", "", []abi.ArgumentMarshaling{
		{Name: "provenBlockNumber", Type: "uint256"},
		{Name: "headers", Type: "bytes[]"},
		{Name: "txIndex", Type: "uint256"},
		{Name: "logIndex", Type: "uint256"},
		{Name: "proofNodes", Type: "bytes[]"},
	})
	if err != nil {
		panic(fmt.Sprintf("failed to build witness ABI type: %v", err))
	}
	return abi.Arguments{{Type: witnessType}}
}
