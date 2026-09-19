package zk

import (
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testMessageBlock uint64 = 1_000

func TestBuildWitness_HeaderChainFromProvenBlock(t *testing.T) {
	chain := newTestChain(testMessageBlock-1, testMessageBlock+5, testMessageBlock)
	lightClient := newTestLightClient(chain, testMessageBlock+2)

	witness, err := BuildWitness(t.Context(), chain, lightClient, chain.message)
	require.NoError(t, err)

	assert.Equal(t, testMessageBlock+2, witness.ProvenBlockNumber.Uint64())
	assert.Equal(t, uint64(1), witness.TxIndex.Uint64())
	assert.Equal(t, uint64(1), witness.LogIndex.Uint64())
	require.Len(t, witness.Headers, 3)
	for i, encoded := range witness.Headers {
		number := testMessageBlock + 2 - uint64(i)
		assert.Equal(t, chain.hash(number), crypto.Keccak256Hash(encoded), "header %d", number)
	}
	assertReceiptProof(t, chain, witness)
	assert.Equal(t, [][2]uint64{{testMessageBlock, testMessageBlock + 2}}, lightClient.ranges)
}

func TestBuildWitness_ProvenBlockIsMessageBlock(t *testing.T) {
	chain := newTestChain(testMessageBlock, testMessageBlock, testMessageBlock)
	lightClient := newTestLightClient(chain, testMessageBlock)

	witness, err := BuildWitness(t.Context(), chain, lightClient, chain.message)
	require.NoError(t, err)

	assert.Equal(t, testMessageBlock, witness.ProvenBlockNumber.Uint64())
	require.Len(t, witness.Headers, 1)
	assert.Equal(t, chain.hash(testMessageBlock), crypto.Keccak256Hash(witness.Headers[0]))
	assertReceiptProof(t, chain, witness)
}

func TestBuildWitness_PicksLowestProvenBlock(t *testing.T) {
	chain := newTestChain(testMessageBlock, testMessageBlock+10, testMessageBlock)
	lightClient := newTestLightClient(chain, testMessageBlock+1, testMessageBlock+3, testMessageBlock+10)

	witness, err := BuildWitness(t.Context(), chain, lightClient, chain.message)
	require.NoError(t, err)

	assert.Equal(t, testMessageBlock+1, witness.ProvenBlockNumber.Uint64())
	assert.Len(t, witness.Headers, 2)
	assert.Equal(t, [][2]uint64{{testMessageBlock, testMessageBlock + 10}}, lightClient.ranges)
}

func TestBuildWitness_LongHeaderChain(t *testing.T) {
	chain := newTestChain(testMessageBlock, testMessageBlock+100, testMessageBlock)
	lightClient := newTestLightClient(chain, testMessageBlock+100)

	witness, err := BuildWitness(t.Context(), chain, lightClient, chain.message)
	require.NoError(t, err)

	assert.Equal(t, testMessageBlock+100, witness.ProvenBlockNumber.Uint64())
	assert.Len(t, witness.Headers, 101)
	assert.Len(t, lightClient.ranges, 7)
	assertReceiptProof(t, chain, witness)
}

func TestBuildWitness_ScansInBatches(t *testing.T) {
	chain := newTestChain(testMessageBlock, testMessageBlock+40, testMessageBlock)
	lightClient := newTestLightClient(chain, testMessageBlock+20, testMessageBlock+40)

	witness, err := BuildWitness(t.Context(), chain, lightClient, chain.message)
	require.NoError(t, err)

	assert.Equal(t, testMessageBlock+20, witness.ProvenBlockNumber.Uint64())
	assert.Len(t, witness.Headers, 21)
	assert.Equal(t, [][2]uint64{
		{testMessageBlock, testMessageBlock + provenBlockScanBatch - 1},
		{testMessageBlock + provenBlockScanBatch, testMessageBlock + 2*provenBlockScanBatch - 1},
	}, lightClient.ranges)
}

func TestBuildWitness_NotProven(t *testing.T) {
	chain := newTestChain(testMessageBlock-3, testMessageBlock, testMessageBlock)
	lightClient := newTestLightClient(chain, testMessageBlock-1)

	_, err := BuildWitness(t.Context(), chain, lightClient, chain.message)
	require.ErrorIs(t, err, errNotProven)
	assert.Empty(t, lightClient.ranges)
}

func TestBuildWitness_LogNotFound(t *testing.T) {
	chain := newTestChain(testMessageBlock, testMessageBlock, testMessageBlock)
	lightClient := newTestLightClient(chain, testMessageBlock)
	message := chain.message
	message.MessageID = common.HexToHash("0x09")

	_, err := BuildWitness(t.Context(), chain, lightClient, message)
	require.ErrorContains(t, err, "block 1000 has no CCIPMessageSent log")
}

func TestBuildWitness_LogFromAnotherEmitter(t *testing.T) {
	chain := newTestChain(testMessageBlock, testMessageBlock, testMessageBlock)
	lightClient := newTestLightClient(chain, testMessageBlock)
	message := chain.message
	message.OnRamp = common.HexToAddress("0x0a")

	_, err := BuildWitness(t.Context(), chain, lightClient, message)
	require.ErrorContains(t, err, "block 1000 has no CCIPMessageSent log")
}

func TestBuildWitness_FailedTransaction(t *testing.T) {
	chain := newTestChain(testMessageBlock, testMessageBlock, testMessageBlock)
	lightClient := newTestLightClient(chain, testMessageBlock)
	chain.receipts[testMessageBlock][1].Status = types.ReceiptStatusFailed

	_, err := BuildWitness(t.Context(), chain, lightClient, chain.message)
	require.ErrorContains(t, err, "transaction 1 of block 1000 emitted message")
	require.ErrorContains(t, err, "did not succeed")
}

func TestBuildWitness_HeaderHashMismatch(t *testing.T) {
	chain := newTestChain(testMessageBlock, testMessageBlock+1, testMessageBlock)
	lightClient := newTestLightClient(chain, testMessageBlock+1)
	chain.headers[testMessageBlock].Extra = []byte("changed after the child committed to it")

	_, err := BuildWitness(t.Context(), chain, lightClient, chain.message)
	require.ErrorContains(t, err, "header 1000 hashes to")
}

func TestBuildWitness_ReceiptsRootMismatch(t *testing.T) {
	chain := newTestChain(testMessageBlock, testMessageBlock, testMessageBlock)
	lightClient := newTestLightClient(chain, testMessageBlock)
	chain.receipts[testMessageBlock] = append(chain.receipts[testMessageBlock], testReceipt(3, nil))

	_, err := BuildWitness(t.Context(), chain, lightClient, chain.message)
	require.ErrorContains(t, err, "header receipts root is")
}

func TestCheckProvenReceipt(t *testing.T) {
	chain := newTestChain(testMessageBlock, testMessageBlock, testMessageBlock)
	receipts := chain.receipts[testMessageBlock]
	proven, err := receipts[1].MarshalBinary()
	require.NoError(t, err)
	other, err := receipts[0].MarshalBinary()
	require.NoError(t, err)
	failed := *receipts[1]
	failed.Status = types.ReceiptStatusFailed
	failedEncoded, err := failed.MarshalBinary()
	require.NoError(t, err)

	require.NoError(t, checkProvenReceipt(proven, 1, chain.message))
	require.ErrorContains(t, checkProvenReceipt(proven, 0, chain.message), "is not the CCIPMessageSent log")
	require.ErrorContains(t, checkProvenReceipt(proven, 2, chain.message), "has 2 logs, log index is 2")
	require.ErrorContains(t, checkProvenReceipt(other, 0, chain.message), "has 0 logs")
	require.ErrorContains(t, checkProvenReceipt(failedEncoded, 1, chain.message), "did not succeed")
	require.ErrorContains(t, checkProvenReceipt([]byte{0x02, 0x01}, 1, chain.message), "does not decode")
}

func TestWitness_Encode(t *testing.T) {
	chain := newTestChain(testMessageBlock, testMessageBlock+1, testMessageBlock)
	lightClient := newTestLightClient(chain, testMessageBlock+1)
	witness, err := BuildWitness(t.Context(), chain, lightClient, chain.message)
	require.NoError(t, err)

	encoded, err := witness.Encode(DefaultVerifierVersion)
	require.NoError(t, err)
	assert.Equal(t, []byte(DefaultVerifierVersion), encoded[:verifierVersionBytes])

	assert.Equal(t, witness, decodeWitness(t, encoded))
}

// decodeWitness decodes verifier results the way the destination verifier does.
func decodeWitness(t *testing.T, verifierResults []byte) *Witness {
	t.Helper()
	values, err := witnessArguments.Unpack(verifierResults[verifierVersionBytes:])
	require.NoError(t, err)
	require.Len(t, values, 1)
	witness, ok := abi.ConvertType(values[0], new(Witness)).(*Witness)
	require.True(t, ok)
	return witness
}

// assertReceiptProof checks the proof nodes against the receipts root of the message block header, the way the
// destination verifier does, and that the proven leaf is the consensus encoding of the message receipt.
func assertReceiptProof(t *testing.T, chain *testChain, witness *Witness) {
	t.Helper()
	var header types.Header
	require.NoError(t, rlp.DecodeBytes(witness.Headers[len(witness.Headers)-1], &header))
	assert.Equal(t, chain.message.BlockNumber, header.Number.Uint64())

	nodes := &proofNodes{byHash: make(map[common.Hash][]byte)}
	for _, node := range witness.ProofNodes {
		require.NoError(t, nodes.Put(crypto.Keccak256(node), node))
	}
	key := rlp.AppendUint64(nil, witness.TxIndex.Uint64())
	value, err := trie.VerifyProof(header.ReceiptHash, key, nodes)
	require.NoError(t, err)

	expected, err := chain.receipts[chain.message.BlockNumber][witness.TxIndex.Uint64()].MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, expected, value)
	assert.Equal(t, crypto.Keccak256Hash(witness.ProofNodes[0]), header.ReceiptHash, "first proof node is the root")
}
