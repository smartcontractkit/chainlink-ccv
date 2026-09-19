package zk

import (
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// TestBuildWitness_Testnet builds the witness of a real Sepolia message against the SP1Helios contract on
// Arbitrum Sepolia. It runs only when the RPC endpoints and the ccipSend transaction hash are set:
//
//	ZK_TEST_SEPOLIA_RPC_URL, ZK_TEST_ARBITRUM_SEPOLIA_RPC_URL, ZK_TEST_TX_HASH
//
// It logs the encoded verifier results so they can be checked against the destination verifier.
func TestBuildWitness_Testnet(t *testing.T) {
	sourceURL := os.Getenv("ZK_TEST_SEPOLIA_RPC_URL")
	destURL := os.Getenv("ZK_TEST_ARBITRUM_SEPOLIA_RPC_URL")
	txHash := os.Getenv("ZK_TEST_TX_HASH")
	if sourceURL == "" || destURL == "" || txHash == "" {
		t.Skip("ZK_TEST_SEPOLIA_RPC_URL, ZK_TEST_ARBITRUM_SEPOLIA_RPC_URL and ZK_TEST_TX_HASH are not set")
	}

	source := protocol.ChainSelector(chainsel.ETHEREUM_TESTNET_SEPOLIA.Selector)
	dest := protocol.ChainSelector(chainsel.ETHEREUM_TESTNET_SEPOLIA_ARBITRUM_1.Selector)
	lightClient, err := protocol.NewUnknownAddressFromHex("0xf66AB2b4C1B7045ea51e4d905F91c40EAB31304E")
	require.NoError(t, err)
	lanes, err := DialLanes(t.Context(), []Lane{{SourceChainSelector: source, DestChainSelector: dest, LightClient: lightClient}},
		map[protocol.ChainSelector]string{source: sourceURL, dest: destURL})
	require.NoError(t, err)
	lane := lanes[LaneKey{SourceChainSelector: source, DestChainSelector: dest}]

	// The task carries the block number and the message id. The test takes them from the transaction receipt.
	sourceClient, err := ethclient.DialContext(t.Context(), sourceURL)
	require.NoError(t, err)
	receipt, err := sourceClient.TransactionReceipt(t.Context(), common.HexToHash(txHash))
	require.NoError(t, err)
	var message SentMessage
	for _, log := range receipt.Logs {
		if len(log.Topics) == messageSentTopicCount && log.Topics[0] == CCIPMessageSentTopic {
			message = SentMessage{
				BlockNumber: receipt.BlockNumber.Uint64(),
				OnRamp:      log.Address,
				MessageID:   log.Topics[messageIDTopicIndex],
			}
		}
	}
	require.NotZero(t, message.MessageID, "transaction has no CCIPMessageSent log")

	witness, err := BuildWitness(t.Context(), lane.Source, lane.Proven, message)
	require.NoError(t, err)
	assert.Equal(t, uint64(receipt.TransactionIndex), witness.TxIndex.Uint64())

	hashes, err := lane.Proven.ProvenBlockHashes(t.Context(), witness.ProvenBlockNumber.Uint64(), witness.ProvenBlockNumber.Uint64())
	require.NoError(t, err)
	expected := hashes[0]
	var header types.Header
	for _, encoded := range witness.Headers {
		assert.Equal(t, expected, crypto.Keccak256Hash(encoded))
		require.NoError(t, rlp.DecodeBytes(encoded, &header))
		expected = header.ParentHash
	}
	assert.Equal(t, message.BlockNumber, header.Number.Uint64())

	nodes := &proofNodes{byHash: make(map[common.Hash][]byte)}
	for _, node := range witness.ProofNodes {
		require.NoError(t, nodes.Put(crypto.Keccak256(node), node))
	}
	value, err := trie.VerifyProof(header.ReceiptHash, rlp.AppendUint64(nil, witness.TxIndex.Uint64()), nodes)
	require.NoError(t, err)
	expectedReceipt, err := receipt.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, expectedReceipt, value)

	verifierResults, err := witness.Encode(DefaultVerifierVersion)
	require.NoError(t, err)
	t.Logf("message %s in block %d, proven block %d, %d headers, %d proof nodes, %d bytes",
		message.MessageID, message.BlockNumber, witness.ProvenBlockNumber, len(witness.Headers), len(witness.ProofNodes), len(verifierResults))
	t.Logf("onRamp %s", message.OnRamp)
	t.Logf("verifierResults 0x%x", verifierResults)
}
