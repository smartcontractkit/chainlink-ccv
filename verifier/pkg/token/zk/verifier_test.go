package zk

import (
	"errors"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token/internal"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func testConfig() ZKConfig {
	return ZKConfig{
		NotProvenRetry:  45 * time.Second,
		VerifierVersion: DefaultVerifierVersion,
	}
}

// testTask returns a task on the lane the test verifier serves, and the chain that emits its message.
func testTask(firstBlock, lastBlock, messageBlock uint64) (verifier.VerificationTask, *testChain) {
	task := internal.CreateTestVerificationTask(1)
	task.Message.OnRampAddress = protocol.UnknownAddress(testOnRamp.Bytes())
	task.Message.OnRampAddressLength = uint8(len(task.Message.OnRampAddress))
	task.MessageID = task.Message.MustMessageID().String()
	task.BlockNumber = messageBlock
	chain := newTestChainForMessage(firstBlock, lastBlock, messageBlock, common.Hash(task.Message.MustMessageID()))
	return task, chain
}

func testLanes(chain *testChain, lightClient ProvenBlockReader) map[LaneKey]LaneReaders {
	task := internal.CreateTestVerificationTask(1)
	key := LaneKey{SourceChainSelector: task.Message.SourceChainSelector, DestChainSelector: task.Message.DestChainSelector}
	return map[LaneKey]LaneReaders{key: {Source: chain, Proven: lightClient}}
}

func TestVerifier_VerifyMessages_Success(t *testing.T) {
	task, chain := testTask(testMessageBlock, testMessageBlock+2, testMessageBlock)
	lightClient := newTestLightClient(chain, testMessageBlock+2)

	v := NewVerifier(logger.Test(t), monitoring.NewFakeVerifierMonitoring(), "test-verifier", testConfig(), testLanes(chain, lightClient))
	results := v.VerifyMessages(t.Context(), []verifier.VerificationTask{task})

	require.Len(t, results, 1)
	require.Nil(t, results[0].Error)
	result := results[0].Result
	require.NotNil(t, result)
	assert.Equal(t, task.MessageID, result.MessageID.String())
	assert.Equal(t, []protocol.UnknownAddress{internal.CCVAddress1, internal.CCVAddress2}, result.CCVAddresses)
	assert.Equal(t, internal.ExecutorAddress, result.ExecutorAddress)
	assert.Equal(t, DefaultVerifierVersion, result.CCVVersion)

	assert.Equal(t, []byte(DefaultVerifierVersion), []byte(result.Signature[:verifierVersionBytes]))
	witness := decodeWitness(t, result.Signature)
	assert.Equal(t, testMessageBlock+2, witness.ProvenBlockNumber.Uint64())
	assert.Len(t, witness.Headers, 3)
	assert.Equal(t, uint64(1), witness.TxIndex.Uint64())
	assert.Equal(t, uint64(1), witness.LogIndex.Uint64())
}

func TestVerifier_VerifyMessages_NoLane(t *testing.T) {
	task, chain := testTask(testMessageBlock, testMessageBlock, testMessageBlock)
	lightClient := newTestLightClient(chain, testMessageBlock)
	task.Message.DestChainSelector = 42

	v := NewVerifier(logger.Test(t), monitoring.NewFakeVerifierMonitoring(), "test-verifier", testConfig(), testLanes(chain, lightClient))
	results := v.VerifyMessages(t.Context(), []verifier.VerificationTask{task})

	require.Len(t, results, 1)
	require.NotNil(t, results[0].Error)
	assert.False(t, results[0].Error.Retryable)
	assert.ErrorContains(t, results[0].Error.Error, "no lane configured")
}

func TestVerifier_VerifyMessages_NotProven(t *testing.T) {
	task, chain := testTask(testMessageBlock-1, testMessageBlock, testMessageBlock)
	lightClient := newTestLightClient(chain, testMessageBlock-1)

	v := NewVerifier(logger.Test(t), monitoring.NewFakeVerifierMonitoring(), "test-verifier", testConfig(), testLanes(chain, lightClient))
	results := v.VerifyMessages(t.Context(), []verifier.VerificationTask{task})

	require.Len(t, results, 1)
	require.NotNil(t, results[0].Error)
	assert.True(t, results[0].Error.Retryable)
	assert.Equal(t, 45*time.Second, results[0].Error.DelayOrDefault())
	assert.True(t, errors.Is(results[0].Error.Error, errNotProven))
}

func TestVerifier_VerifyMessages_SourceError(t *testing.T) {
	task, chain := testTask(testMessageBlock, testMessageBlock, testMessageBlock)
	lightClient := newTestLightClient(chain, testMessageBlock)
	task.BlockNumber = testMessageBlock + 1

	v := NewVerifier(logger.Test(t), monitoring.NewFakeVerifierMonitoring(), "test-verifier", testConfig(), testLanes(chain, lightClient))
	results := v.VerifyMessages(t.Context(), []verifier.VerificationTask{task})

	require.Len(t, results, 1)
	require.NotNil(t, results[0].Error)
	assert.True(t, results[0].Error.Retryable)
	assert.Equal(t, anyErrorRetry, results[0].Error.DelayOrDefault())
	assert.ErrorContains(t, results[0].Error.Error, "failed to fetch receipts of block 1001")
}
