package test

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/common"

	verifiermocks "github.com/smartcontractkit/chainlink-ccv/verifier/mocks"
)

// WaitForMessagesInStorage waits for the specified number of messages to be processed.
// Since messages are batched, we can't rely on one notification per message.
// Instead, we poll the storage to check if the expected count has been reached.
func WaitForMessagesInStorage(t *testing.T, storage *common.InMemoryOffchainStorage, count int) {
	timeout := time.After(30 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			require.FailNow(t, "Timeout waiting for messages", "expected %d messages, got %d", count, storage.GetTotalCount())
		case <-ticker.C:
			if storage.GetTotalCount() >= count {
				return
			}
		}
	}
}

func CreateTestMessage(t *testing.T, nonce protocol.Nonce, sourceChainSelector, destChainSelector protocol.ChainSelector, finality uint16) protocol.Message {
	// Create empty token transfer
	tokenTransfer := protocol.NewEmptyTokenTransfer()

	sender := protocol.UnknownAddress([]byte("sender_address"))
	receiver := protocol.UnknownAddress([]byte("receiver_address"))
	onRampAddr := protocol.UnknownAddress([]byte("onramp_address"))
	offRampAddr := protocol.UnknownAddress([]byte("offramp_address"))

	message, err := protocol.NewMessage(
		sourceChainSelector,
		destChainSelector,
		nonce,
		onRampAddr,
		offRampAddr,
		finality,
		sender,
		receiver,
		[]byte("test data"), // dest blob
		[]byte("test data"), // data
		tokenTransfer,
	)
	require.NoError(t, err)
	return *message
}

// MockSourceReaderSetup contains a mock source Reader and its Channel.
type MockSourceReaderSetup struct {
	Reader  *verifiermocks.MockSourceReader
	Channel chan verifier.VerificationTask
}

// SetupMockSourceReader creates a mock source Reader with expectations.
func SetupMockSourceReader(t *testing.T) *MockSourceReaderSetup {
	mockReader := verifiermocks.NewMockSourceReader(t)
	channel := make(chan verifier.VerificationTask, 10)

	now := time.Now().Unix()
	//nolint:gosec // G115: This is a test setup.
	mockReader.EXPECT().BlockTime(mock.Anything, mock.Anything).Return(uint64(now), nil).Maybe()

	return &MockSourceReaderSetup{
		Reader:  mockReader,
		Channel: channel,
	}
}

func (msrs *MockSourceReaderSetup) ExpectVerificationTask(maybeVerificationTask bool) {
	call := msrs.Reader.EXPECT().VerificationTasks(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(func(ctx context.Context, b, b2 *big.Int) ([]verifier.VerificationTask, error) {
		var tasks []verifier.VerificationTask
		for {
			select {
			case task := <-msrs.Channel:
				tasks = append(tasks, task)
			default:
				return tasks, nil
			}
		}
	})
	if maybeVerificationTask {
		call.Maybe()
	}
}
