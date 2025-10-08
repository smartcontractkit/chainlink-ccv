package executor

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/smartcontractkit/chainlink-ccv/executor/internal/executor_mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	coordinator "github.com/smartcontractkit/chainlink-ccv/executor"
)

type mockDestinationReader struct {
	executedErr error
	ccvInfoErr  error
	ccvInfo     coordinator.CcvAddressInfo
	executed    bool
}

func (m *mockDestinationReader) IsMessageExecuted(ctx context.Context, message protocol.Message) (bool, error) {
	return m.executed, m.executedErr
}

func (m *mockDestinationReader) GetCCVSForMessage(ctx context.Context, message protocol.Message) (coordinator.CcvAddressInfo, error) {
	return m.ccvInfo, m.ccvInfoErr
}

// Tests.
func Test_ChainlinkExecutor(t *testing.T) {
	defaultTransmitter := func() *executor_mocks.MockContractTransmitter {
		ct := executor_mocks.NewMockContractTransmitter(t)
		ct.EXPECT().ConvertAndWriteMessageToChain(mock.Anything, mock.Anything).Return(nil).Maybe()
		return ct
	}

	testcases := []struct {
		name                       string
		ct                         func() *executor_mocks.MockContractTransmitter
		ctChains                   []protocol.ChainSelector
		dr                         *mockDestinationReader
		drChains                   []protocol.ChainSelector
		vr                         *executor_mocks.MockVerifierResultReader
		msg                        coordinator.MessageWithCCVData
		validateShouldError        bool
		validateMessageShouldError bool
		executeShouldError         bool
	}{
		{
			name:                       "valid case",
			ct:                         defaultTransmitter,
			ctChains:                   []protocol.ChainSelector{1, 2},
			dr:                         &mockDestinationReader{},
			drChains:                   []protocol.ChainSelector{1, 2},
			vr:                         &executor_mocks.MockVerifierResultReader{},
			msg:                        coordinator.MessageWithCCVData{Message: protocol.Message{DestChainSelector: 1, SourceChainSelector: 2, Nonce: 1}},
			validateShouldError:        false,
			validateMessageShouldError: false,
			executeShouldError:         false,
		},
		{
			name:                       "mismatched supported chains should error",
			ct:                         defaultTransmitter,
			ctChains:                   []protocol.ChainSelector{1},
			dr:                         &mockDestinationReader{},
			drChains:                   []protocol.ChainSelector{1, 2},
			vr:                         &executor_mocks.MockVerifierResultReader{},
			msg:                        coordinator.MessageWithCCVData{Message: protocol.Message{DestChainSelector: 1, SourceChainSelector: 2, Nonce: 1}},
			validateShouldError:        true,
			validateMessageShouldError: false,
			executeShouldError:         false,
		},
		{
			name: "should fail to execute if ConvertAndWriteMessageToChain fails",
			ct: func() *executor_mocks.MockContractTransmitter {
				ct := executor_mocks.NewMockContractTransmitter(t)
				ct.EXPECT().ConvertAndWriteMessageToChain(mock.Anything, mock.Anything).Return(errors.New("fail"))
				return ct
			},
			ctChains:                   []protocol.ChainSelector{1},
			dr:                         &mockDestinationReader{},
			drChains:                   []protocol.ChainSelector{1},
			vr:                         &executor_mocks.MockVerifierResultReader{},
			msg:                        coordinator.MessageWithCCVData{Message: protocol.Message{DestChainSelector: 1, SourceChainSelector: 2, Nonce: 1}},
			validateShouldError:        false,
			validateMessageShouldError: false,
			executeShouldError:         true,
		},
		{
			name:                       "Should not error if message already executed",
			ct:                         defaultTransmitter,
			ctChains:                   []protocol.ChainSelector{1},
			dr:                         &mockDestinationReader{executed: true, executedErr: nil},
			drChains:                   []protocol.ChainSelector{1},
			vr:                         &executor_mocks.MockVerifierResultReader{},
			msg:                        coordinator.MessageWithCCVData{Message: protocol.Message{DestChainSelector: 1, SourceChainSelector: 2, Nonce: 1}},
			validateShouldError:        false,
			validateMessageShouldError: false,
			executeShouldError:         false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			allContractTransmitters := make(map[protocol.ChainSelector]coordinator.ContractTransmitter)
			ct := tc.ct()
			for _, chain := range tc.ctChains {
				allContractTransmitters[chain] = ct
			}

			allDestinationReaders := make(map[protocol.ChainSelector]coordinator.DestinationReader)
			for _, chain := range tc.drChains {
				allDestinationReaders[chain] = tc.dr
			}
			executor := NewChainlinkExecutor(logger.Test(t), allContractTransmitters, allDestinationReaders, tc.vr)
			err := executor.Validate()
			if tc.validateShouldError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			err = executor.CheckValidMessage(context.Background(), tc.msg.Message)
			if tc.validateMessageShouldError {
				assert.Error(t, err)
				return
			} else {
				assert.NoError(t, err)
			}

			err = executor.AttemptExecuteMessage(context.Background(), tc.msg.Message)
			if tc.executeShouldError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestChainlinkExecutor_orderCcvData(t *testing.T) {
	executor := NewChainlinkExecutor(nil, nil, nil, nil)
	ccvAddr := protocol.UnknownAddress{}
	ccvData := []protocol.CCVData{{DestVerifierAddress: ccvAddr, CCVData: []byte("data")}}
	ccvInfo := coordinator.CcvAddressInfo{
		RequiredCcvs:      []protocol.UnknownAddress{ccvAddr},
		OptionalCcvs:      []protocol.UnknownAddress{},
		OptionalThreshold: 0,
	}
	addrs, data, err := executor.orderCcvData(ccvData, ccvInfo)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(addrs))
	assert.Equal(t, 1, len(data))
}
