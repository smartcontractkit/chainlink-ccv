package executor

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/smartcontractkit/chainlink-ccv/executor/internal/executor_mocks"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/contracttransmitter"
	"github.com/smartcontractkit/chainlink-ccv/executor/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	dr "github.com/smartcontractkit/chainlink-ccv/executor/pkg/destinationreader"
	protocol "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

type mockDestinationReader struct {
	executedErr error
	ccvInfoErr  error
	ccvInfo     types.CcvAddressInfo
	executed    bool
}

func (m *mockDestinationReader) IsMessageExecuted(ctx context.Context, src protocol.ChainSelector, nonce protocol.Nonce) (bool, error) {
	return m.executed, m.executedErr
}

func (m *mockDestinationReader) GetCCVSForMessage(ctx context.Context, src protocol.ChainSelector, receiver protocol.UnknownAddress) (types.CcvAddressInfo, error) {
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
		msg                        types.MessageWithCCVData
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
			msg:                        types.MessageWithCCVData{Message: protocol.Message{DestChainSelector: 1, SourceChainSelector: 2, Nonce: 1}},
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
			msg:                        types.MessageWithCCVData{Message: protocol.Message{DestChainSelector: 1, SourceChainSelector: 2, Nonce: 1}},
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
			msg:                        types.MessageWithCCVData{Message: protocol.Message{DestChainSelector: 1, SourceChainSelector: 2, Nonce: 1}},
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
			msg:                        types.MessageWithCCVData{Message: protocol.Message{DestChainSelector: 1, SourceChainSelector: 2, Nonce: 1}},
			validateShouldError:        false,
			validateMessageShouldError: false,
			executeShouldError:         false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			allContractTransmitters := make(map[protocol.ChainSelector]contracttransmitter.ContractTransmitter)
			ct := tc.ct()
			for _, chain := range tc.ctChains {
				allContractTransmitters[chain] = ct
			}

			allDestinationReaders := make(map[protocol.ChainSelector]dr.DestinationReader)
			for _, chain := range tc.drChains {
				allDestinationReaders[chain] = tc.dr
			}
			executor := NewChainlinkExecutor(logger.Test(t), allContractTransmitters, allDestinationReaders)
			err := executor.Validate()
			if tc.validateShouldError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			err = executor.CheckValidMessage(context.Background(), tc.msg)
			if tc.validateMessageShouldError {
				assert.Error(t, err)
				return
			} else {
				assert.NoError(t, err)
			}

			err = executor.ExecuteMessage(context.Background(), tc.msg)
			if tc.executeShouldError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestChainlinkExecutor_orderCcvData(t *testing.T) {
	executor := NewChainlinkExecutor(nil, nil, nil)
	ccvAddr := protocol.UnknownAddress{}
	ccvData := []protocol.CCVData{{DestVerifierAddress: ccvAddr, CCVData: []byte("data")}}
	ccvInfo := types.CcvAddressInfo{
		RequiredCcvs:      []protocol.UnknownAddress{ccvAddr},
		OptionalCcvs:      []protocol.UnknownAddress{},
		OptionalThreshold: 0,
	}
	addrs, data, err := executor.orderCcvData(ccvData, ccvInfo)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(addrs))
	assert.Equal(t, 1, len(data))
}
