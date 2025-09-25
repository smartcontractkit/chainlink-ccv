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
	protocol2 "github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	dr "github.com/smartcontractkit/chainlink-ccv/executor/pkg/destinationreader"
)

type mockDestinationReader struct {
	executedErr error
	ccvInfoErr  error
	ccvInfo     types.CcvAddressInfo
	executed    bool
}

func (m *mockDestinationReader) IsMessageExecuted(ctx context.Context, message protocol2.Message) (bool, error) {
	return m.executed, m.executedErr
}

func (m *mockDestinationReader) GetCCVSForMessage(ctx context.Context, message protocol2.Message) (types.CcvAddressInfo, error) {
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
		ctChains                   []protocol2.ChainSelector
		dr                         *mockDestinationReader
		drChains                   []protocol2.ChainSelector
		msg                        types.MessageWithCCVData
		validateShouldError        bool
		validateMessageShouldError bool
		executeShouldError         bool
	}{
		{
			name:                       "valid case",
			ct:                         defaultTransmitter,
			ctChains:                   []protocol2.ChainSelector{1, 2},
			dr:                         &mockDestinationReader{},
			drChains:                   []protocol2.ChainSelector{1, 2},
			msg:                        types.MessageWithCCVData{Message: protocol2.Message{DestChainSelector: 1, SourceChainSelector: 2, Nonce: 1}},
			validateShouldError:        false,
			validateMessageShouldError: false,
			executeShouldError:         false,
		},
		{
			name:                       "mismatched supported chains should error",
			ct:                         defaultTransmitter,
			ctChains:                   []protocol2.ChainSelector{1},
			dr:                         &mockDestinationReader{},
			drChains:                   []protocol2.ChainSelector{1, 2},
			msg:                        types.MessageWithCCVData{Message: protocol2.Message{DestChainSelector: 1, SourceChainSelector: 2, Nonce: 1}},
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
			ctChains:                   []protocol2.ChainSelector{1},
			dr:                         &mockDestinationReader{},
			drChains:                   []protocol2.ChainSelector{1},
			msg:                        types.MessageWithCCVData{Message: protocol2.Message{DestChainSelector: 1, SourceChainSelector: 2, Nonce: 1}},
			validateShouldError:        false,
			validateMessageShouldError: false,
			executeShouldError:         true,
		},
		{
			name:                       "Should not error if message already executed",
			ct:                         defaultTransmitter,
			ctChains:                   []protocol2.ChainSelector{1},
			dr:                         &mockDestinationReader{executed: true, executedErr: nil},
			drChains:                   []protocol2.ChainSelector{1},
			msg:                        types.MessageWithCCVData{Message: protocol2.Message{DestChainSelector: 1, SourceChainSelector: 2, Nonce: 1}},
			validateShouldError:        false,
			validateMessageShouldError: false,
			executeShouldError:         false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			allContractTransmitters := make(map[protocol2.ChainSelector]contracttransmitter.ContractTransmitter)
			ct := tc.ct()
			for _, chain := range tc.ctChains {
				allContractTransmitters[chain] = ct
			}

			allDestinationReaders := make(map[protocol2.ChainSelector]dr.DestinationReader)
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
	ccvAddr := protocol2.UnknownAddress{}
	ccvData := []protocol2.CCVData{{DestVerifierAddress: ccvAddr, CCVData: []byte("data")}}
	ccvInfo := types.CcvAddressInfo{
		RequiredCcvs:      []protocol2.UnknownAddress{ccvAddr},
		OptionalCcvs:      []protocol2.UnknownAddress{},
		OptionalThreshold: 0,
	}
	addrs, data, err := executor.orderCcvData(ccvData, ccvInfo)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(addrs))
	assert.Equal(t, 1, len(data))
}
