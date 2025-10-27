package executor

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/smartcontractkit/chainlink-ccv/executor/internal/executor_mocks"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/monitoring"
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
	address1, err := protocol.RandomAddress()
	assert.NoError(t, err)
	address2, err := protocol.RandomAddress()
	assert.NoError(t, err)
	execAddress, err := protocol.RandomAddress()
	assert.NoError(t, err)
	ExecIssuer := []protocol.ReceiptWithBlob{
		{
			Issuer: execAddress,
		},
	}
	defaultTransmitter := func() *executor_mocks.MockContractTransmitter {
		ct := executor_mocks.NewMockContractTransmitter(t)
		ct.EXPECT().ConvertAndWriteMessageToChain(mock.Anything, mock.Anything).Return(nil).Maybe()
		return ct
	}

	mockVerifierResultCreator := func() *executor_mocks.MockVerifierResultReader {
		vr := executor_mocks.NewMockVerifierResultReader(t)
		vr.EXPECT().GetVerifierResults(mock.Anything, mock.Anything).Return([]protocol.CCVData{
			{DestVerifierAddress: protocol.UnknownAddress{}, CCVData: []byte("data"), ReceiptBlobs: ExecIssuer},
		}, nil).Maybe()
		return vr
	}
	testcases := []struct {
		name                       string
		ct                         func() *executor_mocks.MockContractTransmitter
		ctChains                   []protocol.ChainSelector
		dr                         *mockDestinationReader
		drChains                   []protocol.ChainSelector
		executorMap                map[protocol.ChainSelector]protocol.UnknownAddress
		vr                         func() *executor_mocks.MockVerifierResultReader
		msg                        protocol.Message
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
			executorMap:                map[protocol.ChainSelector]protocol.UnknownAddress{1: execAddress, 2: execAddress},
			vr:                         mockVerifierResultCreator,
			msg:                        protocol.Message{DestChainSelector: 1, SourceChainSelector: 2, Nonce: 1},
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
			executorMap:                map[protocol.ChainSelector]protocol.UnknownAddress{1: execAddress, 2: execAddress},
			vr:                         mockVerifierResultCreator,
			msg:                        protocol.Message{DestChainSelector: 1, SourceChainSelector: 2, Nonce: 1},
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
			executorMap:                map[protocol.ChainSelector]protocol.UnknownAddress{1: execAddress},
			vr:                         mockVerifierResultCreator,
			msg:                        protocol.Message{DestChainSelector: 1, SourceChainSelector: 2, Nonce: 1},
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
			executorMap:                map[protocol.ChainSelector]protocol.UnknownAddress{1: execAddress},
			vr:                         mockVerifierResultCreator,
			msg:                        protocol.Message{DestChainSelector: 1, SourceChainSelector: 2, Nonce: 1},
			validateShouldError:        false,
			validateMessageShouldError: false,
			executeShouldError:         true,
		},
		{
			name: "Should only have use up to Threshold amount of optional CCVs",
			ct: func() *executor_mocks.MockContractTransmitter {
				ct := executor_mocks.NewMockContractTransmitter(t)
				ct.EXPECT().ConvertAndWriteMessageToChain(mock.Anything, coordinator.AbstractAggregatedReport{
					Message: protocol.Message{DestChainSelector: 1, SourceChainSelector: 2, Nonce: 1},
					CCVS:    []protocol.UnknownAddress{address1},
					CCVData: [][]byte{[]byte("data")},
				}).Return(nil).Once()
				return ct
			},
			ctChains: []protocol.ChainSelector{1},
			dr: &mockDestinationReader{
				executed:    false,
				executedErr: nil,
				ccvInfo: coordinator.CcvAddressInfo{
					OptionalCcvs:      []protocol.UnknownAddress{address1, address2},
					OptionalThreshold: 1,
				},
			},
			drChains:    []protocol.ChainSelector{1},
			executorMap: map[protocol.ChainSelector]protocol.UnknownAddress{1: execAddress},
			vr: func() *executor_mocks.MockVerifierResultReader {
				vr := executor_mocks.NewMockVerifierResultReader(t)
				vr.EXPECT().GetVerifierResults(mock.Anything, mock.Anything).Return([]protocol.CCVData{
					{DestVerifierAddress: address1, CCVData: []byte("data"), ReceiptBlobs: ExecIssuer},
					{DestVerifierAddress: address2, CCVData: []byte("data"), ReceiptBlobs: ExecIssuer},
				}, nil).Maybe()
				return vr
			},
			msg: protocol.Message{DestChainSelector: 1, SourceChainSelector: 2, Nonce: 1},
		},
		{
			name: "Should support a 0 threshold for optional CCVs",
			ct: func() *executor_mocks.MockContractTransmitter {
				ct := executor_mocks.NewMockContractTransmitter(t)
				ct.EXPECT().ConvertAndWriteMessageToChain(mock.Anything, coordinator.AbstractAggregatedReport{
					Message: protocol.Message{DestChainSelector: 1, SourceChainSelector: 2, Nonce: 1},
					CCVS:    []protocol.UnknownAddress{},
					CCVData: [][]byte{},
				}).Return(nil).Once()
				return ct
			},
			ctChains: []protocol.ChainSelector{1},
			dr: &mockDestinationReader{
				executed:    false,
				executedErr: nil,
				ccvInfo: coordinator.CcvAddressInfo{
					OptionalCcvs:      []protocol.UnknownAddress{address1, address2},
					OptionalThreshold: 0,
				},
			},
			drChains:    []protocol.ChainSelector{1},
			executorMap: map[protocol.ChainSelector]protocol.UnknownAddress{1: execAddress},
			vr: func() *executor_mocks.MockVerifierResultReader {
				vr := executor_mocks.NewMockVerifierResultReader(t)
				vr.EXPECT().GetVerifierResults(mock.Anything, mock.Anything).Return([]protocol.CCVData{
					{DestVerifierAddress: address1, CCVData: []byte("data"), ReceiptBlobs: ExecIssuer},
					{DestVerifierAddress: address2, CCVData: []byte("data"), ReceiptBlobs: ExecIssuer},
				}, nil).Maybe()
				return vr
			},
			msg: protocol.Message{DestChainSelector: 1, SourceChainSelector: 2, Nonce: 1},
		},
		{
			name: "Should fail out if executor is not on any receipt",
			ct: func() *executor_mocks.MockContractTransmitter {
				return executor_mocks.NewMockContractTransmitter(t)
			},
			ctChains: []protocol.ChainSelector{1},
			dr: &mockDestinationReader{
				executed:    false,
				executedErr: nil,
				ccvInfo: coordinator.CcvAddressInfo{
					OptionalCcvs:      []protocol.UnknownAddress{address1, address2},
					OptionalThreshold: 1,
				},
			},
			drChains:    []protocol.ChainSelector{1},
			executorMap: map[protocol.ChainSelector]protocol.UnknownAddress{1: execAddress},
			vr: func() *executor_mocks.MockVerifierResultReader {
				vr := executor_mocks.NewMockVerifierResultReader(t)
				vr.EXPECT().GetVerifierResults(mock.Anything, mock.Anything).Return([]protocol.CCVData{
					{DestVerifierAddress: address1, CCVData: []byte("data")},
					{DestVerifierAddress: address2, CCVData: []byte("data")},
				}, nil).Maybe()
				return vr
			},
			msg:                protocol.Message{DestChainSelector: 1, SourceChainSelector: 2, Nonce: 1},
			executeShouldError: true,
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

			executor := NewChainlinkExecutor(logger.Test(t), allContractTransmitters, allDestinationReaders, tc.vr(), tc.executorMap, monitoring.NewNoopExecutorMonitoring())
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

			err = executor.AttemptExecuteMessage(context.Background(), tc.msg)
			if tc.executeShouldError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestChainlinkExecutor_orderCcvData(t *testing.T) {
	executor := NewChainlinkExecutor(nil, nil, nil, nil, nil, nil)
	message := protocol.Message{}
	ccvAddr := protocol.UnknownAddress{}
	ccvData := []protocol.CCVData{{DestVerifierAddress: ccvAddr, CCVData: []byte("data")}}
	ccvInfo := coordinator.CcvAddressInfo{
		RequiredCcvs:      []protocol.UnknownAddress{ccvAddr},
		OptionalCcvs:      []protocol.UnknownAddress{},
		OptionalThreshold: 0,
	}
	report, timestamp, err := executor.orderCcvData(message, ccvData, ccvInfo)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(report.CCVS))
	assert.Equal(t, 1, len(report.CCVData))
	assert.Equal(t, int64(0), timestamp)
}
