package executor

import (
	"context"
	"errors"
	"testing"
	"time"

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
	ccvInfo     coordinator.CCVAddressInfo
	executed    bool
}

func (m *mockDestinationReader) IsMessageExecuted(ctx context.Context, message protocol.Message) (bool, error) {
	return m.executed, m.executedErr
}

func (m *mockDestinationReader) GetCCVSForMessage(ctx context.Context, message protocol.Message) (coordinator.CCVAddressInfo, error) {
	return m.ccvInfo, m.ccvInfoErr
}

func Test_ChainlinkExecutor(t *testing.T) {
	defaultTransmitter := func() *executor_mocks.MockContractTransmitter {
		ct := executor_mocks.NewMockContractTransmitter(t)
		ct.EXPECT().ConvertAndWriteMessageToChain(mock.Anything, mock.Anything).Return(nil).Maybe()
		return ct
	}

	mockVerifierResultCreator := func() *executor_mocks.MockVerifierResultReader {
		vr := executor_mocks.NewMockVerifierResultReader(t)
		vr.EXPECT().GetVerifierResults(mock.Anything, mock.Anything).Return([]protocol.CCVData{
			{DestVerifierAddress: protocol.UnknownAddress{}, CCVData: []byte("data")},
		}, nil).Maybe()
		return vr
	}
	address1, err := protocol.RandomAddress()
	assert.NoError(t, err)
	address2, err := protocol.RandomAddress()
	assert.NoError(t, err)

	testcases := []struct {
		name                       string
		ct                         func() *executor_mocks.MockContractTransmitter
		ctChains                   []protocol.ChainSelector
		dr                         *mockDestinationReader
		drChains                   []protocol.ChainSelector
		vr                         func() *executor_mocks.MockVerifierResultReader
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
			vr:                         mockVerifierResultCreator,
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
			vr:                         mockVerifierResultCreator,
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
			vr:                         mockVerifierResultCreator,
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
			vr:                         mockVerifierResultCreator,
			msg:                        coordinator.MessageWithCCVData{Message: protocol.Message{DestChainSelector: 1, SourceChainSelector: 2, Nonce: 1}},
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
				ccvInfo: coordinator.CCVAddressInfo{
					OptionalCCVs:      []protocol.UnknownAddress{address1, address2},
					OptionalThreshold: 1,
				},
			},
			drChains: []protocol.ChainSelector{1},
			vr: func() *executor_mocks.MockVerifierResultReader {
				vr := executor_mocks.NewMockVerifierResultReader(t)
				vr.EXPECT().GetVerifierResults(mock.Anything, mock.Anything).Return([]protocol.CCVData{
					{DestVerifierAddress: address1, CCVData: []byte("data")},
					{DestVerifierAddress: address2, CCVData: []byte("data")},
				}, nil).Maybe()
				return vr
			},
			msg: coordinator.MessageWithCCVData{Message: protocol.Message{DestChainSelector: 1, SourceChainSelector: 2, Nonce: 1}},
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
				ccvInfo: coordinator.CCVAddressInfo{
					OptionalCCVs:      []protocol.UnknownAddress{address1, address2},
					OptionalThreshold: 0,
				},
			},
			drChains: []protocol.ChainSelector{1},
			vr: func() *executor_mocks.MockVerifierResultReader {
				vr := executor_mocks.NewMockVerifierResultReader(t)
				vr.EXPECT().GetVerifierResults(mock.Anything, mock.Anything).Return([]protocol.CCVData{
					{DestVerifierAddress: address1, CCVData: []byte("data")},
					{DestVerifierAddress: address2, CCVData: []byte("data")},
				}, nil).Maybe()
				return vr
			},
			msg: coordinator.MessageWithCCVData{Message: protocol.Message{DestChainSelector: 1, SourceChainSelector: 2, Nonce: 1}},
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
			executor := NewChainlinkExecutor(logger.Test(t), allContractTransmitters, allDestinationReaders, tc.vr(), monitoring.NewNoopExecutorMonitoring())
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

func Test_orderCCVData(t *testing.T) {
	reqAddr1, err := protocol.RandomAddress()
	assert.NoError(t, err)
	reqAddr2, err := protocol.RandomAddress()
	assert.NoError(t, err)
	optAddr1, err := protocol.RandomAddress()
	assert.NoError(t, err)
	optAddr2, err := protocol.RandomAddress()
	assert.NoError(t, err)
	optAddr3, err := protocol.RandomAddress()
	assert.NoError(t, err)
	otherAddr, err := protocol.RandomAddress()
	assert.NoError(t, err)

	reqData1 := protocol.CCVData{DestVerifierAddress: reqAddr1, CCVData: []byte("req1"), Timestamp: time.UnixMilli(10)}
	reqData2 := protocol.CCVData{DestVerifierAddress: reqAddr2, CCVData: []byte("req2"), Timestamp: time.UnixMilli(20)}
	optData1 := protocol.CCVData{DestVerifierAddress: optAddr1, CCVData: []byte("opt1"), Timestamp: time.UnixMilli(5)}
	optData2 := protocol.CCVData{DestVerifierAddress: optAddr2, CCVData: []byte("opt2"), Timestamp: time.UnixMilli(25)}
	optData3 := protocol.CCVData{DestVerifierAddress: optAddr3, CCVData: []byte("opt3"), Timestamp: time.UnixMilli(15)}
	otherData := protocol.CCVData{DestVerifierAddress: otherAddr, CCVData: []byte("other"), Timestamp: time.UnixMilli(100)}

	testcases := []struct {
		name                string
		ccvDatas            []protocol.CCVData
		receiverCCVInfo     coordinator.CCVAddressInfo
		expectedOrderedData [][]byte
		expectedOfframps    []protocol.UnknownAddress
		expectedTimestamp   int64
		expectedErr         error
		expectedErrContains string
	}{
		{
			name:     "happy path",
			ccvDatas: []protocol.CCVData{reqData1, reqData2, optData1, optData2, optData3, otherData},
			receiverCCVInfo: coordinator.CCVAddressInfo{
				RequiredCCVs:      []protocol.UnknownAddress{reqAddr1, reqAddr2},
				OptionalCCVs:      []protocol.UnknownAddress{optAddr1, optAddr2, optAddr3},
				OptionalThreshold: 2,
			},
			expectedOrderedData: [][]byte{[]byte("req1"), []byte("req2"), []byte("opt1"), []byte("opt2")},
			expectedOfframps:    []protocol.UnknownAddress{reqAddr1, reqAddr2, optAddr1, optAddr2},
			expectedTimestamp:   25,
			expectedErr:         nil,
		},
		{
			name:     "missing required ccv",
			ccvDatas: []protocol.CCVData{reqData1, optData1, optData2, optData3},
			receiverCCVInfo: coordinator.CCVAddressInfo{
				RequiredCCVs:      []protocol.UnknownAddress{reqAddr1, reqAddr2},
				OptionalCCVs:      []protocol.UnknownAddress{optAddr1, optAddr2, optAddr3},
				OptionalThreshold: 2,
			},
			expectedErr:         coordinator.ErrInsufficientVerifiers,
			expectedErrContains: "required CCV",
		},
		{
			name:     "insufficient optional ccvs",
			ccvDatas: []protocol.CCVData{reqData1, reqData2, optData1},
			receiverCCVInfo: coordinator.CCVAddressInfo{
				RequiredCCVs:      []protocol.UnknownAddress{reqAddr1, reqAddr2},
				OptionalCCVs:      []protocol.UnknownAddress{optAddr1, optAddr2, optAddr3},
				OptionalThreshold: 2,
			},
			expectedErr:         coordinator.ErrInsufficientVerifiers,
			expectedErrContains: "not enough optional CCVs",
		},
		{
			name:     "optional threshold is 0",
			ccvDatas: []protocol.CCVData{reqData1, reqData2, optData1, optData2, optData3},
			receiverCCVInfo: coordinator.CCVAddressInfo{
				RequiredCCVs:      []protocol.UnknownAddress{reqAddr1, reqAddr2},
				OptionalCCVs:      []protocol.UnknownAddress{optAddr1, optAddr2, optAddr3},
				OptionalThreshold: 0,
			},
			expectedOrderedData: [][]byte{[]byte("req1"), []byte("req2")},
			expectedOfframps:    []protocol.UnknownAddress{reqAddr1, reqAddr2},
			expectedTimestamp:   20,
			expectedErr:         nil,
		},
		{
			name:     "no required ccvs",
			ccvDatas: []protocol.CCVData{reqData1, reqData2, optData1, optData2, optData3},
			receiverCCVInfo: coordinator.CCVAddressInfo{
				RequiredCCVs:      []protocol.UnknownAddress{},
				OptionalCCVs:      []protocol.UnknownAddress{optAddr1, optAddr2, optAddr3},
				OptionalThreshold: 2,
			},
			expectedOrderedData: [][]byte{[]byte("opt1"), []byte("opt2")},
			expectedOfframps:    []protocol.UnknownAddress{optAddr1, optAddr2},
			expectedTimestamp:   25,
			expectedErr:         nil,
		},
		{
			name:     "only takes up to threshold of optional ccvs",
			ccvDatas: []protocol.CCVData{reqData1, reqData2, optData1, optData2, optData3},
			receiverCCVInfo: coordinator.CCVAddressInfo{
				RequiredCCVs:      []protocol.UnknownAddress{reqAddr1, reqAddr2},
				OptionalCCVs:      []protocol.UnknownAddress{optAddr1, optAddr2, optAddr3},
				OptionalThreshold: 2,
			},
			expectedOrderedData: [][]byte{[]byte("req1"), []byte("req2"), []byte("opt1"), []byte("opt2")},
			expectedOfframps:    []protocol.UnknownAddress{reqAddr1, reqAddr2, optAddr1, optAddr2},
			expectedTimestamp:   25, // max(20, max(5,25))
			expectedErr:         nil,
		},
		{
			name:     "correct timestamp calculation",
			ccvDatas: []protocol.CCVData{reqData1, reqData2, optData1, optData2, optData3},
			receiverCCVInfo: coordinator.CCVAddressInfo{
				RequiredCCVs:      []protocol.UnknownAddress{reqAddr1, reqAddr2},           // timestamps 10, 20. max is 20
				OptionalCCVs:      []protocol.UnknownAddress{optAddr1, optAddr3, optAddr2}, // timestamps 5, 15, 25
				OptionalThreshold: 2,
			},
			// first two optional ccvs found are optAddr1 (ts 5) and optAddr3 (ts 15)
			// optional timestamps are [5, 15]. sorted [5, 15]. minSignificant is 15.
			// latest is max(20, 15) = 20
			expectedOrderedData: [][]byte{[]byte("req1"), []byte("req2"), []byte("opt1"), []byte("opt3")},
			expectedOfframps:    []protocol.UnknownAddress{reqAddr1, reqAddr2, optAddr1, optAddr3},
			expectedTimestamp:   20,
			expectedErr:         nil,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			orderedData, orderedOfframps, timestamp, err := orderCCVData(tc.ccvDatas, tc.receiverCCVInfo)

			if tc.expectedErr != nil {
				assert.Error(t, err)
				assert.True(t, errors.Is(err, tc.expectedErr))
				if tc.expectedErrContains != "" {
					assert.Contains(t, err.Error(), tc.expectedErrContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedOrderedData, orderedData)
				assert.Equal(t, tc.expectedOfframps, orderedOfframps)
				assert.Equal(t, tc.expectedTimestamp, timestamp)
			}
		})
	}
}
