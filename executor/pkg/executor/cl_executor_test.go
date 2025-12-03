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
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/cursechecker"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	ccvcommon "github.com/smartcontractkit/chainlink-ccv/common"
	coordinator "github.com/smartcontractkit/chainlink-ccv/executor"
)

func Test_ChainlinkExecutor(t *testing.T) {
	defaultTransmitter := func() *executor_mocks.MockContractTransmitter {
		ct := executor_mocks.NewMockContractTransmitter(t)
		ct.EXPECT().ConvertAndWriteMessageToChain(mock.Anything, mock.Anything).Return(nil).Maybe()
		return ct
	}

	address1, err := protocol.RandomAddress()
	assert.NoError(t, err)
	address2, err := protocol.RandomAddress()
	assert.NoError(t, err)

	mockVerifierResultCreator := func(msg protocol.Message) *executor_mocks.MockVerifierResultReader {
		vr := executor_mocks.NewMockVerifierResultReader(t)
		messageID, err := msg.MessageID()
		assert.NoError(t, err)
		vr.EXPECT().GetVerifierResults(mock.Anything, mock.Anything).Return([]protocol.VerifierResult{
			{MessageID: messageID, Message: msg, MessageCCVAddresses: []protocol.UnknownAddress{}, MessageExecutorAddress: address1},
		}, nil).Maybe()
		return vr
	}
	testcases := []struct {
		name                       string
		ct                         func() *executor_mocks.MockContractTransmitter
		ctChains                   []protocol.ChainSelector
		dr                         func() *executor_mocks.MockDestinationReader
		drChains                   []protocol.ChainSelector
		vr                         func(protocol.Message) *executor_mocks.MockVerifierResultReader
		msg                        coordinator.MessageWithCCVData
		validateShouldError        bool
		validateMessageShouldError bool
		executeShouldError         bool
	}{
		{
			name:     "valid case",
			ct:       defaultTransmitter,
			ctChains: []protocol.ChainSelector{1, 2},
			dr: func() *executor_mocks.MockDestinationReader {
				dr := executor_mocks.NewMockDestinationReader(t)
				dr.EXPECT().GetCCVSForMessage(mock.Anything, mock.Anything).Return(coordinator.CCVAddressInfo{}, nil).Maybe()
				return dr
			},
			drChains:                   []protocol.ChainSelector{1, 2},
			vr:                         mockVerifierResultCreator,
			msg:                        coordinator.MessageWithCCVData{Message: protocol.Message{DestChainSelector: 1, SourceChainSelector: 2, SequenceNumber: 1}},
			validateShouldError:        false,
			validateMessageShouldError: false,
			executeShouldError:         false,
		},
		{
			name:     "mismatched supported chains should error",
			ct:       defaultTransmitter,
			ctChains: []protocol.ChainSelector{1},
			dr: func() *executor_mocks.MockDestinationReader {
				dr := executor_mocks.NewMockDestinationReader(t)
				dr.EXPECT().GetCCVSForMessage(mock.Anything, mock.Anything).Return(coordinator.CCVAddressInfo{}, nil).Maybe()
				return dr
			},
			drChains:                   []protocol.ChainSelector{1, 2},
			vr:                         mockVerifierResultCreator,
			msg:                        coordinator.MessageWithCCVData{Message: generateFakeMessage(1, 2, 1, nil, address1)},
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
			ctChains: []protocol.ChainSelector{1},
			dr: func() *executor_mocks.MockDestinationReader {
				dr := executor_mocks.NewMockDestinationReader(t)
				dr.EXPECT().GetCCVSForMessage(mock.Anything, mock.Anything).Return(coordinator.CCVAddressInfo{}, nil).Maybe()
				return dr
			},
			drChains:                   []protocol.ChainSelector{1},
			vr:                         mockVerifierResultCreator,
			msg:                        coordinator.MessageWithCCVData{Message: generateFakeMessage(1, 2, 1, nil, address1)},
			validateShouldError:        false,
			validateMessageShouldError: false,
			executeShouldError:         true,
		},
		{
			name: "Should only use up to threshold amount of optional CCVs",
			ct: func() *executor_mocks.MockContractTransmitter {
				ct := executor_mocks.NewMockContractTransmitter(t)
				ct.EXPECT().ConvertAndWriteMessageToChain(mock.Anything, mock.MatchedBy(func(report coordinator.AbstractAggregatedReport) bool {
					wantMsg := generateFakeMessage(1, 2, 1, address1, address2)
					return assert.ObjectsAreEqual(wantMsg, report.Message) &&
						len(report.CCVS) == 1 &&
						len(report.CCVData) == 1 &&
						string(report.CCVData[0]) == "data1"
				})).Return(nil).Once()
				return ct
			},
			ctChains: []protocol.ChainSelector{1},
			dr: func() *executor_mocks.MockDestinationReader {
				dr := executor_mocks.NewMockDestinationReader(t)
				dr.EXPECT().GetCCVSForMessage(mock.Anything, mock.Anything).Return(coordinator.CCVAddressInfo{
					OptionalCCVs:      []protocol.UnknownAddress{address1, address2},
					OptionalThreshold: 1,
				}, nil).Maybe()
				return dr
			},
			drChains: []protocol.ChainSelector{1},
			vr: func(msg protocol.Message) *executor_mocks.MockVerifierResultReader {
				vr := executor_mocks.NewMockVerifierResultReader(t)
				messageID, _ := msg.MessageID()
				vr.EXPECT().GetVerifierResults(mock.Anything, mock.Anything).Return([]protocol.VerifierResult{
					{MessageID: messageID, Message: msg, MessageCCVAddresses: []protocol.UnknownAddress{address1}, CCVData: []byte("data1"), VerifierDestAddress: address1, MessageExecutorAddress: address2},
					{MessageID: messageID, Message: msg, MessageCCVAddresses: []protocol.UnknownAddress{address2}, CCVData: []byte("data2"), VerifierDestAddress: address2, MessageExecutorAddress: address2},
				}, nil).Maybe()
				return vr
			},
			msg: coordinator.MessageWithCCVData{Message: generateFakeMessage(1, 2, 1, address1, address2)},
		},
		{
			name: "Should support a 0 threshold for optional CCVs",
			ct: func() *executor_mocks.MockContractTransmitter {
				ct := executor_mocks.NewMockContractTransmitter(t)
				ct.EXPECT().ConvertAndWriteMessageToChain(mock.Anything, coordinator.AbstractAggregatedReport{
					Message: generateFakeMessage(1, 2, 1, nil, address1),
					CCVS:    []protocol.UnknownAddress{},
					CCVData: [][]byte{},
				}).Return(nil).Once()
				return ct
			},
			ctChains: []protocol.ChainSelector{1},
			dr: func() *executor_mocks.MockDestinationReader {
				dr := executor_mocks.NewMockDestinationReader(t)
				dr.EXPECT().GetCCVSForMessage(mock.Anything, mock.Anything).Return(coordinator.CCVAddressInfo{
					OptionalCCVs:      []protocol.UnknownAddress{address1, address2},
					OptionalThreshold: 0,
				}, nil).Maybe()
				return dr
			},
			drChains: []protocol.ChainSelector{1},
			vr: func(protocol.Message) *executor_mocks.MockVerifierResultReader {
				vr := executor_mocks.NewMockVerifierResultReader(t)
				vr.EXPECT().GetVerifierResults(mock.Anything, mock.Anything).Return([]protocol.VerifierResult{
					{VerifierDestAddress: address1, CCVData: []byte("data"), MessageExecutorAddress: address1},
					{VerifierDestAddress: address2, CCVData: []byte("data"), MessageExecutorAddress: address1},
				}, nil).Maybe()
				return vr
			},
			msg: coordinator.MessageWithCCVData{Message: generateFakeMessage(1, 2, 1, nil, address1)},
		},
		{
			name: "Should fail to execute if all verifier result messageExecutorAddress does not match defaultExecutorAddress",
			ct: func() *executor_mocks.MockContractTransmitter {
				// ConvertAndWriteMessageToChain should not be called if executor address doesn't match
				ct := executor_mocks.NewMockContractTransmitter(t)
				return ct
			},
			ctChains: []protocol.ChainSelector{1},
			dr: func() *executor_mocks.MockDestinationReader {
				dr := executor_mocks.NewMockDestinationReader(t)
				dr.EXPECT().GetCCVSForMessage(mock.Anything, mock.Anything).Return(coordinator.CCVAddressInfo{
					OptionalCCVs:      []protocol.UnknownAddress{address1, address2},
					OptionalThreshold: 1,
				}, nil).Maybe()
				return dr
			},
			drChains: []protocol.ChainSelector{1},
			vr: func(protocol.Message) *executor_mocks.MockVerifierResultReader {
				vr := executor_mocks.NewMockVerifierResultReader(t)
				// MessageExecutorAddress is not equal to defaultExecutorAddress (address1).
				vr.EXPECT().GetVerifierResults(mock.Anything, mock.Anything).Return([]protocol.VerifierResult{
					{VerifierDestAddress: address2, CCVData: []byte("data"), MessageExecutorAddress: address2},
					{VerifierDestAddress: address2, CCVData: []byte("data"), MessageExecutorAddress: address2},
				}, nil).Maybe()
				return vr
			},
			msg:                coordinator.MessageWithCCVData{Message: generateFakeMessage(1, 2, 1, nil, address1)},
			executeShouldError: true,
		},
		{
			name: "Should continue to execute if one verifier result messageExecutorAddress does not match defaultExecutorAddress and meets quorum",
			ct: func() *executor_mocks.MockContractTransmitter {
				// ConvertAndWriteMessageToChain should not be called if executor address doesn't match
				ct := executor_mocks.NewMockContractTransmitter(t)
				return ct
			},
			ctChains: []protocol.ChainSelector{1},
			dr: func() *executor_mocks.MockDestinationReader {
				dr := executor_mocks.NewMockDestinationReader(t)
				dr.EXPECT().GetCCVSForMessage(mock.Anything, mock.Anything).Return(coordinator.CCVAddressInfo{
					OptionalCCVs:      []protocol.UnknownAddress{address1, address2},
					OptionalThreshold: 1,
				}, nil).Maybe()
				return dr
			},
			drChains: []protocol.ChainSelector{1},
			vr: func(protocol.Message) *executor_mocks.MockVerifierResultReader {
				vr := executor_mocks.NewMockVerifierResultReader(t)
				// MessageExecutorAddress is not equal to defaultExecutorAddress (address1).
				vr.EXPECT().GetVerifierResults(mock.Anything, mock.Anything).Return([]protocol.VerifierResult{
					{VerifierDestAddress: address1, CCVData: []byte("data"), MessageExecutorAddress: address1},
					{VerifierDestAddress: address2, CCVData: []byte("data"), MessageExecutorAddress: address2},
				}, nil).Maybe()
				return vr
			},
			msg:                coordinator.MessageWithCCVData{Message: generateFakeMessage(1, 2, 1, nil, address1)},
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
			allRMNReaders := make(map[protocol.ChainSelector]ccvcommon.RMNRemoteReader)
			dr := tc.dr()
			for _, chain := range tc.drChains {
				allDestinationReaders[chain] = dr
				allRMNReaders[chain] = dr
			}
			curseChecker := cursechecker.NewCachedCurseChecker(cursechecker.Params{
				Lggr:        logger.Test(t),
				RmnReaders:  allRMNReaders,
				CacheExpiry: 1 * time.Second,
			})
			defaultExecutorAddresses := make(map[protocol.ChainSelector]protocol.UnknownAddress)
			for _, chain := range tc.drChains {
				defaultExecutorAddresses[chain] = address1
			}
			defaultExecutorAddresses[tc.msg.Message.SourceChainSelector] = address2
			executor := NewChainlinkExecutor(logger.Test(t), allContractTransmitters, allDestinationReaders, curseChecker, tc.vr(tc.msg.Message), monitoring.NewNoopExecutorMonitoring(), defaultExecutorAddresses)
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
			dr.AssertNotCalled(t, "GetMessageExecutionState")
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

	reqData1 := protocol.VerifierResult{VerifierDestAddress: reqAddr1, CCVData: []byte("req1"), Timestamp: time.UnixMilli(10)}
	reqData2 := protocol.VerifierResult{VerifierDestAddress: reqAddr2, CCVData: []byte("req2"), Timestamp: time.UnixMilli(20)}
	optData1 := protocol.VerifierResult{VerifierDestAddress: optAddr1, CCVData: []byte("opt1"), Timestamp: time.UnixMilli(5)}
	optData2 := protocol.VerifierResult{VerifierDestAddress: optAddr2, CCVData: []byte("opt2"), Timestamp: time.UnixMilli(25)}
	optData3 := protocol.VerifierResult{VerifierDestAddress: optAddr3, CCVData: []byte("opt3"), Timestamp: time.UnixMilli(15)}
	otherData := protocol.VerifierResult{VerifierDestAddress: otherAddr, CCVData: []byte("other"), Timestamp: time.UnixMilli(100)}

	testcases := []struct {
		name                string
		ccvDatas            []protocol.VerifierResult
		receiverCCVInfo     coordinator.CCVAddressInfo
		expectedOrderedData [][]byte
		expectedOfframps    []protocol.UnknownAddress
		expectedTimestamp   int64
		expectedErr         error
		expectedErrContains string
	}{
		{
			name:     "happy path",
			ccvDatas: []protocol.VerifierResult{reqData1, reqData2, optData1, optData2, optData3, otherData},
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
			ccvDatas: []protocol.VerifierResult{reqData1, optData1, optData2, optData3},
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
			ccvDatas: []protocol.VerifierResult{reqData1, reqData2, optData1},
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
			ccvDatas: []protocol.VerifierResult{reqData1, reqData2, optData1, optData2, optData3},
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
			ccvDatas: []protocol.VerifierResult{reqData1, reqData2, optData1, optData2, optData3},
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
			ccvDatas: []protocol.VerifierResult{reqData1, reqData2, optData1, optData2, optData3},
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
			ccvDatas: []protocol.VerifierResult{reqData1, reqData2, optData1, optData2, optData3},
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

// generateFakeMessage creates a fake protocol.Message for testing purposes.
// It accepts destChainSelector, sourceChainSelector, and sequenceNumber as parameters.
func generateFakeMessage(destChainSelector, sourceChainSelector protocol.ChainSelector, sequenceNumber protocol.SequenceNumber, verifierAddress, executorAddress protocol.UnknownAddress) protocol.Message {
	// Use zero addresses and empty byte slices for simplicity
	var (
		emptyAddress protocol.UnknownAddress
		emptyBytes   []byte
	)
	ccvAndExecutorHash, _ := protocol.ComputeCCVAndExecutorHash([]protocol.UnknownAddress{verifierAddress}, executorAddress)
	return protocol.Message{
		Sender:               emptyAddress,
		Data:                 emptyBytes,
		OnRampAddress:        emptyAddress,
		TokenTransfer:        nil,
		OffRampAddress:       emptyAddress,
		DestBlob:             emptyBytes,
		Receiver:             emptyAddress,
		SourceChainSelector:  sourceChainSelector,
		DestChainSelector:    destChainSelector,
		SequenceNumber:       sequenceNumber,
		ExecutionGasLimit:    0,
		CcipReceiveGasLimit:  0,
		Finality:             0,
		CcvAndExecutorHash:   ccvAndExecutorHash,
		DestBlobLength:       0,
		TokenTransferLength:  0,
		DataLength:           0,
		ReceiverLength:       0,
		SenderLength:         0,
		Version:              1,
		OffRampAddressLength: 0,
		OnRampAddressLength:  0,
	}
}
