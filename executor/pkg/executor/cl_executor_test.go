package executor

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	coordinator "github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/cursechecker"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// setupTestExecutor creates a test executor with the provided mocks.
func setupTestExecutor(
	t *testing.T,
	ct map[protocol.ChainSelector]*mocks.MockContractTransmitter,
	dr map[protocol.ChainSelector]*mocks.MockDestinationReader,
	vr *mocks.MockVerifierResultReader,
	address1, address2 protocol.UnknownAddress,
	sourceChainSelector protocol.ChainSelector,
) *ChainlinkExecutor {
	allContractTransmitters := make(map[protocol.ChainSelector]chainaccess.ContractTransmitter)
	for chain, mockCT := range ct {
		allContractTransmitters[chain] = mockCT
	}

	allDestinationReaders := make(map[protocol.ChainSelector]chainaccess.DestinationReader)
	allRMNReaders := make(map[protocol.ChainSelector]chainaccess.RMNCurseReader)
	for chain, mockDR := range dr {
		allDestinationReaders[chain] = mockDR
		allRMNReaders[chain] = mockDR
	}

	curseChecker := cursechecker.NewCachedCurseChecker(cursechecker.Params{
		Lggr:        logger.Test(t),
		RmnReaders:  allRMNReaders,
		CacheExpiry: 1 * time.Second,
	})

	defaultExecutorAddresses := map[protocol.ChainSelector]protocol.UnknownAddress{
		1: address1,
		2: address2,
	}
	defaultExecutorAddresses[sourceChainSelector] = address2

	return NewChainlinkExecutor(
		logger.Test(t),
		allContractTransmitters,
		allDestinationReaders,
		curseChecker,
		vr,
		monitoring.NewNoopExecutorMonitoring(),
		defaultExecutorAddresses,
	)
}

func Test_ChainlinkExecutor_Validate(t *testing.T) {
	address1, err := protocol.RandomAddress()
	assert.NoError(t, err)
	address2, err := protocol.RandomAddress()
	assert.NoError(t, err)

	testcases := []struct {
		name        string
		ctChains    []protocol.ChainSelector
		drChains    []protocol.ChainSelector
		expectError bool
	}{
		{
			name:        "valid case - matching chains",
			ctChains:    []protocol.ChainSelector{1, 2},
			drChains:    []protocol.ChainSelector{1, 2},
			expectError: false,
		},
		{
			name:        "mismatched supported chains should error",
			ctChains:    []protocol.ChainSelector{1},
			drChains:    []protocol.ChainSelector{1, 2},
			expectError: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ct := make(map[protocol.ChainSelector]*mocks.MockContractTransmitter)
			for _, chain := range tc.ctChains {
				mockCT := mocks.NewMockContractTransmitter(t)
				ct[chain] = mockCT
			}

			dr := make(map[protocol.ChainSelector]*mocks.MockDestinationReader)
			for _, chain := range tc.drChains {
				mockDR := mocks.NewMockDestinationReader(t)
				dr[chain] = mockDR
			}

			vr := mocks.NewMockVerifierResultReader(t)
			executor := setupTestExecutor(t, ct, dr, vr, address1, address2, 2)

			err := executor.Validate()
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_ChainlinkExecutor_HandleMessage_CurseCheck(t *testing.T) {
	address1, err := protocol.RandomAddress()
	assert.NoError(t, err)
	address2, err := protocol.RandomAddress()
	assert.NoError(t, err)

	testcases := []struct {
		name          string
		isCursed      bool
		expectedRetry bool
		expectedError bool
	}{
		{
			name:          "cursed, should retry",
			isCursed:      true,
			expectedRetry: true,
			expectedError: false,
		},
		// we don't need to test the non cursed scenario, it will be covered in later tests
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ct := map[protocol.ChainSelector]*mocks.MockContractTransmitter{
				1: mocks.NewMockContractTransmitter(t),
			}
			dr := map[protocol.ChainSelector]*mocks.MockDestinationReader{
				1: mocks.NewMockDestinationReader(t),
			}
			vr := mocks.NewMockVerifierResultReader(t)
			msg := generateFakeMessage(1, 2, 1, nil, address2)

			curseChecker := mocks.NewMockCurseChecker(t)
			curseChecker.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(tc.isCursed).Once()
			executor := setupTestExecutor(t, ct, dr, vr, address1, address2, 2)
			executor.curseChecker = curseChecker

			shouldRetry, err := executor.HandleMessage(context.Background(), msg)
			assert.Equal(t, tc.expectedRetry, shouldRetry)
			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_ChainlinkExecutor_HandleMessage_VerifierResults(t *testing.T) {
	address1, err := protocol.RandomAddress()
	assert.NoError(t, err)
	address2, err := protocol.RandomAddress()
	assert.NoError(t, err)

	testcases := []struct {
		name                 string
		verifierResults      []protocol.VerifierResult
		verifierResultsErr   error
		ccvInfo              protocol.CCVAddressInfo
		ccvInfoErr           error
		expectedRetry        bool
		expectedError        bool
		expectedNoResultsErr bool
	}{
		{
			name: "valid verifier results - should continue",
			verifierResults: []protocol.VerifierResult{
				{MessageID: protocol.Bytes32{}, Message: generateFakeMessage(1, 2, 1, nil, address2), MessageCCVAddresses: []protocol.UnknownAddress{}, MessageExecutorAddress: address2},
			},
			ccvInfo:       protocol.CCVAddressInfo{},
			expectedRetry: false,
			expectedError: false,
		},
		{
			name:               "GetVerifierResults returns error - should retry",
			verifierResultsErr: errors.New("verifier results error"),
			expectedRetry:      true,
			expectedError:      true,
		},
		{
			name:                 "no verifier results - should retry with error",
			verifierResults:      []protocol.VerifierResult{},
			ccvInfo:              protocol.CCVAddressInfo{},
			expectedRetry:        true,
			expectedError:        true,
			expectedNoResultsErr: true,
		},
		{
			name: "verifier results filtered out due to executor address mismatch - should retry with error",
			verifierResults: []protocol.VerifierResult{
				{MessageID: protocol.Bytes32{}, Message: generateFakeMessage(1, 2, 1, nil, address1), MessageCCVAddresses: []protocol.UnknownAddress{}, MessageExecutorAddress: address1}, // address1 doesn't match defaultExecutorAddress[2] = address2
			},
			ccvInfo:              protocol.CCVAddressInfo{},
			expectedRetry:        true,
			expectedError:        true,
			expectedNoResultsErr: true,
		},
		{
			name: "impossible receiver verifier quorum - should skip",
			verifierResults: []protocol.VerifierResult{
				{MessageID: protocol.Bytes32{}, Message: generateFakeMessage(1, 2, 1, nil, address2), MessageCCVAddresses: []protocol.UnknownAddress{}, MessageExecutorAddress: address2},
			},
			ccvInfo: protocol.CCVAddressInfo{
				OptionalCCVs:      []protocol.UnknownAddress{address1},
				OptionalThreshold: 1,
			},
			expectedRetry: false,
			expectedError: false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ct := map[protocol.ChainSelector]*mocks.MockContractTransmitter{
				1: mocks.NewMockContractTransmitter(t),
			}

			dr := map[protocol.ChainSelector]*mocks.MockDestinationReader{
				1: mocks.NewMockDestinationReader(t),
			}
			dr[1].EXPECT().GetRMNCursedSubjects(mock.Anything).Return([]protocol.Bytes16{}, nil).Once()
			dr[1].EXPECT().GetMessageSuccess(mock.Anything, mock.Anything).Return(false, nil).Once()
			dr[1].EXPECT().GetExecutionAttempts(mock.Anything, mock.Anything).Return([]protocol.ExecutionAttempt{}, nil).Maybe()
			// GetCCVSForMessage is called in parallel with GetVerifierResults, so we need to set it up even if verifier results error
			dr[1].EXPECT().GetCCVSForMessage(mock.Anything, mock.Anything).Return(tc.ccvInfo, tc.ccvInfoErr).Maybe()

			vr := mocks.NewMockVerifierResultReader(t)
			msg := generateFakeMessage(1, 2, 1, nil, address2)
			messageID, _ := msg.MessageID()

			if tc.verifierResultsErr != nil {
				vr.EXPECT().GetVerifierResults(mock.Anything, mock.Anything).Return(nil, tc.verifierResultsErr).Once()
			} else {
				// Update messageID in verifier results
				results := make([]protocol.VerifierResult, len(tc.verifierResults))
				for i, result := range tc.verifierResults {
					result.MessageID = messageID
					result.Message = msg
					results[i] = result
				}
				vr.EXPECT().GetVerifierResults(mock.Anything, mock.Anything).Return(results, nil).Maybe()
			}

			// Only expect ConvertAndWriteMessageToChain if we have valid results and can proceed
			if !tc.expectedError && !tc.expectedNoResultsErr && len(tc.verifierResults) > 0 && tc.verifierResults[0].MessageExecutorAddress.Equal(address2) {
				ct[1].EXPECT().ConvertAndWriteMessageToChain(mock.Anything, mock.Anything).Return(nil).Maybe()
			}

			executor := setupTestExecutor(t, ct, dr, vr, address1, address2, 2)

			shouldRetry, err := executor.HandleMessage(context.Background(), msg)
			assert.Equal(t, tc.expectedRetry, shouldRetry)
			if tc.expectedError {
				assert.Error(t, err)
				if tc.expectedNoResultsErr {
					assert.Contains(t, err.Error(), "no verifier results")
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_ChainlinkExecutor_HandleMessage_OrderCCVData(t *testing.T) {
	address1, err := protocol.RandomAddress()
	assert.NoError(t, err)
	address2, err := protocol.RandomAddress()
	assert.NoError(t, err)

	testcases := []struct {
		name            string
		verifierResults []protocol.VerifierResult
		ccvInfo         protocol.CCVAddressInfo
		orderCCVDataErr bool
		expectedRetry   bool
		expectedError   bool
	}{
		{
			name: "orderCCVData succeeds - should continue",
			verifierResults: []protocol.VerifierResult{
				{MessageID: protocol.Bytes32{}, Message: generateFakeMessage(1, 2, 1, address1, address2), MessageCCVAddresses: []protocol.UnknownAddress{address1}, VerifierDestAddress: address1, CCVData: []byte("data1"), MessageExecutorAddress: address2},
			},
			ccvInfo: protocol.CCVAddressInfo{
				OptionalCCVs:      []protocol.UnknownAddress{address1},
				OptionalThreshold: 1,
			},
			expectedRetry: false,
			expectedError: false,
		},
		{
			name: "orderCCVData fails due to insufficient verifiers - should retry",
			verifierResults: []protocol.VerifierResult{
				{MessageID: protocol.Bytes32{}, Message: generateFakeMessage(1, 2, 1, address1, address2), MessageCCVAddresses: []protocol.UnknownAddress{address1}, VerifierDestAddress: address1, CCVData: []byte("data1"), MessageExecutorAddress: address2},
			},
			ccvInfo: protocol.CCVAddressInfo{
				RequiredCCVs:      []protocol.UnknownAddress{address2}, // address2 not in verifier results
				OptionalCCVs:      []protocol.UnknownAddress{address1},
				OptionalThreshold: 0,
			},
			orderCCVDataErr: true,
			expectedRetry:   true,
			expectedError:   true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ct := map[protocol.ChainSelector]*mocks.MockContractTransmitter{
				1: mocks.NewMockContractTransmitter(t),
			}

			dr := map[protocol.ChainSelector]*mocks.MockDestinationReader{
				1: mocks.NewMockDestinationReader(t),
			}
			dr[1].EXPECT().GetRMNCursedSubjects(mock.Anything).Return([]protocol.Bytes16{}, nil).Once()
			dr[1].EXPECT().GetMessageSuccess(mock.Anything, mock.Anything).Return(false, nil).Once()
			dr[1].EXPECT().GetExecutionAttempts(mock.Anything, mock.Anything).Return([]protocol.ExecutionAttempt{}, nil).Maybe()
			dr[1].EXPECT().GetCCVSForMessage(mock.Anything, mock.Anything).Return(tc.ccvInfo, nil).Maybe()

			vr := mocks.NewMockVerifierResultReader(t)
			msg := generateFakeMessage(1, 2, 1, address1, address2)
			messageID, _ := msg.MessageID()

			// Update messageID in verifier results
			results := make([]protocol.VerifierResult, len(tc.verifierResults))
			for i, result := range tc.verifierResults {
				result.MessageID = messageID
				result.Message = msg
				results[i] = result
			}
			vr.EXPECT().GetVerifierResults(mock.Anything, mock.Anything).Return(results, nil).Maybe()

			if !tc.orderCCVDataErr {
				ct[1].EXPECT().ConvertAndWriteMessageToChain(mock.Anything, mock.Anything).Return(nil).Once()
			}

			executor := setupTestExecutor(t, ct, dr, vr, address1, address2, 2)

			shouldRetry, err := executor.HandleMessage(context.Background(), msg)
			assert.Equal(t, tc.expectedRetry, shouldRetry)
			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_ChainlinkExecutor_HandleMessage_ConvertAndWrite(t *testing.T) {
	address1, err := protocol.RandomAddress()
	assert.NoError(t, err)
	address2, err := protocol.RandomAddress()
	assert.NoError(t, err)

	testcases := []struct {
		name                string
		convertAndWriteErr  error
		expectedRetry       bool
		expectedError       bool
		expectedReportCheck func(*testing.T, protocol.AbstractAggregatedReport) bool
	}{
		{
			name:               "ConvertAndWriteMessageToChain succeeds - should complete",
			convertAndWriteErr: nil,
			expectedRetry:      false,
			expectedError:      false,
		},
		{
			name:               "ConvertAndWriteMessageToChain fails - should retry",
			convertAndWriteErr: errors.New("convert and write failed"),
			expectedRetry:      true,
			expectedError:      true,
		},
		{
			name:               "ConvertAndWriteMessageToChain with correct report structure",
			convertAndWriteErr: nil,
			expectedRetry:      false,
			expectedError:      false,
			expectedReportCheck: func(t *testing.T, report protocol.AbstractAggregatedReport) bool {
				return len(report.CCVS) == 1 &&
					len(report.CCVData) == 1 &&
					string(report.CCVData[0]) == "data1"
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ct := map[protocol.ChainSelector]*mocks.MockContractTransmitter{
				1: mocks.NewMockContractTransmitter(t),
			}

			dr := map[protocol.ChainSelector]*mocks.MockDestinationReader{
				1: mocks.NewMockDestinationReader(t),
			}
			dr[1].EXPECT().GetRMNCursedSubjects(mock.Anything).Return([]protocol.Bytes16{}, nil).Once()
			dr[1].EXPECT().GetMessageSuccess(mock.Anything, mock.Anything).Return(false, nil).Once()
			dr[1].EXPECT().GetExecutionAttempts(mock.Anything, mock.Anything).Return([]protocol.ExecutionAttempt{}, nil).Once()
			dr[1].EXPECT().GetCCVSForMessage(mock.Anything, mock.Anything).Return(protocol.CCVAddressInfo{
				OptionalCCVs:      []protocol.UnknownAddress{address1},
				OptionalThreshold: 1,
			}, nil).Maybe()

			vr := mocks.NewMockVerifierResultReader(t)
			msg := generateFakeMessage(1, 2, 1, address1, address2)
			messageID, _ := msg.MessageID()

			vr.EXPECT().GetVerifierResults(mock.Anything, mock.Anything).Return([]protocol.VerifierResult{
				{MessageID: messageID, Message: msg, MessageCCVAddresses: []protocol.UnknownAddress{address1}, VerifierDestAddress: address1, CCVData: []byte("data1"), MessageExecutorAddress: address2},
			}, nil).Maybe()

			if tc.expectedReportCheck != nil {
				ct[1].EXPECT().ConvertAndWriteMessageToChain(mock.Anything, mock.MatchedBy(func(report protocol.AbstractAggregatedReport) bool {
					return tc.expectedReportCheck(t, report)
				})).Return(tc.convertAndWriteErr).Once()
			} else {
				ct[1].EXPECT().ConvertAndWriteMessageToChain(mock.Anything, mock.Anything).Return(tc.convertAndWriteErr).Once()
			}

			executor := setupTestExecutor(t, ct, dr, vr, address1, address2, 2)

			shouldRetry, err := executor.HandleMessage(context.Background(), msg)
			assert.Equal(t, tc.expectedRetry, shouldRetry)
			if tc.expectedError {
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

	reqData1 := protocol.VerifierResult{VerifierDestAddress: reqAddr1, CCVData: []byte("req1"), Timestamp: time.UnixMilli(10)}
	reqData2 := protocol.VerifierResult{VerifierDestAddress: reqAddr2, CCVData: []byte("req2"), Timestamp: time.UnixMilli(20)}
	optData1 := protocol.VerifierResult{VerifierDestAddress: optAddr1, CCVData: []byte("opt1"), Timestamp: time.UnixMilli(5)}
	optData2 := protocol.VerifierResult{VerifierDestAddress: optAddr2, CCVData: []byte("opt2"), Timestamp: time.UnixMilli(25)}
	optData3 := protocol.VerifierResult{VerifierDestAddress: optAddr3, CCVData: []byte("opt3"), Timestamp: time.UnixMilli(15)}
	otherData := protocol.VerifierResult{VerifierDestAddress: otherAddr, CCVData: []byte("other"), Timestamp: time.UnixMilli(100)}

	testcases := []struct {
		name                string
		ccvDatas            []protocol.VerifierResult
		receiverCCVInfo     protocol.CCVAddressInfo
		expectedOrderedData [][]byte
		expectedOfframps    []protocol.UnknownAddress
		expectedTimestamp   int64
		expectedErr         error
		expectedErrContains string
	}{
		{
			name:     "happy path",
			ccvDatas: []protocol.VerifierResult{reqData1, reqData2, optData1, optData2, optData3, otherData},
			receiverCCVInfo: protocol.CCVAddressInfo{
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
			receiverCCVInfo: protocol.CCVAddressInfo{
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
			receiverCCVInfo: protocol.CCVAddressInfo{
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
			receiverCCVInfo: protocol.CCVAddressInfo{
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
			receiverCCVInfo: protocol.CCVAddressInfo{
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
			receiverCCVInfo: protocol.CCVAddressInfo{
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
			receiverCCVInfo: protocol.CCVAddressInfo{
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
// If verifierAddress is nil, an empty slice is used for CCV addresses.
func generateFakeMessage(destChainSelector, sourceChainSelector protocol.ChainSelector, sequenceNumber protocol.SequenceNumber, verifierAddress, executorAddress protocol.UnknownAddress) protocol.Message {
	// Use zero addresses and empty byte slices for simplicity
	var (
		emptyAddress protocol.UnknownAddress
		emptyBytes   []byte
	)
	var ccvAddresses []protocol.UnknownAddress
	if len(verifierAddress) > 0 {
		ccvAddresses = []protocol.UnknownAddress{verifierAddress}
	} else {
		ccvAddresses = []protocol.UnknownAddress{}
	}
	ccvAndExecutorHash, _ := protocol.ComputeCCVAndExecutorHash(ccvAddresses, executorAddress)
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
