package contracttransmitter

import (
	"context"
	"errors"
	"math"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	txmgr "github.com/smartcontractkit/chainlink-evm/pkg/txmgr"
)

// mockTxManager is a simple mock that implements only the CreateTransaction method we need for testing
// We embed the TxManager interface so the type satisfies it, and delegate CreateTransaction to our mock.
type mockTxManager struct {
	mock.Mock
	// Embed to satisfy interface but don't actually use other methods
	txmgr.TxManager
}

func (m *mockTxManager) CreateTransaction(ctx context.Context, txRequest txmgr.TxRequest) (txmgr.Tx, error) {
	args := m.Called(ctx, txRequest)
	if tx, ok := args.Get(0).(txmgr.Tx); ok {
		return tx, args.Error(1)
	}
	return txmgr.Tx{}, args.Error(1)
}

// mockRoundRobin is a simple mock implementation of keys.RoundRobin.
type mockRoundRobin struct {
	mock.Mock
}

func (m *mockRoundRobin) GetNextAddress(ctx context.Context, addresses ...common.Address) (common.Address, error) {
	args := m.Called(ctx, addresses)
	return args.Get(0).(common.Address), args.Error(1)
}

type gasEstimatorFunc func(context.Context, ethereum.CallMsg) (uint64, error)

func (f gasEstimatorFunc) EstimateGas(ctx context.Context, msg ethereum.CallMsg) (uint64, error) {
	return f(ctx, msg)
}

func lowGasEstimator(context.Context, ethereum.CallMsg) (uint64, error) {
	return 1, nil
}

func TestTXMEVMContractTransmitter_ConvertAndWriteMessageToChain(t *testing.T) {
	testKey := "test-key"
	testCases := []struct {
		name                     string
		report                   protocol.AbstractAggregatedReport
		setupMocks               func(*mockTxManager, *mockRoundRobin)
		expectedError            string
		expectedLogFields        map[string]any
		expectErrMessageEncoding bool
	}{
		{
			name: "successful transmission",
			report: protocol.AbstractAggregatedReport{
				CCVS: []protocol.UnknownAddress{
					protocol.UnknownAddress(common.HexToAddress("0x1111111111111111111111111111111111111111").Bytes()),
					protocol.UnknownAddress(common.HexToAddress("0x2222222222222222222222222222222222222222").Bytes()),
				},
				CCVData: [][]byte{
					[]byte("ccv_data_1"),
					[]byte("ccv_data_2"),
				},
				Message: mustCreateMessage(t, 1, 2, 100, 2000000, 1000000),
			},
			setupMocks: func(txm *mockTxManager, rr *mockRoundRobin) {
				fromAddr := common.HexToAddress("0xabcdef1234567890abcdef1234567890abcdef12")
				rr.On("GetNextAddress", mock.Anything, mock.Anything).Return(fromAddr, nil)

				expectedTx := txmgr.Tx{
					IdempotencyKey: &testKey,
				}

				txm.On("CreateTransaction", mock.Anything, mock.MatchedBy(func(req txmgr.TxRequest) bool {
					return req.FromAddress == fromAddr &&
						req.FeeLimit == uint64(2000000)+
							eip150ForwardingGasBuffer(1000000) &&
						len(req.EncodedPayload) > 0
				})).Return(expectedTx, nil)
			},
			expectedError: "",
		},
		{
			name: "error encoding message",
			report: protocol.AbstractAggregatedReport{
				Message: protocol.Message{
					SenderLength: 99, // mismatch: triggers validateLengthFields error
					Sender:       []byte{0x01},
				},
			},
			setupMocks:               func(txm *mockTxManager, rr *mockRoundRobin) {},
			expectedError:            "unable to submit txn: invalid message encoding",
			expectErrMessageEncoding: true,
		},
		{
			name: "error getting round-robin address",
			report: protocol.AbstractAggregatedReport{
				CCVS: []protocol.UnknownAddress{
					protocol.UnknownAddress(common.HexToAddress("0x1111111111111111111111111111111111111111").Bytes()),
				},
				CCVData: [][]byte{
					[]byte("ccv_data_1"),
				},
				Message: mustCreateMessage(t, 1, 2, 100, 1000000, 1000000),
			},
			setupMocks: func(txm *mockTxManager, rr *mockRoundRobin) {
				rr.On("GetNextAddress", mock.Anything, mock.Anything).Return(common.Address{}, errors.New("no available keys"))
			},
			expectedError: "skipping transmit, error getting round-robin from address: no available keys",
		},
		{
			name: "error creating transaction",
			report: protocol.AbstractAggregatedReport{
				CCVS: []protocol.UnknownAddress{
					protocol.UnknownAddress(common.HexToAddress("0x1111111111111111111111111111111111111111").Bytes()),
				},
				CCVData: [][]byte{
					[]byte("ccv_data_1"),
				},
				Message: mustCreateMessage(t, 1, 2, 100, 1000000, 1000000),
			},
			setupMocks: func(txm *mockTxManager, rr *mockRoundRobin) {
				fromAddr := common.HexToAddress("0xabcdef1234567890abcdef1234567890abcdef12")
				rr.On("GetNextAddress", mock.Anything, mock.Anything).Return(fromAddr, nil)

				txm.On("CreateTransaction", mock.Anything, mock.Anything).Return(
					txmgr.Tx{},
					errors.New("transaction pool full"),
				)
			},
			expectedError: "failed to create txm transaction: transaction pool full",
		},
		{
			name: "empty CCVs and CCVData",
			report: protocol.AbstractAggregatedReport{
				CCVS:    []protocol.UnknownAddress{},
				CCVData: [][]byte{},
				Message: mustCreateMessage(t, 1, 2, 100, 1000000, 1000000),
			},
			setupMocks: func(txm *mockTxManager, rr *mockRoundRobin) {
				fromAddr := common.HexToAddress("0xabcdef1234567890abcdef1234567890abcdef12")
				rr.On("GetNextAddress", mock.Anything, mock.Anything).Return(fromAddr, nil)

				expectedTx := txmgr.Tx{
					IdempotencyKey: &testKey,
				}

				txm.On("CreateTransaction", mock.Anything, mock.MatchedBy(func(req txmgr.TxRequest) bool {
					return req.FromAddress == fromAddr &&
						req.FeeLimit == uint64(1000000)+eip150ForwardingGasBuffer(1000000) &&
						len(req.EncodedPayload) > 0
				})).Return(expectedTx, nil)
			},
			expectedError: "",
		},
		{
			name: "multiple CCVs with large gas limit",
			report: protocol.AbstractAggregatedReport{
				CCVS: []protocol.UnknownAddress{
					protocol.UnknownAddress(common.HexToAddress("0x1111111111111111111111111111111111111111").Bytes()),
					protocol.UnknownAddress(common.HexToAddress("0x2222222222222222222222222222222222222222").Bytes()),
					protocol.UnknownAddress(common.HexToAddress("0x3333333333333333333333333333333333333333").Bytes()),
				},
				CCVData: [][]byte{
					[]byte("ccv_data_1"),
					[]byte("ccv_data_2"),
					[]byte("ccv_data_3"),
				},
				Message: mustCreateMessage(t, 1, 2, 100, 5000000, 5000000),
			},
			setupMocks: func(txm *mockTxManager, rr *mockRoundRobin) {
				fromAddr := common.HexToAddress("0xabcdef1234567890abcdef1234567890abcdef12")
				rr.On("GetNextAddress", mock.Anything, mock.Anything).Return(fromAddr, nil)

				expectedTx := txmgr.Tx{
					IdempotencyKey: &testKey,
				}

				txm.On("CreateTransaction", mock.Anything, mock.MatchedBy(func(req txmgr.TxRequest) bool {
					return req.FromAddress == fromAddr &&
						req.FeeLimit == uint64(5000000)+eip150ForwardingGasBuffer(5000000) &&
						len(req.EncodedPayload) > 0
				})).Return(expectedTx, nil)
			},
			expectedError: "",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			lggr := logger.Test(t)

			// Setup mocks
			mockTxm := new(mockTxManager)
			mockRR := new(mockRoundRobin)

			tc.setupMocks(mockTxm, mockRR)

			// Create contract transmitter
			offRampAddr := common.HexToAddress("0x9999999999999999999999999999999999999999")
			fromAddresses := []common.Address{
				common.HexToAddress("0xabcdef1234567890abcdef1234567890abcdef12"),
				common.HexToAddress("0xfedcba0987654321fedcba0987654321fedcba09"),
			}

			transmitter := NewEVMContractTransmitterFromTxm(
				lggr,
				protocol.ChainSelector(1),
				mockTxm,
				offRampAddr,
				mockRR,
				fromAddresses,
				monitoring.NewNoopExecutorMonitoring(),
				WithGasEstimator(gasEstimatorFunc(lowGasEstimator)),
			)

			// Execute
			err := transmitter.ConvertAndWriteMessageToChain(ctx, tc.report)

			// Assert
			if tc.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
				if tc.expectErrMessageEncoding {
					assert.True(t, errors.Is(err, executor.ErrMessageEncoding))
				}
			} else {
				require.NoError(t, err)
			}

			mockTxm.AssertExpectations(t)
			mockRR.AssertExpectations(t)
		})
	}
}

func TestNewEVMContractTransmitterFromTxm(t *testing.T) {
	testCases := []struct {
		name                string
		chainSelector       protocol.ChainSelector
		offRampAddress      common.Address
		fromAddresses       []common.Address
		validateTransmitter func(*testing.T, *TXMEVMContractTransmitter)
	}{
		{
			name:           "creates transmitter with all fields set",
			chainSelector:  protocol.ChainSelector(1),
			offRampAddress: common.HexToAddress("0x1111111111111111111111111111111111111111"),
			fromAddresses: []common.Address{
				common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			},
			validateTransmitter: func(t *testing.T, ct *TXMEVMContractTransmitter) {
				assert.NotNil(t, ct.lggr)
				assert.NotNil(t, ct.TxmClient)
				assert.NotNil(t, ct.keys)
				assert.Equal(t, protocol.ChainSelector(1), ct.chainSelector)
				assert.Equal(t, common.HexToAddress("0x1111111111111111111111111111111111111111"), ct.OffRampAddress)
				assert.Len(t, ct.fromAddresses, 1)
			},
		},
		{
			name:           "creates transmitter with multiple from addresses",
			chainSelector:  protocol.ChainSelector(2),
			offRampAddress: common.HexToAddress("0x2222222222222222222222222222222222222222"),
			fromAddresses: []common.Address{
				common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
				common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
				common.HexToAddress("0xcccccccccccccccccccccccccccccccccccccccc"),
			},
			validateTransmitter: func(t *testing.T, ct *TXMEVMContractTransmitter) {
				assert.Equal(t, protocol.ChainSelector(2), ct.chainSelector)
				assert.Len(t, ct.fromAddresses, 3)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			lggr := logger.Test(t)
			mockTxm := new(mockTxManager)
			mockRR := new(mockRoundRobin)

			transmitter := NewEVMContractTransmitterFromTxm(
				lggr,
				tc.chainSelector,
				mockTxm,
				tc.offRampAddress,
				mockRR,
				tc.fromAddresses,
				monitoring.NewNoopExecutorMonitoring(),
			)

			require.NotNil(t, transmitter)
			tc.validateTransmitter(t, transmitter)
		})
	}
}

func TestTXMEVMContractTransmitter_ABIEncoding(t *testing.T) {
	testKey := "test-key"
	testCases := []struct {
		name          string
		report        protocol.AbstractAggregatedReport
		validateError func(*testing.T, error)
	}{
		{
			name: "valid report encodes successfully",
			report: protocol.AbstractAggregatedReport{
				CCVS: []protocol.UnknownAddress{
					protocol.UnknownAddress(common.HexToAddress("0x1111111111111111111111111111111111111111").Bytes()),
				},
				CCVData: [][]byte{
					[]byte("test_data"),
				},
				Message: mustCreateMessage(t, 1, 2, 100, 1000000, 1000000),
			},
			validateError: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			lggr := logger.Test(t)

			mockTxm := new(mockTxManager)
			mockRR := new(mockRoundRobin)

			fromAddr := common.HexToAddress("0xabcdef1234567890abcdef1234567890abcdef12")
			mockRR.On("GetNextAddress", mock.Anything, mock.Anything).Return(fromAddr, nil)

			var capturedPayload []byte
			expectedTx := txmgr.Tx{
				IdempotencyKey: &testKey,
			}

			mockTxm.On("CreateTransaction", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
				req := args.Get(1).(txmgr.TxRequest)
				capturedPayload = req.EncodedPayload
			}).Return(expectedTx, nil)

			transmitter := NewEVMContractTransmitterFromTxm(
				lggr,
				protocol.ChainSelector(1),
				mockTxm,
				common.HexToAddress("0x9999999999999999999999999999999999999999"),
				mockRR,
				[]common.Address{fromAddr},
				monitoring.NewNoopExecutorMonitoring(),
				WithGasEstimator(gasEstimatorFunc(lowGasEstimator)),
			)

			err := transmitter.ConvertAndWriteMessageToChain(ctx, tc.report)
			tc.validateError(t, err)

			if err == nil {
				// Verify the payload is not empty and has expected structure
				assert.NotEmpty(t, capturedPayload)

				// Recompute what the expected payload should be using the actual encoding logic
				expectedMsg, _ := tc.report.Message.Encode()
				expectedCCVs := make([]common.Address, len(tc.report.CCVS))
				for i, ccv := range tc.report.CCVS {
					expectedCCVs[i] = common.HexToAddress(ccv.String())
				}
				expectedCCVData := tc.report.CCVData

				expectedPayload, err := offrampABI.Pack("execute", expectedMsg, expectedCCVs, expectedCCVData, DefaultGasLimitOverride)
				require.NoError(t, err)

				// Compare the payloads for byte-level equality
				assert.Equal(t, expectedPayload, capturedPayload)
			}
		})
	}
}

func TestTXMEVMContractTransmitter_RaisesStaleMessageGasFromRPC(t *testing.T) {
	ctx := context.Background()
	lggr := logger.Test(t)
	offRamp := common.HexToAddress("0x9999999999999999999999999999999999999999")
	from := common.HexToAddress("0xabcdef1234567890abcdef1234567890abcdef12")
	testKey := "test-key"

	mockRR := new(mockRoundRobin)
	mockRR.On("GetNextAddress", mock.Anything, mock.Anything).Return(from, nil)
	mockTxm := new(mockTxManager)
	mockTxm.On("CreateTransaction", mock.Anything, mock.MatchedBy(func(req txmgr.TxRequest) bool {
		return req.FeeLimit == 780629 && req.FromAddress == from && req.ToAddress == offRamp
	})).Return(txmgr.Tx{IdempotencyKey: &testKey}, nil)

	var call ethereum.CallMsg
	estimator := gasEstimatorFunc(func(_ context.Context, msg ethereum.CallMsg) (uint64, error) {
		call = msg
		return 678808, nil
	})
	transmitter := NewEVMContractTransmitterFromTxm(
		lggr, protocol.ChainSelector(1), mockTxm, offRamp, mockRR, []common.Address{from}, monitoring.NewNoopExecutorMonitoring(), WithGasEstimator(estimator),
	)
	report := protocol.AbstractAggregatedReport{
		CCVS:    []protocol.UnknownAddress{protocol.UnknownAddress(common.HexToAddress("0x1111111111111111111111111111111111111111").Bytes())},
		CCVData: [][]byte{make([]byte, 9000)},
		Message: mustCreateMessage(t, 1, 2, 100, 574980, 0),
	}

	require.NoError(t, transmitter.ConvertAndWriteMessageToChain(ctx, report))
	assert.Equal(t, from, call.From)
	assert.Equal(t, offRamp, *call.To)
	assert.NotEmpty(t, call.Data)
	mockTxm.AssertExpectations(t)
}

func TestTXMEVMContractTransmitter_EstimateGasLimit(t *testing.T) {
	from := common.HexToAddress("0xabcdef1234567890abcdef1234567890abcdef12")
	payload := []byte{1, 2, 3}

	t.Run("message gas remains the floor", func(t *testing.T) {
		ct := &TXMEVMContractTransmitter{gasEstimator: gasEstimatorFunc(lowGasEstimator)}
		got, err := ct.estimateGasLimit(t.Context(), from, payload, 1000)
		require.NoError(t, err)
		assert.Equal(t, uint64(1000), got)
	})

	t.Run("RPC estimate gets a fifteen percent buffer", func(t *testing.T) {
		ct := &TXMEVMContractTransmitter{gasEstimator: gasEstimatorFunc(func(context.Context, ethereum.CallMsg) (uint64, error) {
			return 678808, nil
		})}
		got, err := ct.estimateGasLimit(t.Context(), from, payload, 574980)
		require.NoError(t, err)
		assert.Equal(t, uint64(780629), got)
	})

	t.Run("zero estimate is rejected", func(t *testing.T) {
		ct := &TXMEVMContractTransmitter{gasEstimator: gasEstimatorFunc(func(context.Context, ethereum.CallMsg) (uint64, error) {
			return 0, nil
		})}
		_, err := ct.estimateGasLimit(t.Context(), from, payload, 1000)
		require.ErrorContains(t, err, "returned zero")
	})

	t.Run("buffer overflow is rejected", func(t *testing.T) {
		ct := &TXMEVMContractTransmitter{gasEstimator: gasEstimatorFunc(func(context.Context, ethereum.CallMsg) (uint64, error) {
			return math.MaxUint64, nil
		})}
		_, err := ct.estimateGasLimit(t.Context(), from, payload, 0)
		require.ErrorContains(t, err, "failed to buffer gas estimate")
	})

	t.Run("missing estimator is rejected", func(t *testing.T) {
		ct := &TXMEVMContractTransmitter{}
		_, err := ct.estimateGasLimit(t.Context(), from, payload, 1000)
		require.ErrorContains(t, err, "not configured")
	})
}

func TestTXMEVMContractTransmitter_EstimationFailureDoesNotCreateTransaction(t *testing.T) {
	from := common.HexToAddress("0xabcdef1234567890abcdef1234567890abcdef12")
	mockRR := new(mockRoundRobin)
	mockRR.On("GetNextAddress", mock.Anything, mock.Anything).Return(from, nil)
	mockTxm := new(mockTxManager)
	estimator := gasEstimatorFunc(func(context.Context, ethereum.CallMsg) (uint64, error) {
		return 0, errors.New("RPC unavailable")
	})
	transmitter := NewEVMContractTransmitterFromTxm(
		logger.Test(t), protocol.ChainSelector(1), mockTxm,
		common.HexToAddress("0x9999999999999999999999999999999999999999"),
		mockRR, []common.Address{from}, monitoring.NewNoopExecutorMonitoring(), WithGasEstimator(estimator),
	)
	report := protocol.AbstractAggregatedReport{Message: mustCreateMessage(t, 1, 2, 100, 574980, 0)}

	err := transmitter.ConvertAndWriteMessageToChain(t.Context(), report)
	require.ErrorContains(t, err, "RPC unavailable")
	mockTxm.AssertNotCalled(t, "CreateTransaction", mock.Anything, mock.Anything)
}

func TestEIP150ForwardingGasBuffer(t *testing.T) {
	testCases := []struct {
		name                string
		ccipReceiveGasLimit uint32
	}{
		{name: "zero", ccipReceiveGasLimit: 0},
		{name: "one", ccipReceiveGasLimit: 1},
		{name: "one below denominator boundary", ccipReceiveGasLimit: eip150ForwardingDenominator - 1},
		{name: "exact denominator boundary", ccipReceiveGasLimit: eip150ForwardingDenominator},
		{name: "exact numerator boundary", ccipReceiveGasLimit: eip150ForwardingNumerator},
		{name: "typical gas limit", ccipReceiveGasLimit: 200000},
		{name: "large gas limit", ccipReceiveGasLimit: 5000000},
		{name: "max uint32", ccipReceiveGasLimit: math.MaxUint32},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gasLimit := uint64(tc.ccipReceiveGasLimit)
			buffer := eip150ForwardingGasBuffer(tc.ccipReceiveGasLimit)

			// Gas received after an EIP-150 CALL boundary
			eip150ForwardedGas := func(gas uint64) uint64 { return gas - gas/64 }

			assert.GreaterOrEqual(t, eip150ForwardedGas(eip150ForwardedGas(gasLimit+buffer)), gasLimit, "buffer too small")
			assert.LessOrEqual(t, eip150ForwardedGas(eip150ForwardedGas(gasLimit+buffer)), gasLimit+2, "buffer larger than necessary")
		})
	}
}

func TestTXMEVMContractTransmitter_SetsMessageIDMeta(t *testing.T) {
	ctx := context.Background()
	lggr := logger.Test(t)
	testKey := "test-key"

	msg := mustCreateMessage(t, 1, 2, 100, 1000000, 1000000)
	expectedMessageID, err := msg.MessageID()
	require.NoError(t, err)

	report := protocol.AbstractAggregatedReport{
		CCVS: []protocol.UnknownAddress{
			protocol.UnknownAddress(common.HexToAddress("0x1111111111111111111111111111111111111111").Bytes()),
		},
		CCVData: [][]byte{[]byte("ccv_data_1")},
		Message: msg,
	}

	mockTxm := new(mockTxManager)
	mockRR := new(mockRoundRobin)
	fromAddr := common.HexToAddress("0xabcdef1234567890abcdef1234567890abcdef12")
	mockRR.On("GetNextAddress", mock.Anything, mock.Anything).Return(fromAddr, nil)
	mockTxm.On("CreateTransaction", mock.Anything, mock.MatchedBy(func(req txmgr.TxRequest) bool {
		return req.Meta != nil &&
			len(req.Meta.MessageIDs) == 1 &&
			req.Meta.MessageIDs[0] == expectedMessageID.String()
	})).Return(txmgr.Tx{IdempotencyKey: &testKey}, nil)

	transmitter := NewEVMContractTransmitterFromTxm(
		lggr,
		protocol.ChainSelector(1),
		mockTxm,
		common.HexToAddress("0x9999999999999999999999999999999999999999"),
		mockRR,
		[]common.Address{fromAddr},
		monitoring.NewNoopExecutorMonitoring(),
		WithGasEstimator(gasEstimatorFunc(lowGasEstimator)),
	)

	require.NoError(t, transmitter.ConvertAndWriteMessageToChain(ctx, report))
	mockTxm.AssertExpectations(t)
}

// mustCreateMessage creates a test message or fails the test.
func mustCreateMessage(t *testing.T, sourceChain, destChain, nonce uint64, executionGasLimit, ccipReceiveGasLimit uint32) protocol.Message {
	msg, err := protocol.NewMessage(
		protocol.ChainSelector(sourceChain),
		protocol.ChainSelector(destChain),
		protocol.SequenceNumber(nonce),
		protocol.UnknownAddress(common.HexToAddress("0x1111111111111111111111111111111111111111").Bytes()),
		protocol.UnknownAddress(common.HexToAddress("0x2222222222222222222222222222222222222222").Bytes()),
		1,
		executionGasLimit,
		ccipReceiveGasLimit,
		protocol.Bytes32{}, // ccvAndExecutorHash
		protocol.UnknownAddress(common.HexToAddress("0x3333333333333333333333333333333333333333").Bytes()),
		protocol.UnknownAddress(common.HexToAddress("0x4444444444444444444444444444444444444444").Bytes()),
		[]byte{},
		[]byte("test data"),
		nil,
	)
	require.NoError(t, err)
	return *msg
}

// TestSetExecutorMonitoring covers the optional chainaccess.ExecutorMonitoringSetter
// capability: the accessor builds the transmitter with no-op monitoring and the executor
// attaches its process-level monitoring before the coordinator starts.
func TestSetExecutorMonitoring(t *testing.T) {
	initial := monitoring.NewNoopExecutorMonitoring()
	ct := &TXMEVMContractTransmitter{monitoring: initial}

	replacement := monitoring.NewNoopExecutorMonitoring()
	ct.SetExecutorMonitoring(replacement)
	require.Same(t, replacement, ct.monitoring)

	ct.SetExecutorMonitoring(nil)
	require.Same(t, replacement, ct.monitoring, "nil must not clobber the attached monitoring")
}
