package contracttransmitter

import (
	"context"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/executor"
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

func TestTXMEVMContractTransmitter_ConvertAndWriteMessageToChain(t *testing.T) {
	testKey := "test-key"
	testCases := []struct {
		name              string
		report            executor.AbstractAggregatedReport
		setupMocks        func(*mockTxManager, *mockRoundRobin)
		expectedError     string
		expectedLogFields map[string]any
	}{
		{
			name: "successful transmission",
			report: executor.AbstractAggregatedReport{
				CCVS: []protocol.UnknownAddress{
					protocol.UnknownAddress(common.HexToAddress("0x1111111111111111111111111111111111111111").Bytes()),
					protocol.UnknownAddress(common.HexToAddress("0x2222222222222222222222222222222222222222").Bytes()),
				},
				CCVData: [][]byte{
					[]byte("ccv_data_1"),
					[]byte("ccv_data_2"),
				},
				Message: mustCreateMessage(t, 1, 2, 100, 1000000),
			},
			setupMocks: func(txm *mockTxManager, rr *mockRoundRobin) {
				fromAddr := common.HexToAddress("0xabcdef1234567890abcdef1234567890abcdef12")
				rr.On("GetNextAddress", mock.Anything, mock.Anything).Return(fromAddr, nil)

				expectedTx := txmgr.Tx{
					IdempotencyKey: &testKey,
				}

				txm.On("CreateTransaction", mock.Anything, mock.MatchedBy(func(req txmgr.TxRequest) bool {
					return req.FromAddress == fromAddr &&
						req.FeeLimit == uint64(2_500_000) &&
						len(req.EncodedPayload) > 0
				})).Return(expectedTx, nil)
			},
			expectedError: "",
		},
		{
			name: "error getting round-robin address",
			report: executor.AbstractAggregatedReport{
				CCVS: []protocol.UnknownAddress{
					protocol.UnknownAddress(common.HexToAddress("0x1111111111111111111111111111111111111111").Bytes()),
				},
				CCVData: [][]byte{
					[]byte("ccv_data_1"),
				},
				Message: mustCreateMessage(t, 1, 2, 100, 1000000),
			},
			setupMocks: func(txm *mockTxManager, rr *mockRoundRobin) {
				rr.On("GetNextAddress", mock.Anything, mock.Anything).Return(common.Address{}, errors.New("no available keys"))
			},
			expectedError: "skipping transmit, error getting round-robin from address: no available keys",
		},
		{
			name: "error creating transaction",
			report: executor.AbstractAggregatedReport{
				CCVS: []protocol.UnknownAddress{
					protocol.UnknownAddress(common.HexToAddress("0x1111111111111111111111111111111111111111").Bytes()),
				},
				CCVData: [][]byte{
					[]byte("ccv_data_1"),
				},
				Message: mustCreateMessage(t, 1, 2, 100, 1000000),
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
			report: executor.AbstractAggregatedReport{
				CCVS:    []protocol.UnknownAddress{},
				CCVData: [][]byte{},
				Message: mustCreateMessage(t, 1, 2, 100, 1000000),
			},
			setupMocks: func(txm *mockTxManager, rr *mockRoundRobin) {
				fromAddr := common.HexToAddress("0xabcdef1234567890abcdef1234567890abcdef12")
				rr.On("GetNextAddress", mock.Anything, mock.Anything).Return(fromAddr, nil)

				expectedTx := txmgr.Tx{
					IdempotencyKey: &testKey,
				}

				txm.On("CreateTransaction", mock.Anything, mock.MatchedBy(func(req txmgr.TxRequest) bool {
					return req.FromAddress == fromAddr &&
						req.FeeLimit == uint64(2_500_000) &&
						len(req.EncodedPayload) > 0
				})).Return(expectedTx, nil)
			},
			expectedError: "",
		},
		{
			name: "multiple CCVs with large gas limit",
			report: executor.AbstractAggregatedReport{
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
				Message: mustCreateMessage(t, 1, 2, 100, 5000000),
			},
			setupMocks: func(txm *mockTxManager, rr *mockRoundRobin) {
				fromAddr := common.HexToAddress("0xabcdef1234567890abcdef1234567890abcdef12")
				rr.On("GetNextAddress", mock.Anything, mock.Anything).Return(fromAddr, nil)

				expectedTx := txmgr.Tx{
					IdempotencyKey: &testKey,
				}

				txm.On("CreateTransaction", mock.Anything, mock.MatchedBy(func(req txmgr.TxRequest) bool {
					return req.FromAddress == fromAddr &&
						req.FeeLimit == uint64(2_500_000) &&
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
			)

			// Execute
			err := transmitter.ConvertAndWriteMessageToChain(ctx, tc.report)

			// Assert
			if tc.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
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
		report        executor.AbstractAggregatedReport
		validateError func(*testing.T, error)
	}{
		{
			name: "valid report encodes successfully",
			report: executor.AbstractAggregatedReport{
				CCVS: []protocol.UnknownAddress{
					protocol.UnknownAddress(common.HexToAddress("0x1111111111111111111111111111111111111111").Bytes()),
				},
				CCVData: [][]byte{
					[]byte("test_data"),
				},
				Message: mustCreateMessage(t, 1, 2, 100, 1000000),
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

				expectedPayload, err := offrampABI.Pack("execute", expectedMsg, expectedCCVs, expectedCCVData)
				require.NoError(t, err)

				// Compare the payloads for byte-level equality
				assert.Equal(t, expectedPayload, capturedPayload)
			}
		})
	}
}

// mustCreateMessage creates a test message or fails the test.
func mustCreateMessage(t *testing.T, sourceChain, destChain, nonce uint64, gasLimit uint32) protocol.Message {
	msg, err := protocol.NewMessage(
		protocol.ChainSelector(sourceChain),
		protocol.ChainSelector(destChain),
		protocol.SequenceNumber(nonce),
		protocol.UnknownAddress(common.HexToAddress("0x1111111111111111111111111111111111111111").Bytes()),
		protocol.UnknownAddress(common.HexToAddress("0x2222222222222222222222222222222222222222").Bytes()),
		1,
		gasLimit,
		gasLimit,           // ccipReceiveGasLimit
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
