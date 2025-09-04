package executor

import (
	"context"
	"errors"
	"github.com/smartcontractkit/chainlink-ccv/executor/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"testing"

	"github.com/smartcontractkit/chainlink-ccv/protocol/common"
	"github.com/smartcontractkit/chainlink-common/pkg/types/ccipocr3"
	"github.com/stretchr/testify/assert"
)

// Mock implementations
type mockContractTransmitter struct {
	supportedChains []ccipocr3.ChainSelector
	convertErr      error
}

func (m *mockContractTransmitter) SupportedChains() []ccipocr3.ChainSelector {
	return m.supportedChains
}
func (m *mockContractTransmitter) ConvertAndWriteMessageToChain(ctx context.Context, report types.AbstractAggregatedReport) error {
	return m.convertErr
}

type mockDestinationReader struct {
	supportedChains []ccipocr3.ChainSelector
	executed        bool
	executedErr     error
	ccvInfo         types.CcvAddressInfo
	ccvInfoErr      error
}

func (m *mockDestinationReader) SupportedChains() []ccipocr3.ChainSelector {
	return m.supportedChains
}
func (m *mockDestinationReader) IsMessageExecuted(ctx context.Context, dest, src ccipocr3.ChainSelector, seq ccipocr3.SeqNum) (bool, error) {
	return m.executed, m.executedErr
}

func (m *mockDestinationReader) GetCCVSForMessage(ctx context.Context, dest, src ccipocr3.ChainSelector, receiver common.UnknownAddress) (types.CcvAddressInfo, error) {
	return m.ccvInfo, m.ccvInfoErr
}

// Tests
func Test_ChainlinkExecutor(t *testing.T) {
	type chainlinkExecutorTestSuite struct {
		name                string
		ct                  *mockContractTransmitter
		dr                  *mockDestinationReader
		msg                 types.MessageWithCCVData
		validateShouldError bool
		executeShouldError  bool
	}

	suite := []chainlinkExecutorTestSuite{
		{
			name:                "valid case",
			ct:                  &mockContractTransmitter{supportedChains: []ccipocr3.ChainSelector{1, 2}},
			dr:                  &mockDestinationReader{supportedChains: []ccipocr3.ChainSelector{1, 2}},
			validateShouldError: false,
			executeShouldError:  false,
		},
		{
			name:                "mismatched supported chains should error",
			ct:                  &mockContractTransmitter{supportedChains: []ccipocr3.ChainSelector{1}},
			dr:                  &mockDestinationReader{supportedChains: []ccipocr3.ChainSelector{1, 2}},
			validateShouldError: true,
			executeShouldError:  false,
		},
		{
			name:                "should fail to execute if ConvertAndWriteMessageToChain fails",
			ct:                  &mockContractTransmitter{supportedChains: []ccipocr3.ChainSelector{1}, convertErr: errors.New("fail")},
			dr:                  &mockDestinationReader{supportedChains: []ccipocr3.ChainSelector{1}},
			msg:                 types.MessageWithCCVData{Message: common.Message{DestChainSelector: 1, SourceChainSelector: 1, SequenceNumber: 1}},
			validateShouldError: false,
			executeShouldError:  true,
		},
		{
			name:                "Should not error if message already executed",
			ct:                  &mockContractTransmitter{supportedChains: []ccipocr3.ChainSelector{1}},
			dr:                  &mockDestinationReader{supportedChains: []ccipocr3.ChainSelector{1}, executed: true, executedErr: nil},
			msg:                 types.MessageWithCCVData{Message: common.Message{DestChainSelector: 1, SourceChainSelector: 1, SequenceNumber: 1}},
			validateShouldError: false,
			executeShouldError:  false,
		},
	}

	for _, tc := range suite {
		executor := NewChainlinkExecutor(logger.Test(t), tc.ct, tc.dr)
		err := executor.Validate()
		if tc.validateShouldError {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}

		err = executor.ExecuteMessage(context.Background(), tc.msg)
		if tc.executeShouldError {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}

func TestChainlinkExecutor_orderCcvData(t *testing.T) {
	executor := NewChainlinkExecutor(nil, nil, nil)
	ccvAddr := common.UnknownAddress{}
	ccvData := []common.CCVData{{DestVerifierAddress: ccvAddr, CCVData: []byte("data")}}
	ccvInfo := types.CcvAddressInfo{
		RequiredCcvs:      []common.UnknownAddress{ccvAddr},
		OptionalCcvs:      []common.UnknownAddress{},
		OptionalThreshold: 0,
	}
	addrs, data, err := executor.orderCcvData(ccvData, ccvInfo)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(addrs))
	assert.Equal(t, 1, len(data))
}
