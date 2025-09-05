package executor

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/smartcontractkit/chainlink-ccv/executor/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	ct "github.com/smartcontractkit/chainlink-ccv/executor/pkg/contracttransmitter"
	dr "github.com/smartcontractkit/chainlink-ccv/executor/pkg/destinationreader"
	protocol "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

// Mock implementations.
type mockContractTransmitter struct {
	convertErr error
}

func (m *mockContractTransmitter) ConvertAndWriteMessageToChain(ctx context.Context, report types.AbstractAggregatedReport) error {
	return m.convertErr
}

type mockDestinationReader struct {
	executedErr error
	ccvInfoErr  error
	ccvInfo     types.CcvAddressInfo
	executed    bool
}

func (m *mockDestinationReader) IsMessageExecuted(ctx context.Context, src protocol.ChainSelector, seq protocol.SeqNum) (bool, error) {
	return m.executed, m.executedErr
}

func (m *mockDestinationReader) GetCCVSForMessage(ctx context.Context, src protocol.ChainSelector, receiver protocol.UnknownAddress) (types.CcvAddressInfo, error) {
	return m.ccvInfo, m.ccvInfoErr
}

// Tests.
func Test_ChainlinkExecutor(t *testing.T) {
	type chainlinkExecutorTestSuite struct {
		name                       string
		ct                         *mockContractTransmitter
		ctChains                   []protocol.ChainSelector
		dr                         *mockDestinationReader
		drChains                   []protocol.ChainSelector
		msg                        types.MessageWithCCVData
		validateShouldError        bool
		validateMessageShouldError bool
		executeShouldError         bool
	}

	suite := []chainlinkExecutorTestSuite{
		{
			name:                       "valid case",
			ct:                         &mockContractTransmitter{},
			ctChains:                   []protocol.ChainSelector{1, 2},
			dr:                         &mockDestinationReader{},
			drChains:                   []protocol.ChainSelector{1, 2},
			msg:                        types.MessageWithCCVData{Message: protocol.Message{DestChainSelector: 1, SourceChainSelector: 2, SequenceNumber: 1}},
			validateShouldError:        false,
			validateMessageShouldError: false,
			executeShouldError:         false,
		},
		{
			name:                       "mismatched supported chains should error",
			ct:                         &mockContractTransmitter{},
			ctChains:                   []protocol.ChainSelector{1},
			dr:                         &mockDestinationReader{},
			drChains:                   []protocol.ChainSelector{1, 2},
			msg:                        types.MessageWithCCVData{Message: protocol.Message{DestChainSelector: 1, SourceChainSelector: 2, SequenceNumber: 1}},
			validateShouldError:        true,
			validateMessageShouldError: false,
			executeShouldError:         false,
		},
		{
			name:                       "should fail to execute if ConvertAndWriteMessageToChain fails",
			ct:                         &mockContractTransmitter{convertErr: errors.New("fail")},
			ctChains:                   []protocol.ChainSelector{1},
			dr:                         &mockDestinationReader{},
			drChains:                   []protocol.ChainSelector{1},
			msg:                        types.MessageWithCCVData{Message: protocol.Message{DestChainSelector: 1, SourceChainSelector: 2, SequenceNumber: 1}},
			validateShouldError:        false,
			validateMessageShouldError: false,
			executeShouldError:         true,
		},
		{
			name:                       "Should not error if message already executed",
			ct:                         &mockContractTransmitter{},
			ctChains:                   []protocol.ChainSelector{1},
			dr:                         &mockDestinationReader{executed: true, executedErr: nil},
			drChains:                   []protocol.ChainSelector{1},
			msg:                        types.MessageWithCCVData{Message: protocol.Message{DestChainSelector: 1, SourceChainSelector: 2, SequenceNumber: 1}},
			validateShouldError:        false,
			validateMessageShouldError: false,
			executeShouldError:         false,
		},
	}

	for _, tc := range suite {
		allContractTransmitters := make(map[protocol.ChainSelector]ct.ContractTransmitter)
		for _, chain := range tc.ctChains {
			allContractTransmitters[chain] = tc.ct
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
			continue
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
