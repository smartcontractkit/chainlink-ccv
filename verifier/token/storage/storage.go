package storage

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type OffchainStorage struct {
	data map[protocol.Bytes32]protocol.VerifierNodeResult
}

func NewOffchainStorage() *OffchainStorage {
	return &OffchainStorage{
		data: make(map[protocol.Bytes32]protocol.VerifierNodeResult),
	}
}

func (o *OffchainStorage) WriteCCVNodeData(
	_ context.Context,
	ccvDataList []protocol.VerifierNodeResult,
) error {
	for _, ccvData := range ccvDataList {
		o.data[ccvData.MessageID] = ccvData
	}
	return nil
}

func (o *OffchainStorage) ReadBatchCCVData(
	_ context.Context,
	msgsIDs []protocol.Bytes32,
) (map[protocol.Bytes32]protocol.QueryResponse, error) {
	results := make(map[protocol.Bytes32]protocol.QueryResponse)

	for _, msgID := range msgsIDs {
		ccv, ok := o.data[msgID]
		if !ok {
			continue
		}
		results[msgID] = protocol.QueryResponse{
			Timestamp: nil,
			Data: protocol.VerifierResult{
				MessageID:              ccv.MessageID,
				Message:                ccv.Message,
				MessageCCVAddresses:    ccv.CCVAddresses,
				MessageExecutorAddress: ccv.ExecutorAddress,
				CCVData:                ccv.Signature,
				Timestamp:              time.Now(),
				VerifierSourceAddress:  nil,
				VerifierDestAddress:    nil,
			},
		}
	}
	return results, nil
}

type ChainStatusManager struct {
	statuses map[protocol.ChainSelector]*protocol.ChainStatusInfo
}

func NewChainStatusManager() protocol.ChainStatusManager {
	return &ChainStatusManager{
		statuses: make(map[protocol.ChainSelector]*protocol.ChainStatusInfo),
	}
}

func (c *ChainStatusManager) WriteChainStatuses(
	_ context.Context,
	statuses []protocol.ChainStatusInfo,
) error {
	for _, status := range statuses {
		c.statuses[status.ChainSelector] = &status
	}
	return nil
}

func (c *ChainStatusManager) ReadChainStatuses(
	_ context.Context,
	chainSelectors []protocol.ChainSelector,
) (map[protocol.ChainSelector]*protocol.ChainStatusInfo, error) {
	result := make(map[protocol.ChainSelector]*protocol.ChainStatusInfo)
	for _, selector := range chainSelectors {
		if status, exists := c.statuses[selector]; exists {
			result[selector] = status
		}
	}
	return result, nil
}
