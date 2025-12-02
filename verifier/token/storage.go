package token

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type OffchainStorage struct {
	data map[string][]byte
}

func NewOffchainStorage() protocol.CCVNodeDataWriter {
	return &OffchainStorage{
		data: make(map[string][]byte),
	}
}

func (o OffchainStorage) WriteCCVNodeData(
	_ context.Context,
	ccvDataList []protocol.VerifierNodeResult,
) error {
	for _, ccvData := range ccvDataList {
		o.data[ccvData.MessageID.String()] = ccvData.Signature
	}
	return nil
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
