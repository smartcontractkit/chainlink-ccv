package lbtc

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
