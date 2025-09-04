package contracttransmitter

import (
	"context"
	"github.com/smartcontractkit/chainlink-ccv/executor/types"
)

// ContractTransmitter is an interface for transmitting messages to destination chains
// it should be implemented by chain-specific transmitters
type ContractTransmitter interface {
	ConvertAndWriteMessageToChain(ctx context.Context, report types.AbstractAggregatedReport) error
}
