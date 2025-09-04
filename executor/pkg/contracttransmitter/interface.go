package contracttransmitter

import (
	"context"
	"github.com/smartcontractkit/chainlink-ccv/executor/types"
	"github.com/smartcontractkit/chainlink-common/pkg/types/ccipocr3"
)

// ContractTransmitter is an interface for transmitting messages to destination chains
// it should be implemented by chain-specific transmitters
type ContractTransmitter interface {
	SupportedChains() []ccipocr3.ChainSelector
	ConvertAndWriteMessageToChain(ctx context.Context, report types.AbstractAggregatedReport) error
}
