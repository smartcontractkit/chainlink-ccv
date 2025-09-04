package destinationreader

import (
	"context"
	"github.com/smartcontractkit/chainlink-ccv/executor/types"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common"
	"github.com/smartcontractkit/chainlink-common/pkg/types/ccipocr3"
)

// DestinationReader is an interface for reading message status and data from destination chains
// It's used to get the list of ccv addresses for each receiver, as well as check if messages have been executed
type DestinationReader interface {
	SupportedChains() []ccipocr3.ChainSelector
	GetCCVSForMessage(ctx context.Context, destSelector ccipocr3.ChainSelector, sourceSelector ccipocr3.ChainSelector, receiverAddress common.UnknownAddress) (types.CcvAddressInfo, error)
	IsMessageExecuted(ctx context.Context, destSelector ccipocr3.ChainSelector, sourceSelector ccipocr3.ChainSelector, sequenceNumber ccipocr3.SeqNum) (bool, error)
}
