package destinationreader

import (
	"context"
	"github.com/smartcontractkit/chainlink-ccv/executor/types"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common"
	"github.com/smartcontractkit/chainlink-common/pkg/types/ccipocr3"
)

// DestinationReader is an interface for reading message status and data from a single destination chain
// It's used to get the list of ccv addresses for each receiver, as well as check if messages have been executed
// When integrating with non-evms, the implementer only needs to add support for a single chain
type DestinationReader interface {
	GetCCVSForMessage(ctx context.Context, sourceSelector ccipocr3.ChainSelector, receiverAddress common.UnknownAddress) (types.CcvAddressInfo, error)
	IsMessageExecuted(ctx context.Context, sourceSelector ccipocr3.ChainSelector, sequenceNumber ccipocr3.SeqNum) (bool, error)
}
