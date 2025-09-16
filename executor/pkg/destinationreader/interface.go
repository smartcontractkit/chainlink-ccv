package destinationreader

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/executor/types"

	protocol "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

// DestinationReader is an interface for reading message status and data from a single destination chain
// It's used to get the list of ccv addresses for each receiver, as well as check if messages have been executed
// When integrating with non-evms, the implementer only needs to add support for a single chain.
type DestinationReader interface {
	// GetCCVSForMessage return cross-chain verifications for selected message
	GetCCVSForMessage(ctx context.Context, sourceSelector protocol.ChainSelector, receiverAddress protocol.UnknownAddress) (types.CcvAddressInfo, error)
	// IsMessageExecuted returns true if message is executed
	IsMessageExecuted(ctx context.Context, message protocol.Message) (bool, error)
}
