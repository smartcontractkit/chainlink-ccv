package executor

import (
	"context"

	"github.com/smartcontractkit/chainlink-common/pkg/types/ccipocr3"
)

type LeaderElector interface {
	get_delay(messageId ccipocr3.Bytes32, destSelector ccipocr3.ChainSelector) uint64
}

// DestinationReader is an interface for reading message status and data from destination chains
// It's used to get the list of ccv addresses for each receiver, as well as check if messages have been executed
type DestinationReader interface {
	SupportedChains() []ccipocr3.ChainSelector
	GetCCVSForMessage(ctx context.Context, destSelector ccipocr3.ChainSelector, sourceSelector ccipocr3.ChainSelector, receiverAddress ccipocr3.UnknownAddress) (CcvAddressInfo, error)
	IsMessageExecuted(ctx context.Context, destSelector ccipocr3.ChainSelector, sourceSelector ccipocr3.ChainSelector, sequenceNumber ccipocr3.SeqNum) (bool, error)
	GetSenderNonce(ctx context.Context, destSelector ccipocr3.ChainSelector, sourceSelector ccipocr3.ChainSelector, senderAddress string) (uint64, error)
}

// ContractTransmitter is an interface for transmitting messages to destination chains
// it should be implemented by chain-specific transmitters
type ContractTransmitter interface {
	SupportedChains() []ccipocr3.ChainSelector
	ConvertAndWriteMessageToChain(ctx context.Context, report AbstractAggregatedReport) error
}

// CcvDataReader is an interface for reading CCV data messages.
// It has a single method which returns a channel for receiving messages that need to be processed.
type CcvDataReader interface {
	subscribeMessages() (chan MessageWithCCVData, chan error)
}
