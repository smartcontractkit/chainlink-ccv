package ccvdatareader

import "github.com/smartcontractkit/chainlink-ccv/executor/types"

// CcvDataReader is an interface for reading CCV data messages.
// It has a single method which returns a channel for receiving messages that need to be processed.
type CcvDataReader interface {
	// SubscribeMessages returns a channel
	SubscribeMessages() (chan types.MessageWithCCVData, chan error)
}
