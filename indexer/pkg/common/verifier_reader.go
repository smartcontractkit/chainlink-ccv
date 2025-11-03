package common

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type VerifierReader interface {
	// Start VerifierReader.
	Start(ctx context.Context) error
	// Close gracefully stops VerifierReader.
	Close() error
	// ProcessMessage enqueues a new message to be procssed by the verifier reader
	// results are then demultiplex and sent back to the caller.
	ProcessMessage(messageID protocol.Bytes32) chan Result[protocol.CCVData]
}
