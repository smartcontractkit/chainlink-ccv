package load

import (
	"time"

	"github.com/smartcontractkit/chainlink-testing-framework/wasp"
)

// SrcDest identifies a source-destination lane by chain selector.
type SrcDest struct {
	Src  uint64
	Dest uint64
}

// SentMessage represents a message sent by a load gun, tracked for verification.
type SentMessage struct {
	SeqNo     uint64
	MessageID [32]byte
	SentTime  time.Time
	ChainPair SrcDest
}

// LoadGun extends wasp.Gun with message tracking for CCIP load tests.
// Chain-specific guns (EVMTXGun, SolanaTXGun, etc.) implement this interface
// to plug into the shared verification and metrics pipeline (AssertMessagesAsync).
type LoadGun interface {
	// Call implements wasp's gun contract and fires one message per invocation.
	Call(gen *wasp.Generator) *wasp.Response

	// CloseSentChannel signals that no more messages will be sent.
	// Must be called after the wasp profile completes to unblock verification.
	CloseSentChannel()

	// SentMessages returns a read-only channel of sent messages.
	// The verification goroutine reads from this channel to confirm execution on dest.
	SentMessages() <-chan SentMessage
}
