package messagedisablement

import "github.com/smartcontractkit/chainlink-ccv/protocol"

type MessageReport interface {
	// GetSourceChainSelector returns the source chain selector for the message.
	GetSourceChainSelector() uint64
	// GetDestinationSelector returns the destination chain selector for the message.
	GetDestinationSelector() uint64
	// GetTokenTransfer returns the token transfer payload for token messages.
	GetTokenTransfer() *protocol.TokenTransfer
}

type Checker interface {
	// IsDisabled returns true when any active disablement rule blocks the message.
	IsDisabled(report MessageReport) bool
}

type NoopChecker struct{}

func (NoopChecker) IsDisabled(_ MessageReport) bool { return false }
