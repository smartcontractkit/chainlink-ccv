package messagedisablement

import "github.com/smartcontractkit/chainlink-ccv/protocol"

type MessageReport interface {
	GetSourceChainSelector() uint64
	GetDestinationSelector() uint64
	GetTokenTransfer() *protocol.TokenTransfer
}

type Checker interface {
	IsDisabled(report MessageReport) bool
}

type NoopChecker struct{}

func (NoopChecker) IsDisabled(_ MessageReport) bool { return false }
