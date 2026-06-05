package common

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// AllowAllMessagesChecker implements MessageRulesChecker by never disabling a message.
// Use when message-disablement rules from the aggregator are not wired (e.g. tests, token verifier stub).
type AllowAllMessagesChecker struct{}

func (AllowAllMessagesChecker) IsMessageDisabled(context.Context, protocol.Message) (bool, error) {
	return false, nil
}
