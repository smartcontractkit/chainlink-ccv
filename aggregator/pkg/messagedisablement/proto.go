package messagedisablement

import (
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	messagepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/message-rules/v1"
)

func timeToUnixMillis(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func RuleToProto(rule Rule) (*messagepb.MessageRule, error) {
	pbRule := &messagepb.MessageRule{
		Id:                  rule.ID,
		CreatedAtUnixMillis: timeToUnixMillis(rule.CreatedAt),
		UpdatedAtUnixMillis: timeToUnixMillis(rule.UpdatedAt),
	}

	switch rule.Type {
	case RuleTypeChain:
		data, err := rule.ChainData()
		if err != nil {
			return nil, err
		}
		pbRule.Condition = &messagepb.MessageRule_Chain{
			Chain: &messagepb.ChainMessageRule{
				ChainSelector: data.ChainSelector,
			},
		}
	case RuleTypeLane:
		data, err := rule.LaneData()
		if err != nil {
			return nil, err
		}
		pbRule.Condition = &messagepb.MessageRule_Lane{
			Lane: &messagepb.LaneMessageRule{
				SelectorA: data.SelectorA,
				SelectorB: data.SelectorB,
			},
		}
	case RuleTypeToken:
		data, err := rule.TokenData()
		if err != nil {
			return nil, err
		}
		token, err := NormalizeTokenAddress(data.TokenAddress)
		if err != nil {
			return nil, err
		}
		tokenBytes, err := protocol.NewByteSliceFromHex(token)
		if err != nil {
			return nil, err
		}
		pbRule.Condition = &messagepb.MessageRule_Token{
			Token: &messagepb.TokenMessageRule{
				ChainSelector: data.ChainSelector,
				TokenAddress:  tokenBytes,
			},
		}
	default:
		return nil, fmt.Errorf("unknown rule type %q", rule.Type)
	}

	return pbRule, nil
}

func RulesToProto(rules []Rule) ([]*messagepb.MessageRule, error) {
	out := make([]*messagepb.MessageRule, 0, len(rules))
	for _, rule := range rules {
		pbRule, err := RuleToProto(rule)
		if err != nil {
			return nil, fmt.Errorf("failed to map rule %q to proto: %w", rule.ID, err)
		}
		out = append(out, pbRule)
	}
	return out, nil
}
