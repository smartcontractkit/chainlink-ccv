package messagerules

import (
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	messagepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/message-rules/v1"
)

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
		tokenBytes, err := protocol.NewByteSliceFromHex(data.TokenAddress)
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

func unixMillis(millis int64) time.Time {
	if millis == 0 {
		return time.Time{}
	}
	return time.UnixMilli(millis).UTC()
}

func timeToUnixMillis(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func RuleFromProto(rule *messagepb.MessageRule) (Rule, error) {
	if rule == nil {
		return Rule{}, fmt.Errorf("message rule cannot be nil")
	}

	createdAt := unixMillis(rule.GetCreatedAtUnixMillis())
	updatedAt := unixMillis(rule.GetUpdatedAtUnixMillis())

	switch condition := rule.GetCondition().(type) {
	case *messagepb.MessageRule_Chain:
		if condition.Chain == nil {
			return Rule{}, fmt.Errorf("chain rule condition cannot be nil")
		}
		data, err := NewChainRuleData(condition.Chain.GetChainSelector())
		if err != nil {
			return Rule{}, err
		}
		return NewRule(rule.GetId(), data, createdAt, updatedAt)
	case *messagepb.MessageRule_Lane:
		if condition.Lane == nil {
			return Rule{}, fmt.Errorf("lane rule condition cannot be nil")
		}
		data, err := NewLaneRuleData(condition.Lane.GetSelectorA(), condition.Lane.GetSelectorB())
		if err != nil {
			return Rule{}, err
		}
		return NewRule(rule.GetId(), data, createdAt, updatedAt)
	case *messagepb.MessageRule_Token:
		if condition.Token == nil {
			return Rule{}, fmt.Errorf("token rule condition cannot be nil")
		}
		data, err := NewTokenRuleData(
			condition.Token.GetChainSelector(),
			fmt.Sprintf("0x%x", condition.Token.GetTokenAddress()),
		)
		if err != nil {
			return Rule{}, err
		}
		return NewRule(rule.GetId(), data, createdAt, updatedAt)
	default:
		return Rule{}, fmt.Errorf("message rule %q has no condition", rule.GetId())
	}
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

func RulesFromProto(rules []*messagepb.MessageRule) ([]Rule, error) {
	out := make([]Rule, 0, len(rules))
	for _, pbRule := range rules {
		rule, err := RuleFromProto(pbRule)
		if err != nil {
			return nil, err
		}
		out = append(out, rule)
	}
	return out, nil
}
