package messagerules

import (
	"fmt"
	"slices"
	"strings"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type CompiledRules struct {
	rules         []activeRule
	rulesSnapshot []Rule
}

type activeRule interface {
	IsDisabled(MessageReport) bool
}

type chainActiveRule struct {
	data ChainRuleData
}

type laneActiveRule struct {
	data LaneRuleData
}

type tokenActiveRule struct {
	data TokenRuleData
}

func CompileRules(rules []Rule) (CompiledRules, error) {
	compiled := CompiledRules{
		rules:         make([]activeRule, 0, len(rules)),
		rulesSnapshot: make([]Rule, 0, len(rules)),
	}
	for _, rule := range rules {
		compiled.rulesSnapshot = append(compiled.rulesSnapshot, rule)

		var active activeRule
		switch rule.Type {
		case RuleTypeChain:
			data, err := rule.ChainData()
			if err != nil {
				return CompiledRules{}, fmt.Errorf("invalid Chain rule %s: %w", rule.ID, err)
			}
			active = chainActiveRule{data: data}
		case RuleTypeLane:
			data, err := rule.LaneData()
			if err != nil {
				return CompiledRules{}, fmt.Errorf("invalid Lane rule %s: %w", rule.ID, err)
			}
			active = laneActiveRule{data: data}
		case RuleTypeToken:
			data, err := rule.TokenData()
			if err != nil {
				return CompiledRules{}, fmt.Errorf("invalid Token rule %s: %w", rule.ID, err)
			}
			active = tokenActiveRule{data: data}
		default:
			return CompiledRules{}, fmt.Errorf("unknown rule type %q for rule %s", rule.Type, rule.ID)
		}
		compiled.rules = append(compiled.rules, active)
	}
	return compiled, nil
}

func (c CompiledRules) IsDisabled(report MessageReport) bool {
	if report == nil {
		return false
	}
	for _, rule := range c.rules {
		if rule.IsDisabled(report) {
			return true
		}
	}
	return false
}

func (c CompiledRules) ActiveRuleCount() int {
	return len(c.rules)
}

func (c CompiledRules) RulesSnapshot() []Rule {
	return slices.Clone(c.rulesSnapshot)
}

func (r chainActiveRule) IsDisabled(report MessageReport) bool {
	return report.GetSourceChainSelector() == r.data.ChainSelector ||
		report.GetDestinationSelector() == r.data.ChainSelector
}

func (r laneActiveRule) IsDisabled(report MessageReport) bool {
	source := report.GetSourceChainSelector()
	dest := report.GetDestinationSelector()
	return (source == r.data.SelectorA && dest == r.data.SelectorB) ||
		(source == r.data.SelectorB && dest == r.data.SelectorA)
}

func (r tokenActiveRule) IsDisabled(report MessageReport) bool {
	tt := report.GetTokenTransfer()
	if tt == nil {
		return false
	}
	return matchesTokenRule(r.data, report.GetSourceChainSelector(), tt.SourceTokenAddress) ||
		matchesTokenRule(r.data, report.GetDestinationSelector(), tt.DestTokenAddress)
}

func matchesTokenRule(rule TokenRuleData, selector uint64, token protocol.ByteSlice) bool {
	if selector != rule.ChainSelector {
		return false
	}
	if len(token) == 0 {
		return false
	}
	return strings.EqualFold(token.String(), rule.TokenAddress)
}
