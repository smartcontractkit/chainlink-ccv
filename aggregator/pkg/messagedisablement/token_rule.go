package messagedisablement

import (
	"strconv"
	"strings"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type tokenActiveRule struct {
	rule Rule
	data TokenRuleData
}

func newTokenActiveRule(rule Rule) (activeRule, error) {
	data, err := rule.TokenData()
	if err != nil {
		return nil, err
	}
	return tokenActiveRule{rule: rule, data: data}, nil
}

func (r tokenActiveRule) IsDisabled(report MessageReport) bool {
	tt := report.GetTokenTransfer()
	if tt == nil {
		return false
	}
	return matchesTokenRule(r.data, report.GetSourceChainSelector(), tt.SourceTokenAddress) ||
		matchesTokenRule(r.data, report.GetDestinationSelector(), tt.DestTokenAddress)
}

func (r tokenActiveRule) metricKey() string {
	return ruleMetricKey(r.rule)
}

func (r tokenActiveRule) metricLabels() []string {
	return append(ruleMetricLabels(r.rule),
		"chain_selector", strconv.FormatUint(r.data.ChainSelector, 10),
		"token_address", r.data.TokenAddress,
	)
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
