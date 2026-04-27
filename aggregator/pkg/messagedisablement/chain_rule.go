package messagedisablement

import "strconv"

type chainActiveRule struct {
	rule Rule
	data ChainRuleData
}

func newChainActiveRule(rule Rule) (activeRule, error) {
	data, err := rule.ChainData()
	if err != nil {
		return nil, err
	}
	return chainActiveRule{rule: rule, data: data}, nil
}

func (r chainActiveRule) IsDisabled(report MessageReport) bool {
	return report.GetSourceChainSelector() == r.data.ChainSelector ||
		report.GetDestinationSelector() == r.data.ChainSelector
}

func (r chainActiveRule) metricKey() string {
	return ruleMetricKey(r.rule)
}

func (r chainActiveRule) metricLabels() []string {
	return append(ruleMetricLabels(r.rule),
		"chain_selector", strconv.FormatUint(r.data.ChainSelector, 10),
	)
}
