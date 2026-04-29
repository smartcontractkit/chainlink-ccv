package messagedisablement

import "strconv"

type laneActiveRule struct {
	rule Rule
	data LaneRuleData
}

func newLaneActiveRule(rule Rule) (activeRule, error) {
	data, err := rule.LaneData()
	if err != nil {
		return nil, err
	}
	return laneActiveRule{rule: rule, data: data}, nil
}

func (r laneActiveRule) IsDisabled(report MessageReport) bool {
	source := report.GetSourceChainSelector()
	dest := report.GetDestinationSelector()
	return (source == r.data.SelectorA && dest == r.data.SelectorB) ||
		(source == r.data.SelectorB && dest == r.data.SelectorA)
}

func (r laneActiveRule) metricKey() string {
	return internalRuleMetricID(r.rule)
}

func (r laneActiveRule) metricLabels() []string {
	return append(ruleMetricLabels(r.rule),
		"selector_a", strconv.FormatUint(r.data.SelectorA, 10),
		"selector_b", strconv.FormatUint(r.data.SelectorB, 10),
	)
}
