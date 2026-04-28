package messagedisablement

import "strings"

type activeRule interface {
	IsDisabled(MessageReport) bool
	metricKey() string
	metricLabels() []string
}

func ruleMetricKey(rule Rule) string {
	return ruleTypeMetricValue(rule.Type)
}

func ruleMetricLabels(rule Rule) []string {
	return []string{
		"rule_type", ruleTypeMetricValue(rule.Type),
	}
}

func ruleTypeMetricValue(ruleType RuleType) string {
	return strings.ToLower(string(ruleType))
}
