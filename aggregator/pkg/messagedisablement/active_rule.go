package messagedisablement

type activeRule interface {
	IsDisabled(MessageReport) bool
	metricKey() string
	metricLabels() []string
}

func ruleMetricKey(rule Rule) string {
	return string(rule.Type) + "|" + string(rule.Data)
}

func ruleMetricLabels(rule Rule) []string {
	return []string{
		"rule_type", string(rule.Type),
	}
}
