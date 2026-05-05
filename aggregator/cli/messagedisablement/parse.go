package messagedisablement

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/urfave/cli"

	rules "github.com/smartcontractkit/chainlink-ccv/common/messagerules"
)

func ruleIDFlag() cli.StringFlag {
	return cli.StringFlag{Name: "id", Usage: "Rule UUID", Required: true}
}

func chainFlag() cli.StringSliceFlag {
	return cli.StringSliceFlag{Name: "chain", Usage: "Chain selector. For create, may be repeated or comma-separated.", Required: true}
}

func laneFlag() cli.StringSliceFlag {
	return cli.StringSliceFlag{Name: "lane", Usage: "Lane as <selector1>,<selector2>. For create, may be repeated.", Required: true}
}

func tokenFlag() cli.StringSliceFlag {
	return cli.StringSliceFlag{Name: "token", Usage: "Token rule as <selector>,<token-address>. For create, may be repeated.", Required: true}
}

func chainDataFromContext(c *cli.Context) ([]rules.RuleData, error) {
	values := c.StringSlice("chain")
	if len(values) == 0 {
		return nil, fmt.Errorf("--chain is required")
	}

	var data []rules.RuleData
	for _, value := range values {
		parts := splitCommaList(value)
		if len(parts) == 0 {
			return nil, fmt.Errorf("--chain cannot be empty")
		}
		for _, part := range parts {
			selector, err := parseSelector(part)
			if err != nil {
				return nil, fmt.Errorf("invalid --chain value %q: %w", part, err)
			}
			ruleData, err := rules.NewChainRuleData(selector)
			if err != nil {
				return nil, err
			}
			data = append(data, ruleData)
		}
	}
	return data, nil
}

func laneDataFromContext(c *cli.Context) ([]rules.RuleData, error) {
	values := c.StringSlice("lane")
	if len(values) == 0 {
		return nil, fmt.Errorf("--lane is required")
	}

	data := make([]rules.RuleData, 0, len(values))
	for _, value := range values {
		parts := splitRulePair(value)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid --lane value %q: expected <selector1>,<selector2>", value)
		}
		selectorA, err := parseSelector(parts[0])
		if err != nil {
			return nil, fmt.Errorf("invalid --lane first selector %q: %w", parts[0], err)
		}
		selectorB, err := parseSelector(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid --lane second selector %q: %w", parts[1], err)
		}
		ruleData, err := rules.NewLaneRuleData(selectorA, selectorB)
		if err != nil {
			return nil, err
		}
		data = append(data, ruleData)
	}
	return data, nil
}

func tokenDataFromContext(c *cli.Context) ([]rules.RuleData, error) {
	values := c.StringSlice("token")
	if len(values) == 0 {
		return nil, fmt.Errorf("--token is required")
	}

	data := make([]rules.RuleData, 0, len(values))
	for _, value := range values {
		parts := splitRulePair(value)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid --token value %q: expected <selector>,<token-address>", value)
		}
		selector, err := parseSelector(parts[0])
		if err != nil {
			return nil, fmt.Errorf("invalid --token selector %q: %w", parts[0], err)
		}
		ruleData, err := rules.NewTokenRuleData(selector, parts[1])
		if err != nil {
			return nil, err
		}
		data = append(data, ruleData)
	}
	return data, nil
}

func splitCommaList(s string) []string {
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	if len(parts) == 1 && parts[0] == "" {
		return nil
	}
	return parts
}

func splitRulePair(s string) []string {
	return splitCommaList(s)
}

func parseSelector(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("chain selector cannot be empty")
	}
	u, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid chain selector %q: %w", s, err)
	}
	return u, nil
}
