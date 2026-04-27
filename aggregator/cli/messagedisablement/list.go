package messagedisablement

import (
	"context"

	"github.com/urfave/cli"

	rules "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/messagedisablement"
)

func listCommand(getDeps func() Deps) cli.Command {
	return cli.Command{
		Name:   "list",
		Usage:  "List message disablement rules",
		Action: listActionWithFactory(getDeps),
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "type",
				Usage: "Optional rule type filter: Chain, Lane, or Token",
			},
		},
	}
}

func listActionWithFactory(getDeps func() Deps) func(*cli.Context) error {
	return func(c *cli.Context) error {
		deps := getDeps()
		var filter *rules.RuleType
		if typeStr := c.String("type"); typeStr != "" {
			ruleType, err := rules.ParseRuleType(typeStr)
			if err != nil {
				return err
			}
			filter = &ruleType
		}
		dbRules, err := deps.Store.List(context.Background(), filter)
		if err != nil {
			deps.Logger.Errorw("list message disablement rules failed", "error", err)
			return err
		}
		return renderList(dbRules)
	}
}
