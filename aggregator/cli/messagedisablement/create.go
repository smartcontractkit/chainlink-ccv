package messagedisablement

import (
	"context"
	"fmt"

	"github.com/urfave/cli"

	rules "github.com/smartcontractkit/chainlink-ccv/common/messagerules"
)

func createCommand(getDeps func() Deps) cli.Command {
	return cli.Command{
		Name:  "create",
		Usage: "Create message disablement rules",
		Subcommands: []cli.Command{
			{
				Name:   "chain",
				Usage:  "Rule matching any message touching a chain selector. Repeat --chain to create multiple rules.",
				Action: createChainActionWithFactory(getDeps),
				Flags: []cli.Flag{
					chainFlag(),
				},
			},
			{
				Name:   "lane",
				Usage:  "Rule matching an unordered pair of chain selectors. Repeat --lane to create multiple rules.",
				Action: createLaneActionWithFactory(getDeps),
				Flags: []cli.Flag{
					laneFlag(),
				},
			},
			{
				Name:   "token",
				Usage:  "Rule matching a token address on one chain selector. Repeat --token to create multiple rules.",
				Action: createTokenActionWithFactory(getDeps),
				Flags: []cli.Flag{
					tokenFlag(),
				},
			},
		},
	}
}

func createChainActionWithFactory(getDeps func() Deps) func(*cli.Context) error {
	return createRulesActionWithFactory(getDeps, rules.RuleTypeChain, chainDataFromContext)
}

func createLaneActionWithFactory(getDeps func() Deps) func(*cli.Context) error {
	return createRulesActionWithFactory(getDeps, rules.RuleTypeLane, laneDataFromContext)
}

func createTokenActionWithFactory(getDeps func() Deps) func(*cli.Context) error {
	return createRulesActionWithFactory(getDeps, rules.RuleTypeToken, tokenDataFromContext)
}

func createRulesActionWithFactory(getDeps func() Deps, _ rules.RuleType, parseData func(*cli.Context) ([]rules.RuleData, error)) func(*cli.Context) error {
	return func(c *cli.Context) error {
		deps := getDeps()
		ruleData, err := parseData(c)
		if err != nil {
			return err
		}
		createdRules := make([]rules.Rule, 0, len(ruleData))
		for _, data := range ruleData {
			rule, err := deps.Store.Create(context.Background(), data)
			if err != nil {
				deps.Logger.Errorw("create message disablement rule failed", "error", err)
				return err
			}
			fmt.Printf("id=%s\n", rule.ID) //nolint:forbidigo // CLI user output
			createdRules = append(createdRules, rule)
		}
		return renderList(createdRules)
	}
}
