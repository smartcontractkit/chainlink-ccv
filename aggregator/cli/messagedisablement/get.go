package messagedisablement

import (
	"context"
	"fmt"

	"github.com/urfave/cli"

	rules "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/messagedisablement"
)

func getCommand(getDeps func() Deps) cli.Command {
	return cli.Command{
		Name:   "get",
		Usage:  "Get a message disablement rule by id",
		Action: getActionWithFactory(getDeps),
		Flags: []cli.Flag{
			ruleIDFlag(),
		},
	}
}

func getActionWithFactory(getDeps func() Deps) func(*cli.Context) error {
	return func(c *cli.Context) error {
		deps := getDeps()
		id := c.String("id")
		rule, err := deps.Store.Get(context.Background(), id)
		if err != nil {
			deps.Logger.Errorw("get message disablement rule failed", "id", id, "error", err)
			return err
		}
		if rule == nil {
			return fmt.Errorf("message disablement rule %s not found", id)
		}
		return renderList([]rules.Rule{*rule})
	}
}
