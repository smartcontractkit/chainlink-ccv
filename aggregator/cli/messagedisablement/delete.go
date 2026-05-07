package messagedisablement

import (
	"context"
	"fmt"

	"github.com/urfave/cli"
)

func deleteCommand(getDeps func() Deps) cli.Command {
	return cli.Command{
		Name:   "delete",
		Usage:  "Delete a message disablement rule",
		Action: deleteActionWithFactory(getDeps),
		Flags: []cli.Flag{
			ruleIDFlag(),
		},
	}
}

func deleteActionWithFactory(getDeps func() Deps) func(*cli.Context) error {
	return func(c *cli.Context) error {
		deps := getDeps()
		id := c.String("id")
		if err := deps.Store.Delete(context.Background(), id); err != nil {
			deps.Logger.Errorw("delete message disablement rule failed", "id", id, "error", err)
			return err
		}
		fmt.Printf("Deleted message disablement rule %s.\n", id) //nolint:forbidigo // CLI user output
		return nil
	}
}
