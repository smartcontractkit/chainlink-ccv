package messagedisablement

import (
	"github.com/urfave/cli"

	rules "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/messagedisablement"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type Deps struct {
	Logger logger.Logger
	Store  rules.Store
}

func InitMessageDisablementRulesCommands(deps Deps) []cli.Command {
	return buildMessageDisablementRulesCommands(func() Deps { return deps })
}

func InitMessageDisablementRulesCommandsWithFactory(getDeps func() Deps) []cli.Command {
	return buildMessageDisablementRulesCommands(getDeps)
}

func buildMessageDisablementRulesCommands(getDeps func() Deps) []cli.Command {
	return []cli.Command{
		createCommand(getDeps),
		listCommand(getDeps),
		getCommand(getDeps),
		deleteCommand(getDeps),
	}
}
