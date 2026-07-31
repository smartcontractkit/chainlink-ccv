package executor

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/urfave/cli"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccv/cli/migrate"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// RunCCVCLI runs the CCV CLI (ccv migrate ...). Unlike the verifier's CLI there are no DB-backed
// commands here, so nothing is loaded up front: the migration commands run against the Chainlink
// node being migrated and the files an export produced, before the standalone deployment exists.
// Call this when os.Args[1] == "ccv"; pass os.Args[1:] so the app receives ["ccv", "migrate", ...].
// urfave/cli treats args[0] as the program name, so we prepend app.Name so "ccv" is parsed as the
// first command.
func RunCCVCLI(args []string) {
	lggr, err := logger.NewWith(logging.GetLogProfile(zapcore.InfoLevel))
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to create logger: %v\n", err)
		os.Exit(1)
	}
	lggr = logger.Sugared(logger.Named(lggr, "ccv-cli"))

	app := cli.NewApp()
	app.Name = filepath.Base(os.Args[0])
	app.Usage = "CCV executor service and CLI"
	app.Commands = []cli.Command{
		{
			Name:  "ccv",
			Usage: "CCV-related commands",
			Subcommands: []cli.Command{
				{
					Name:        "migrate",
					Usage:       "CL-to-standalone migration: export keys from a Chainlink node and inspect them",
					Subcommands: migrate.InitMigrateCommands(lggr),
				},
			},
		},
	}

	if err := app.Run(append([]string{app.Name}, args...)); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
