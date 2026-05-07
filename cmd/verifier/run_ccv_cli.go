package verifier

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/urfave/cli"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccv/cli/chainstatuses"
	"github.com/smartcontractkit/chainlink-ccv/cli/jobqueue"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/chainstatus"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// RunCCVCLI runs the CCV CLI (ccv chain-statuses list|enable|disable|set-finalized-height).
// DB is connected lazily when a subcommand runs, so --help works without CL_DATABASE_URL.
// Call this when os.Args[1] == "ccv"; pass os.Args[1:] so the app receives ["ccv", "chain-statuses", subcommand, ...].
// urfave/cli treats args[0] as the program name, so we prepend app.Name so "ccv" is parsed as the first command.
func RunCCVCLI(args []string) {
	lggr, err := logger.NewWith(logging.GetLogProfile(zapcore.InfoLevel))
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to create logger: %v\n", err)
		os.Exit(1)
	}
	lggr = logger.Sugared(logger.Named(lggr, "ccv-cli"))

	var chainStatusOnce sync.Once
	var chainStatusDeps chainstatuses.Deps
	getChainStatusDeps := func() chainstatuses.Deps {
		chainStatusOnce.Do(func() {
			ds, connErr := ConnectToPostgresDB(lggr)
			if connErr != nil {
				_, _ = fmt.Fprintf(os.Stderr, "failed to connect to database: %v\n", connErr)
				os.Exit(1)
			}
			if ds == nil {
				_, _ = fmt.Fprintln(os.Stderr, "CL_DATABASE_URL must be set for ccv chain-statuses commands")
				os.Exit(1)
			}
			store := chainstatus.NewPostgresChainStatusStore(ds, lggr)
			chainStatusDeps = chainstatuses.Deps{Logger: lggr, Store: store}
		})
		return chainStatusDeps
	}

	var jobQueueOnce sync.Once
	var jobQueueDeps jobqueue.Deps
	getJobQueueDeps := func() jobqueue.Deps {
		jobQueueOnce.Do(func() {
			ds, connErr := ConnectToPostgresDB(lggr)
			if connErr != nil {
				_, _ = fmt.Fprintf(os.Stderr, "failed to connect to database: %v\n", connErr)
				os.Exit(1)
			}
			if ds == nil {
				_, _ = fmt.Fprintln(os.Stderr, "CL_DATABASE_URL must be set for ccv job-queue commands")
				os.Exit(1)
			}
			store := jobqueue.NewPostgresStore(ds)
			jobQueueDeps = jobqueue.Deps{Logger: lggr, Store: store}
		})
		return jobQueueDeps
	}

	app := cli.NewApp()
	app.Name = filepath.Base(os.Args[0])
	app.Usage = "CCV verifier service and CLI"
	app.Commands = []cli.Command{
		{
			Name:  "ccv",
			Usage: "CCV-related commands",
			Subcommands: []cli.Command{
				{
					Name:        "chain-statuses",
					Usage:       "List, enable, disable, or set finalized block height for chain statuses",
					Subcommands: chainstatuses.InitCCVChainStatusesCommandsWithFactory(getChainStatusDeps),
				},
				{
					Name:        "job-queue",
					Usage:       "List and reschedule failed jobs in the archive tables",
					Subcommands: jobqueue.InitJobQueueCommandsWithFactory(getJobQueueDeps),
				},
			},
		},
	}

	if err := app.Run(append([]string{app.Name}, args...)); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
