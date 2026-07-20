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
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vsecrets"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// RunCCVCLI runs the CCV CLI (ccv chain-statuses list|enable|disable|set-finalized-height).
// DB is connected lazily when a subcommand runs, so --help works without a configured DB URL.
// The DB URL is resolved from the verifier secrets file (with CL_DATABASE_URL fallback), so an
// operator who has cut over to the file need not re-export the env var to run the CLI.
// Call this when os.Args[1] == "ccv"; pass os.Args[1:] so the app receives ["ccv", "chain-statuses", subcommand, ...].
// urfave/cli treats args[0] as the program name, so we prepend app.Name so "ccv" is parsed as the first command.
//
// secretsEnvVar/defaultSecretsPath name the calling app's verifier secrets file; the CLI loads it
// itself (it runs before the service factory) so an operator who has cut over to the file need not
// re-export CL_DATABASE_URL to run the CLI.
func RunCCVCLI(args []string, secretsEnvVar, defaultSecretsPath string) {
	lggr, err := logger.NewWith(logging.GetLogProfile(zapcore.InfoLevel))
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to create logger: %v\n", err)
		os.Exit(1)
	}
	lggr = logger.Sugared(logger.Named(lggr, "ccv-cli"))

	secrets, err := vsecrets.LoadFromEnv(secretsEnvVar, defaultSecretsPath)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to load verifier secrets: %v\n", err)
		os.Exit(1)
	}

	var chainStatusOnce sync.Once
	var chainStatusDeps chainstatuses.Deps
	getChainStatusDeps := func() chainstatuses.Deps {
		chainStatusOnce.Do(func() {
			ds, connErr := ConnectToPostgresDB(lggr, secrets)
			if connErr != nil {
				_, _ = fmt.Fprintf(os.Stderr, "failed to connect to database: %v\n", connErr)
				os.Exit(1)
			}
			if ds == nil {
				_, _ = fmt.Fprintln(os.Stderr, "a database URL must be set (verifier secrets file [db].url or CL_DATABASE_URL) for ccv chain-statuses commands")
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
			ds, connErr := ConnectToPostgresDB(lggr, secrets)
			if connErr != nil {
				_, _ = fmt.Fprintf(os.Stderr, "failed to connect to database: %v\n", connErr)
				os.Exit(1)
			}
			if ds == nil {
				_, _ = fmt.Fprintln(os.Stderr, "a database URL must be set (verifier secrets file [db].url or CL_DATABASE_URL) for ccv job-queue commands")
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
