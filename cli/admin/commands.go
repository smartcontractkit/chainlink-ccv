// Package admin provides the `ccv admin` commands: the admin console server and config
// validation.
package admin

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/urfave/cli"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/admin"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// Command returns the `ccv admin` command. The console manages its own config and node
// connections, so it needs no factory from the caller.
func Command(lggr logger.Logger) cli.Command {
	serveFlags := []cli.Flag{
		cli.StringFlag{
			Name:   "config",
			Usage:  "Path to the console config TOML",
			EnvVar: admin.ConfigPathEnv,
			Value:  admin.DefaultConfigPath,
		},
	}
	return cli.Command{
		Name:  "admin",
		Usage: "Admin console: server-rendered UI over the recovery stores",
		Subcommands: []cli.Command{
			{
				Name:  "serve",
				Usage: "Serve the admin console (binds loopback by default)",
				Flags: serveFlags,
				Action: func(c *cli.Context) error {
					return serve(c, lggr)
				},
			},
			{
				Name:  "check-config",
				Usage: "Validate the console config and print the resolved node identities",
				Flags: serveFlags,
				Action: func(c *cli.Context) error {
					cfg, err := admin.LoadConfig(c.String("config"))
					if err != nil {
						return err
					}
					fmt.Printf("config OK: listen=%s nodes=%d\n", cfg.ListenAddress, len(cfg.Nodes))
					for _, n := range cfg.Nodes {
						fmt.Printf("  node %q (secrets: %s)\n", n.Name, n.SecretsPath)
					}
					return nil
				},
			},
		},
	}
}

func serve(c *cli.Context, lggr logger.Logger) error {
	cfg, err := admin.LoadConfig(c.String("config"))
	if err != nil {
		return err
	}
	srv, err := admin.NewServer(cfg, lggr)
	if err != nil {
		return err
	}
	defer srv.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return srv.Run(ctx)
}
