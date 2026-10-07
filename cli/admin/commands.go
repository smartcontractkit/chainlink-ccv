// Package admin provides the `ccv admin` commands. The console itself is served
// in-process by the verifier factory when the config file is present; this group is
// for pre-flight validation of that file.
package admin

import (
	"fmt"

	"github.com/urfave/cli"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/admin"
)

// Command returns the `ccv admin` command group.
func Command() cli.Command {
	return cli.Command{
		Name:  "admin",
		Usage: "Admin console helpers (the console is served by the verifier process itself)",
		Subcommands: []cli.Command{
			{
				Name:  "check-config",
				Usage: "Validate the console config file the verifier would load at startup",
				Flags: []cli.Flag{
					cli.StringFlag{
						Name:   "config",
						Usage:  "Path to the console config TOML",
						EnvVar: admin.ConfigPathEnv,
						Value:  admin.DefaultConfigPath,
					},
				},
				Action: func(c *cli.Context) error {
					cfg, err := admin.LoadConfig(c.String("config"))
					if err != nil {
						return err
					}
					access := "actor local (loopback)"
					if cfg.Access.ActorHeader != "" {
						access = "proxy header " + cfg.Access.ActorHeader
					}
					fmt.Println("config OK: listen=" + cfg.ListenAddress + " access=" + access) //nolint:forbidigo // CLI user output
					if cfg.AggregatorAddress != "" {
						fmt.Println("  attestation freshness checks via aggregator " + cfg.AggregatorAddress) //nolint:forbidigo // CLI user output
					}
					return nil
				},
			},
		},
	}
}
