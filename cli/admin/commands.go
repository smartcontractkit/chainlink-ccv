// Package admin provides the `ccv admin` commands. The console itself is served
// in-process by the verifier factory when the config file is present; this group is
// for pre-flight validation of that file.
package admin

import (
	"fmt"

	"github.com/urfave/cli"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/admin"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vsecrets"
)

// Command returns the `ccv admin` command group. The verifier secrets (loaded by the
// CLI) let check-config run the same [admin_ui] and access-policy validation the
// verifier runs when it starts the console.
func Command(secrets *vsecrets.VerifierSecrets) cli.Command {
	return cli.Command{
		Name:  "admin",
		Usage: "Admin console helpers (the console is served by the verifier process itself)",
		Subcommands: []cli.Command{
			{
				Name:  "check-config",
				Usage: "Validate the console config the verifier would load at startup",
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
					auth, err := admin.BasicAuthFromSecrets(secrets)
					if err != nil {
						return err
					}
					if err := admin.ValidateAccessPolicy(cfg, auth); err != nil {
						return err
					}
					access := "actor local (loopback)"
					if auth != nil {
						access = "basic auth ([admin_ui]) enabled"
					}
					fmt.Println("config OK: listen=" + cfg.ListenAddress + " access=" + access) //nolint:forbidigo // CLI user output
					return nil
				},
			},
		},
	}
}
