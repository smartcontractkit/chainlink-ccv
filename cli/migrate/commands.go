package migrate

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/urfave/cli"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap/keys"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// InitMigrateCommands builds the `ccv migrate` subcommands. They need no database and no secrets
// file: they run against the Chainlink node being migrated and the files an export produced, so
// they work before the standalone deployment exists.
func InitMigrateCommands(lggr logger.Logger) []cli.Command {
	return []cli.Command{
		{
			Name: "export",
			Usage: "Export the EVM signing and transmitter keys from a running Chainlink node, " +
				"for the CL-to-standalone migration",
			Description: "Finds the node's EVM OCR2 bundle and the chain's enabled account itself, exports both " +
				"under a generated password, verifies each export decodes to the identity the node registered, " +
				"and writes a ready-made [key_import] snippet per process with expected_id filled in. " +
				"See docs/migration/cl-to-standalone.md.",
			Flags: []cli.Flag{
				cli.StringFlag{Name: "node-url", Usage: "base URL of the Chainlink node's API, e.g. http://localhost:6688", Required: true},
				cli.StringFlag{Name: "api-creds", Usage: "path to the node's API credentials file (email on line 1, password on line 2)", Required: true},
				cli.StringFlag{Name: "chain-id", Usage: "EVM chain ID whose enabled account is the transmitter to export", Required: true},
				cli.StringFlag{Name: "out-dir", Usage: "directory to write the exported keys, password file, and [key_import] snippets into", Required: true},
				cli.StringFlag{Name: "bundle-id", Usage: "optional: the OCR2 bundle ID to export, for a node with several EVM bundles"},
				cli.StringFlag{Name: "account", Usage: "optional: the account address to export, for a node with several accounts enabled for the chain"},
			},
			Action: func(c *cli.Context) error {
				result, err := ExportNodeKeys(context.Background(), lggr, ExportConfig{
					NodeURL:   c.String("node-url"),
					CredsPath: c.String("api-creds"),
					ChainID:   c.String("chain-id"),
					OutDir:    c.String("out-dir"),
					BundleID:  c.String("bundle-id"),
					Account:   c.String("account"),
				})
				if err != nil {
					return err
				}
				printExportSummary(result)
				return nil
			},
		},
		{
			Name: "inspect",
			Usage: "Print the identity an exported Chainlink node key carries, to confirm the right " +
				"file is mounted before boot",
			Description: "Reads an export the way the bootstrapper's key_import would and prints the address it " +
				"carries, so a wrong-node mount is caught on the operator's terms rather than by a process " +
				"refusing to start.",
			Flags: []cli.Flag{
				cli.StringFlag{Name: "key-file", Usage: "path to the exported key file", Required: true},
				cli.StringFlag{Name: "password-file", Usage: "path to the file holding the password the key was exported under", Required: true},
			},
			Action: func(c *cli.Context) error {
				return inspectKey(c.String("key-file"), c.String("password-file"))
			},
		},
	}
}

// printExportSummary is the one thing the operator reads, so it is plain stdout rather than a
// log line: what each identity is, where each file landed, and what happens next.
func printExportSummary(r *ExportResult) {
	fmt.Printf(`
Export complete. The two identities that had to survive the move:

  signing address (verifier)    : %s
  transmitter address (executor): %s

Files written:

  %s  (the verifier's key, mode 0600)
  %s  (the executor's key, mode 0600)
  %s  (the password both are encrypted under, mode 0600)
  %s
  %s

Next:

  1. Mount each key file and the password file into its container at the paths its
     snippet names, and add the snippet's [key_import] block to the bootstrap config.
  2. Confirm on chain that the committee signer set holds the signing address above,
     and that the transmitter address is the funded account.
  3. Continue from step 4 of docs/migration/cl-to-standalone.md (stop the Chainlink node).
`,
		r.SigningAddress, r.TransmitterAddress,
		r.OCR2Path, r.ETHPath, r.PasswordPath, r.VerifierTOMLPath, r.ExecutorTOMLPath)
}

// inspectKey implements `ccv migrate inspect`: read the identity a mounted export carries
// without booting anything.
func inspectKey(keyFile, passwordFile string) error {
	if strings.TrimSpace(keyFile) == "" {
		return fmt.Errorf("--key-file is required")
	}
	if strings.TrimSpace(passwordFile) == "" {
		return fmt.Errorf("--password-file is required")
	}
	data, err := os.ReadFile(keyFile) //nolint:gosec // G304: operator-provided path
	if err != nil {
		return fmt.Errorf("failed to read the key file: %w", err)
	}
	format, err := keys.DetectFormat(data)
	if err != nil {
		return err
	}
	id, err := keys.InspectImport(keys.Import{Path: keyFile, PasswordPath: passwordFile})
	if err != nil {
		return err
	}
	fmt.Printf("%s is a %s export carrying identity %s\n", keyFile, format, checksumAddress(id))
	return nil
}
