// Package migrate is the `ccv migrate` command surface: the operator-facing half of the
// CL-to-standalone migration. It is a thin wrapper — the export logic itself lives in
// github.com/smartcontractkit/chainlink-ccv/migration and is shared with the devenv cutover, so
// the command an operator runs and the path the e2e test exercises cannot drift apart.
//
// The procedure these commands serve is docs/migration/evm-cl-to-standalone.md.
package migrate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/urfave/cli"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap/keys"
	"github.com/smartcontractkit/chainlink-ccv/migration"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// InitMigrateCommands builds the `ccv migrate` subcommands. They need no database and no secrets
// file: they run against the Chainlink node being migrated and the files an export produced, so
// they work before the standalone deployment exists.
func InitMigrateCommands(lggr logger.Logger) []cli.Command {
	return []cli.Command{
		{
			Name: "export",
			Usage: "Export the EVM signing key from a running Chainlink node, for the " +
				"CL-to-standalone migration",
			Description: "Finds the node's EVM OCR2 bundle itself, exports it under a generated password, " +
				"verifies the export decodes to the identity the node registered, and writes a ready-made " +
				"[key_import] snippet with expected_id filled in. See docs/migration/evm-cl-to-standalone.md.",
			Flags: []cli.Flag{
				cli.StringFlag{Name: "node-url", Usage: "base URL of the Chainlink node's API, e.g. http://localhost:6688", Required: true},
				cli.StringFlag{Name: "api-creds", Usage: "path to the node's API credentials file (email on line 1, password on line 2)", Required: true},
				cli.StringFlag{Name: "out-dir", Usage: "directory to write the exported key, password file, and [key_import] snippet into", Required: true},
				cli.StringFlag{Name: "bundle-id", Usage: "optional: the OCR2 bundle ID to export, for a node with several EVM bundles"},
				cli.StringFlag{Name: "expected-id", Usage: "optional: the signing address Chainlink Labs read from the operator's JD record; the export fails when the key does not carry it"},
			},
			Action: func(c *cli.Context) error {
				email, password, err := readAPICredentials(c.String("api-creds"))
				if err != nil {
					return err
				}
				result, err := migration.ExportNodeKeys(context.Background(), lggr, migration.ExportConfig{
					NodeURL:     c.String("node-url"),
					APIEmail:    email,
					APIPassword: password,
					OutDir:      c.String("out-dir"),
					BundleID:    c.String("bundle-id"),
					ExpectedID:  c.String("expected-id"),
				})
				if err != nil {
					return err
				}

				// The snippet is the CLI's addition to the shared export: devenv builds its
				// container mounts from the result directly and has no use for it.
				outDir := c.String("out-dir")
				verifierTOMLPath := filepath.Join(outDir, migration.VerifierTOMLFileName)
				if err := migration.WriteKeyImportSnippet(
					verifierTOMLPath, "verifier", migration.OCR2ExportFileName, result.SigningAddress); err != nil {
					return fmt.Errorf("failed to write the verifier's [key_import] snippet: %w", err)
				}

				printExportSummary(c.String("out-dir"), result)
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
		inspectConfigCommand(),
	}
}

// readAPICredentials reads the node's API credentials file: email on line 1, password on line 2 —
// the same layout `chainlink admin login --file` reads, so an operator can reuse the file they
// already keep. Credentials come from a file rather than a flag so they stay out of shell history
// and the process list.
func readAPICredentials(path string) (email, password string, err error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: operator-provided path
	if err != nil {
		return "", "", fmt.Errorf("failed to read the API credentials file: %w", err)
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) < 2 || strings.TrimSpace(lines[0]) == "" {
		return "", "", fmt.Errorf("the API credentials file %s must have the email on line 1 and the password on line 2", path)
	}
	email = strings.TrimSpace(lines[0])
	// Only the line ending is stripped: a password may legitimately contain spaces.
	password = strings.TrimRight(lines[1], "\r\n")
	if password == "" {
		return "", "", fmt.Errorf("the API credentials file %s has an empty password on line 2", path)
	}
	return email, password, nil
}

// printExportSummary is the one thing the operator reads, so it is plain stdout rather than a
// log line: what the identity is, where each file landed, and what happens next. File locations
// are printed as names under the output directory rather than from the result's paths: the
// password file's path is the sort of thing secret scanners flag on principle, and the names are
// fixed anyway.
func printExportSummary(outDir string, r *migration.ExportResult) {
	//nolint:forbidigo // CLI user output
	fmt.Printf(`
Export complete. The identity that had to survive the move:

  signing address (verifier): %s

Files written to %s:

  %s  (the verifier's key, mode 0600)
  %s  (the password it is encrypted under, mode 0600)
  %s

Next — continue from step 3 of docs/migration/evm-cl-to-standalone.md:

  3. Mount your node's TOML config into both containers, mount the key and password files into the
     verifier, and paste the [key_import] block from %s into the verifier's bootstrap config.
  4. Stop the Chainlink node.
  5. Start the verifier and the executor.
  6. Send Chainlink Labs the two CSA public keys.
  7. Fund the executor's transmitter.
`,
		r.SigningAddress, outDir,
		migration.OCR2ExportFileName, migration.PasswordFileName,
		migration.VerifierTOMLFileName,
		migration.VerifierTOMLFileName)
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
	// The format is passed through so the decode does not detect it a second time.
	id, err := keys.InspectImport(keys.Import{Path: keyFile, PasswordPath: passwordFile, Format: format})
	if err != nil {
		return err
	}
	fmt.Printf("%s is a %s export carrying identity %s\n", keyFile, format, migration.ChecksumAddress(id)) //nolint:forbidigo // CLI user output
	return nil
}
