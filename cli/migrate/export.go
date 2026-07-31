package migrate

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap/keys"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// JobTypeVerifier and JobTypeExecutor are the job spec types the migration moves. They mirror
// migration.JobTypeVerifier/JobTypeExecutor in the devenv module, which the binaries cannot
// import.
const (
	JobTypeVerifier = "ccvcommitteeverifier"
	JobTypeExecutor = "ccvexecutor"
)

// The file names an export writes. The key and password names mirror what an operator would have
// produced by hand with `chainlink keys ... export`; the snippet names say which process each
// block belongs to.
const (
	OCR2ExportFileName   = "ocr2.json"
	ETHExportFileName    = "eth.json"
	PasswordFileName     = "export-password.txt"
	VerifierTOMLFileName = "verifier.key_import.toml"
	ExecutorTOMLFileName = "executor.key_import.toml"
)

// ExportConfig is one `ccv migrate export` invocation.
type ExportConfig struct {
	// NodeURL is the base URL of the Chainlink node's API.
	NodeURL string
	// CredsPath is the node's API credentials file: email on line 1, password on line 2 — the same
	// layout `chainlink admin login --file` reads, so an operator can reuse the file they already
	// keep.
	CredsPath string
	// ChainID is the EVM chain whose enabled account is the executor's transmitter.
	ChainID string
	// OutDir receives the exported keys, the password file, and the [key_import] snippets.
	OutDir string
	// BundleID and Account override what the tool resolves itself, for the nodes the resolution
	// errors on: several EVM bundles, or several accounts enabled for the chain.
	BundleID string
	Account  string
}

// ExportResult records what an export produced: the two identities carried across, and every file
// written, so the CLI's summary cannot drift from what is on disk.
type ExportResult struct {
	// SigningAddress and TransmitterAddress are the identities carried across, EIP-55 checksummed.
	SigningAddress     string
	TransmitterAddress string
	OCR2Path           string
	ETHPath            string
	PasswordPath       string
	VerifierTOMLPath   string
	ExecutorTOMLPath   string
}

// ExportNodeKeys pulls the two keys a CL-to-standalone migration has to carry over out of a
// running Chainlink node, without the operator transcribing a bundle ID, an address, or a
// password:
//
//  1. Preflight: the node must run exactly one ccvcommitteeverifier job and one ccvexecutor job —
//     the only shape docs/migration/cl-to-standalone.md applies to.
//  2. The EVM OCR2 bundle and the chain's enabled account are resolved from the node's own
//     listings, the same source the node's JD chain config was built from. Taking them from
//     anywhere else imports an identity no contract knows about.
//  3. Both keys are exported under a generated password the operator never has to invent or type.
//  4. Each export is decoded and its identity checked before anything is reported, and the
//     transmitter is cross-checked against the account the node registered — while the node is
//     still running, not at container startup after it may be stopped.
//  5. A ready-made [key_import] snippet per process is written with expected_id already filled
//     in, so the one value that must not be mistyped never passes through a human.
func ExportNodeKeys(ctx context.Context, lggr logger.Logger, cfg ExportConfig) (*ExportResult, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.OutDir, 0o750); err != nil {
		return nil, fmt.Errorf("failed to create the output directory: %w", err)
	}

	email, password, err := readAPICredentials(cfg.CredsPath)
	if err != nil {
		return nil, err
	}
	client, err := NewNodeClient(cfg.NodeURL)
	if err != nil {
		return nil, err
	}
	if err := client.Login(ctx, email, password); err != nil {
		return nil, err
	}

	if err := preflightJobs(ctx, lggr, client); err != nil {
		return nil, err
	}

	bundleID := strings.TrimSpace(cfg.BundleID)
	if bundleID == "" {
		if bundleID, err = client.EVMOCR2BundleID(ctx); err != nil {
			return nil, err
		}
	}
	account := strings.TrimSpace(cfg.Account)
	if account == "" {
		if account, err = client.AccountForChain(ctx, cfg.ChainID); err != nil {
			return nil, err
		}
	}

	exportPassword, err := generateExportPassword()
	if err != nil {
		return nil, fmt.Errorf("failed to generate an export password: %w", err)
	}
	passwordPath := filepath.Join(cfg.OutDir, PasswordFileName)
	if err := os.WriteFile(passwordPath, []byte(exportPassword), 0o600); err != nil {
		return nil, fmt.Errorf("failed to write the export password file: %w", err)
	}

	ocr2Path := filepath.Join(cfg.OutDir, OCR2ExportFileName)
	if err := exportToFile(ctx, client.ExportOCR2Bundle, bundleID, exportPassword, ocr2Path); err != nil {
		return nil, fmt.Errorf("failed to export the OCR2 bundle %s: %w", bundleID, err)
	}
	ethPath := filepath.Join(cfg.OutDir, ETHExportFileName)
	if err := exportToFile(ctx, client.ExportETHKey, account, exportPassword, ethPath); err != nil {
		return nil, fmt.Errorf("failed to export the EVM account %s: %w", account, err)
	}

	signingAddress, err := keys.InspectImport(keys.Import{Format: keys.ImportFormatOCR2, Path: ocr2Path, PasswordPath: passwordPath})
	if err != nil {
		return nil, fmt.Errorf("the exported OCR2 bundle is unusable: %w", err)
	}
	transmitterAddress, err := keys.InspectImport(keys.Import{Format: keys.ImportFormatETH, Path: ethPath, PasswordPath: passwordPath})
	if err != nil {
		return nil, fmt.Errorf("the exported EVM account key is unusable: %w", err)
	}
	// The node reported this account as enabled for the chain, so a mismatch means the export
	// endpoint returned a different key than the one that address names.
	if !strings.EqualFold(transmitterAddress, strings.TrimPrefix(account, "0x")) {
		return nil, fmt.Errorf(
			"the exported EVM key holds 0x%s but the node registered %s: the export endpoint returned a different key than the account names",
			transmitterAddress, account)
	}

	verifierTOMLPath := filepath.Join(cfg.OutDir, VerifierTOMLFileName)
	if err := writeKeyImportSnippet(verifierTOMLPath, "verifier", OCR2ExportFileName, signingAddress); err != nil {
		return nil, err
	}
	executorTOMLPath := filepath.Join(cfg.OutDir, ExecutorTOMLFileName)
	if err := writeKeyImportSnippet(executorTOMLPath, "executor", ETHExportFileName, transmitterAddress); err != nil {
		return nil, err
	}

	lggr.Infow("exported the Chainlink node keys for the CL-to-standalone migration",
		"outDir", cfg.OutDir, "signingAddress", signingAddress, "transmitterAddress", transmitterAddress)
	return &ExportResult{
		SigningAddress:     checksumAddress(signingAddress),
		TransmitterAddress: checksumAddress(transmitterAddress),
		OCR2Path:           ocr2Path,
		ETHPath:            ethPath,
		PasswordPath:       passwordPath,
		VerifierTOMLPath:   verifierTOMLPath,
		ExecutorTOMLPath:   executorTOMLPath,
	}, nil
}

func (c ExportConfig) validate() error {
	// A slice, not a map: the first missing flag is always the one reported.
	for _, field := range []struct{ flag, value string }{
		{"node-url", c.NodeURL},
		{"api-creds", c.CredsPath},
		{"chain-id", c.ChainID},
		{"out-dir", c.OutDir},
	} {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("--%s is required", field.flag)
		}
	}
	return nil
}

// preflightJobs enforces the one shape this procedure covers: one ccvcommitteeverifier job and
// one ccvexecutor job. A standalone process runs a single job, so a node holding several verifier
// jobs cannot hand its one JD record to any of them — the committee's verifier jobs have to be
// consolidated first, and that is Chainlink Labs' side, not the operator's.
//
// An unreadable job list is a warning rather than a failure: the cutover itself still refuses a
// shape it cannot adopt, and blocking the key export on an API quirk helps no one. A list that
// reads fine but shows neither type is also a warning — an older node may report job types
// differently, and a wrong hard stop here would strand a valid migration.
func preflightJobs(ctx context.Context, lggr logger.Logger, client *NodeClient) error {
	verifiers, executors, err := client.CCVJobCounts(ctx)
	if err != nil {
		lggr.Warnw("could not read the node's job list; confirm manually that it runs exactly one "+
			JobTypeVerifier+" job and one "+JobTypeExecutor+" job before continuing", "err", err)
		return nil
	}
	if verifiers == 0 && executors == 0 {
		lggr.Warnw("the node runs no " + JobTypeVerifier + " or " + JobTypeExecutor + " jobs this tool can see; " +
			"confirm it is the node that runs this operator's CCV jobs before continuing")
		return nil
	}
	if verifiers > 1 {
		return fmt.Errorf(
			"the node runs %d %s jobs; a standalone verifier runs a single job, so the committee's "+
				"verifier jobs must be consolidated into one before migrating — raise it with Chainlink "+
				"Labs rather than picking one (docs/migration/cl-to-standalone.md)",
			verifiers, JobTypeVerifier)
	}
	if verifiers == 0 {
		return fmt.Errorf(
			"the node runs %d %s jobs but no %s job; the migration moves both, so this does not look "+
				"like the node that runs this operator's CCV jobs",
			executors, JobTypeExecutor, JobTypeVerifier)
	}
	if executors != 1 {
		return fmt.Errorf(
			"the node runs %d %s jobs; this procedure applies to a node running exactly one",
			executors, JobTypeExecutor)
	}
	return nil
}

// readAPICredentials reads the node's API credentials file: email on line 1, password on line 2.
// Credentials come from a file rather than a flag so they stay out of shell history and the
// process list.
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

// generateExportPassword returns a random password for one export run. It is generated because
// the password guards a file that lives for minutes and is read once: a human-chosen one adds
// typing, shell history, and nothing else.
func generateExportPassword() (string, error) {
	const (
		alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		length   = 40
	)
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b), nil
}

func exportToFile(ctx context.Context, export func(context.Context, string, string) ([]byte, error), id, password, path string) error {
	data, err := export(ctx, id, password)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// writeKeyImportSnippet writes the [key_import] block for one process with expected_id filled
// in. The value that must not be mistyped — the identity the key has to carry — is written by
// the same tool that read it out of the export, so it never passes through a human clipboard.
func writeKeyImportSnippet(path, process, keyFileName, expectedID string) error {
	content := fmt.Sprintf(`# Generated by `+"`ccv migrate export`"+` for the standalone %s.
# Mount %s and %s into the container at the paths below (renaming the key file to
# key.json on the way in), then add this block to the process's bootstrap config.
[key_import]
path          = "/etc/ccv/migration/key.json"
password_path = "/etc/ccv/migration/export-password.txt"
expected_id   = "%s"
`, process, keyFileName, PasswordFileName, checksumAddress(expectedID))
	// 0644, not 0600: the snippet carries a public address, and it has to be readable by whatever
	// tooling renders the bootstrap config.
	return os.WriteFile(path, []byte(content), 0o644) //nolint:gosec // G306: no secrets; expected_id is a public address
}

// checksumAddress renders a lowercase hex identity as EIP-55, the form block explorers and the
// node's own UI show, so an operator comparing it against either sees the same string.
func checksumAddress(lowerHexID string) string {
	return common.HexToAddress(lowerHexID).Hex()
}
