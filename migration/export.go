// Package migration carries the node-facing half of the CL-to-standalone migration: exporting the
// two keys that have to survive the move from a running Chainlink node. It is the single
// implementation behind both callers of that flow — `ccv migrate export` in the verifier and
// executor images (cli/migrate), which an operator runs by hand, and the devenv cutover
// (build/devenv/migration), which exercises the same path end to end in tests. Devenv orchestrates
// the environment; the logic lives here.
//
// The procedure these callers serve is docs/migration/evm-cl-to-standalone.md.
package migration

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

// ExportConfig is one key export against a running Chainlink node.
type ExportConfig struct {
	// NodeURL is the base URL of the Chainlink node's API.
	NodeURL string
	// APIEmail and APIPassword are the node's API credentials — the same account the operator UI
	// takes. The export endpoints require its admin role.
	APIEmail    string
	APIPassword string
	// ChainID is the EVM chain whose enabled account is the executor's transmitter.
	ChainID string
	// OutDir receives the exported keys and the password file.
	OutDir string
	// BundleID and Account override what the export resolves itself, for the nodes the resolution
	// errors on: several EVM bundles, or several accounts enabled for the chain.
	BundleID string
	Account  string
}

// ExportResult records what an export produced: the two identities carried across, and every file
// written, so a caller's summary cannot drift from what is on disk.
type ExportResult struct {
	// SigningAddress and TransmitterAddress are the identities carried across, EIP-55 checksummed.
	SigningAddress     string
	TransmitterAddress string
	OCR2Path           string
	ETHPath            string
	PasswordPath       string
}

// ExportNodeKeys pulls the two keys a CL-to-standalone migration has to carry over out of a
// running Chainlink node, without the caller transcribing a bundle ID, an address, or a
// password:
//
//  1. Preflight: the node must run exactly one ccvcommitteeverifier job and one ccvexecutor job —
//     the only shape docs/migration/evm-cl-to-standalone.md applies to.
//  2. The EVM OCR2 bundle and the chain's enabled account are resolved from the node's own
//     listings, the same source the node's JD chain config was built from. Taking them from
//     anywhere else imports an identity no contract knows about.
//  3. Both keys are exported under a generated password nobody has to invent or type.
//  4. Each export is decoded and its identity checked before anything is reported, and the
//     transmitter is cross-checked against the account the node registered — while the node is
//     still running, not at container startup after it may be stopped.
func ExportNodeKeys(ctx context.Context, lggr logger.Logger, cfg ExportConfig) (*ExportResult, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	// 0o700: the directory holds exported private keys and the password file.
	if err := os.MkdirAll(cfg.OutDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create the output directory: %w", err)
	}

	client, err := NewNodeClient(cfg.NodeURL)
	if err != nil {
		return nil, err
	}
	if err := client.Login(ctx, cfg.APIEmail, cfg.APIPassword); err != nil {
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

	lggr.Infow("exported the Chainlink node keys for the CL-to-standalone migration",
		"outDir", cfg.OutDir, "signingAddress", signingAddress, "transmitterAddress", transmitterAddress)
	return &ExportResult{
		SigningAddress:     ChecksumAddress(signingAddress),
		TransmitterAddress: ChecksumAddress(transmitterAddress),
		OCR2Path:           ocr2Path,
		ETHPath:            ethPath,
		PasswordPath:       passwordPath,
	}, nil
}

func (c ExportConfig) validate() error {
	// A slice, not a map: the first missing field is always the one reported.
	for _, field := range []struct{ name, value string }{
		{"NodeURL", c.NodeURL},
		{"APIEmail", c.APIEmail},
		{"APIPassword", c.APIPassword},
		{"ChainID", c.ChainID},
		{"OutDir", c.OutDir},
	} {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("%s is required", field.name)
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
				"Labs rather than picking one (docs/migration/evm-cl-to-standalone.md)",
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

// WriteKeyImportSnippet writes the [key_import] block for one process with expected_id filled
// in. The value that must not be mistyped — the identity the key has to carry — is written by the
// same flow that read it out of the export, so it never passes through a human clipboard.
func WriteKeyImportSnippet(path, process, keyFileName, expectedID string) error {
	content := fmt.Sprintf(`# Generated by `+"`ccv migrate export`"+` for the standalone %s.
# Mount %s and %s into the container at the paths below (renaming the key file to
# key.json on the way in), then add this block to the process's bootstrap config.
[key_import]
path          = "/etc/ccv/migration/key.json"
password_path = "/etc/ccv/migration/export-password.txt"
expected_id   = "%s"
`, process, keyFileName, PasswordFileName, ChecksumAddress(expectedID))
	// 0644, not 0600: the snippet carries a public address, and it has to be readable by whatever
	// tooling renders the bootstrap config.
	return os.WriteFile(path, []byte(content), 0o644) //nolint:gosec // G306: no secrets; expected_id is a public address
}

// ChecksumAddress renders a lowercase hex identity as EIP-55, the form block explorers and the
// node's own UI show, so an operator comparing it against either sees the same string.
func ChecksumAddress(lowerHexID string) string {
	return common.HexToAddress(lowerHexID).Hex()
}
