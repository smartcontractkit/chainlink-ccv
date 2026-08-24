// Package migration carries the node-facing half of the CL-to-standalone migration: exporting the
// onchain signing key that has to survive the move from a running Chainlink node. It is the single
// implementation behind both callers of that flow — `ccv migrate export` in the verifier and
// executor images (cli/migrate), which an operator runs by hand, and the devenv cutover
// (build/devenv/migration), which exercises the same path end to end in tests. Devenv orchestrates
// the environment; the logic lives here.
//
// Only the verifier's signing key moves. The executor is not migrated per operator: a single EVM
// executor with one funded key replaces the per-node transmitters, so there is no account to carry.
//
// The procedure these callers serve is docs/migration/evm-cl-to-standalone.md.
package migration

import (
	"context"
	"crypto/rand"
	"errors"
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
// produced by hand with `chainlink keys ocr2 export`; the snippet is the verifier's [key_import]
// block.
const (
	OCR2ExportFileName   = "ocr2.json"
	PasswordFileName     = "export-password.txt"
	VerifierTOMLFileName = "verifier.key_import.toml"
)

// ExportConfig is one key export against a running Chainlink node.
type ExportConfig struct {
	// NodeURL is the base URL of the Chainlink node's API.
	NodeURL string
	// APIEmail and APIPassword are the node's API credentials — the same account the operator UI
	// takes. The export endpoints require its admin role.
	APIEmail    string
	APIPassword string
	// OutDir receives the exported key and the password file.
	OutDir string
	// BundleID overrides the EVM OCR2 bundle the export resolves itself, for a node the resolution
	// errors on because it has several EVM bundles.
	BundleID string
	// ExpectedID, when set, is the signing address Chainlink Labs read from the operator's JD
	// record (OnchainSigningAddress) and handed over with the procedure. The export fails when
	// the decoded key does not carry it: the self-check alone cannot catch a wrong bundle choice,
	// because any exported bundle decodes to a self-consistent identity.
	ExpectedID string
}

// ExportResult records what an export produced: the identity carried across, and every file
// written, so a caller's summary cannot drift from what is on disk.
type ExportResult struct {
	// SigningAddress is the identity carried across, EIP-55 checksummed.
	SigningAddress string
	OCR2Path       string
	PasswordPath   string
}

// ExportNodeKeys pulls the two keys a CL-to-standalone migration has to carry over out of a
// running Chainlink node, without the caller transcribing a bundle ID, an address, or a
// password:
//
//  1. Preflight: the node is expected to run exactly one ccvcommitteeverifier job — the only shape
//     docs/migration/evm-cl-to-standalone.md applies to. A job list that contradicts that shape
//     fails the export; a list that cannot be read, or shows no CCV jobs this tool recognizes, is a
//     warning only, since an older node may report job types differently.
//  2. The EVM OCR2 bundle is resolved from the node's own listing, the same source the node's JD
//     chain config was built from. Taking it from anywhere else imports an identity no contract
//     knows about.
//  3. The bundle is exported under a generated password nobody has to invent or type.
//  4. The export is decoded and its identity checked before anything is reported — while the node
//     is still running, not at container startup after it may be stopped. When the caller supplies
//     the expected_id Chainlink Labs read from the operator's JD record, the decoded identity must
//     match it: the decode self-check alone cannot see a wrong bundle choice. A rejected export's
//     files are removed, so a failed run leaves nothing mountable behind.
func ExportNodeKeys(ctx context.Context, lggr logger.Logger, cfg ExportConfig) (*ExportResult, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.ExpectedID) == "" {
		lggr.Warnw("no expected_id supplied: this export cannot tell whether the right OCR2 bundle " +
			"was chosen, since any bundle decodes to a self-consistent identity. Ask Chainlink Labs for " +
			"this operator's JD signing address (OnchainSigningAddress) and re-run with --expected-id " +
			"before the cutover")
	}
	// 0o700: the directory holds an exported private key and the password file. MkdirAll does not
	// tighten the permissions of a directory that already exists, so chmod it either way.
	if err := os.MkdirAll(cfg.OutDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create the output directory: %w", err)
	}
	if err := os.Chmod(cfg.OutDir, 0o700); err != nil { //nolint:gosec // G302: tightens an existing directory to owner-only; it holds an exported private key
		return nil, fmt.Errorf("failed to restrict the output directory to the owner: %w", err)
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

	signingAddress, err := keys.InspectImport(keys.Import{Format: keys.ImportFormatOCR2, Path: ocr2Path, PasswordPath: passwordPath})
	if err != nil {
		return nil, fmt.Errorf("the exported OCR2 bundle is unusable: %w", err)
	}
	if err := checkExpectedID(cfg.ExpectedID, signingAddress); err != nil {
		// The rejected bundle decodes fine — it is simply the wrong key — so a valid-looking pair
		// left in OutDir invites a later operator, or a script that ignores the exit status, into
		// mounting a key this command already refused.
		removeRejectedExport(lggr, ocr2Path, passwordPath)
		return nil, err
	}

	lggr.Infow("exported the Chainlink node signing key for the CL-to-standalone migration",
		"outDir", cfg.OutDir, "signingAddress", signingAddress)
	return &ExportResult{
		SigningAddress: ChecksumAddress(signingAddress),
		OCR2Path:       ocr2Path,
		PasswordPath:   passwordPath,
	}, nil
}

func (c ExportConfig) validate() error {
	for _, field := range []struct{ name, value string }{
		{"NodeURL", c.NodeURL},
		{"APIEmail", c.APIEmail},
		{"APIPassword", c.APIPassword},
		{"OutDir", c.OutDir},
	} {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("%s is required", field.name)
		}
	}
	// The format is checked here, before the node is called and before any file is written: a
	// mistyped flag has to fail while OutDir is still empty rather than leaving an unverified key
	// and password behind.
	if expected := strings.TrimSpace(c.ExpectedID); expected != "" && !common.IsHexAddress(expected) {
		return fmt.Errorf(
			"expected_id %q is not a hex address; it should be this operator's OnchainSigningAddress "+
				"read from its JD record, handed over with the migration procedure", expected)
	}
	return nil
}

// preflightJobs enforces the one shape this procedure covers: exactly one ccvcommitteeverifier
// job. A standalone process runs a single job, so a node holding several verifier jobs cannot hand
// its one JD record to any of them — the committee's verifier jobs have to be consolidated first,
// and that is Chainlink Labs' side, not the operator's. The executor is not migrated (a single EVM
// executor with one funded key replaces the per-node transmitters), so its job count is not checked.
//
// An unreadable job list is a warning rather than a failure: the cutover itself still refuses a
// shape it cannot adopt, and blocking the key export on an API quirk helps no one. A list that
// reads fine but shows no CCV jobs is also a warning — an older node may report job types
// differently, and a wrong hard stop here would strand a valid migration.
func preflightJobs(ctx context.Context, lggr logger.Logger, client *NodeClient) error {
	verifiers, executors, err := client.CCVJobCounts(ctx)
	if err != nil {
		lggr.Warnw("could not read the node's job list; confirm manually that it runs exactly one "+
			JobTypeVerifier+" job before continuing", "err", err)
		return nil
	}
	if verifiers == 0 && executors == 0 {
		lggr.Warnw("the node runs no " + JobTypeVerifier + " or " + JobTypeExecutor + " jobs this tool can see; " +
			"confirm it is the node that runs this operator's CCV jobs before continuing")
		return nil
	}
	// Zero verifier jobs alongside at least one executor job is a different problem from several
	// verifier jobs, and saying "consolidate them" would send the operator after a job that is not
	// there. The likely cause is the wrong node.
	if verifiers == 0 {
		return fmt.Errorf(
			"the node runs no %s job, though it runs %d %s job(s); this migration exports the verifier's "+
				"signing key, so check that --node-url points at the node running this operator's %s job "+
				"(docs/migration/evm-cl-to-standalone.md)",
			JobTypeVerifier, executors, JobTypeExecutor, JobTypeVerifier)
	}
	if verifiers > 1 {
		return fmt.Errorf(
			"the node runs %d %s jobs; a standalone verifier runs a single job, so the committee's "+
				"verifier jobs must be consolidated into one before migrating — raise it with Chainlink "+
				"Labs rather than picking one (docs/migration/evm-cl-to-standalone.md)",
			verifiers, JobTypeVerifier)
	}
	return nil
}

// checkExpectedID compares the exported key's identity against the expected_id Chainlink Labs
// sourced from JD. The comparison runs while the node is still up, so a wrong bundle choice —
// which the decode self-check cannot see, since any bundle decodes to a self-consistent identity —
// fails the export rather than surfacing after the node is stopped. The value stays optional
// because it comes from Chainlink Labs out of band; an export without it is warned about rather
// than refused, since the check it skips is the only one that sees a wrong bundle.
func checkExpectedID(expectedID, signingAddress string) error {
	expected := strings.TrimSpace(expectedID)
	if expected == "" {
		return nil
	}
	if !strings.EqualFold(common.HexToAddress(expected).Hex(), ChecksumAddress(signingAddress)) {
		return fmt.Errorf(
			"the exported key carries signing address %s, which does not match the expected_id %s "+
				"from the operator's JD record: the wrong OCR2 bundle was exported — stop and recheck "+
				"which bundle the committee registers for this operator",
			ChecksumAddress(signingAddress), common.HexToAddress(expected).Hex())
	}
	return nil
}

// removeRejectedExport deletes the key and password an identity check refused, so a failed export
// leaves nothing mountable in OutDir. A removal that fails is warned about rather than returned:
// the identity mismatch is the error worth reading. The file that would not go away is named by
// os.Remove's *fs.PathError, not by a separate log field: passing the password file's path to a
// log call reads to static analysis as logging the password itself, and the error already carries
// the path.
func removeRejectedExport(lggr logger.Logger, paths ...string) {
	for _, path := range paths {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			lggr.Warnw("could not remove a rejected export artifact; delete it by hand before retrying",
				"err", err)
		}
	}
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
