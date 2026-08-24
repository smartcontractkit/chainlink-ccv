package migration

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap/keys"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// happyNode returns a fake node running one verifier job, with one EVM OCR2 bundle — the shape the
// migration procedure applies to. The node also runs an executor job, which the verifier-only
// migration ignores.
func happyNode(t *testing.T) *fakeNode {
	t.Helper()
	node := newFakeNode(t)
	node.ocr2Key = newTestKey(t)
	node.ocr2BundlesJSON = ocr2BundleJSON("bundle-1", "evm")
	node.jobsJSON = oneVerifierOneExecutorJSON()
	return node
}

func happyConfig(node *fakeNode, url, outDir string) ExportConfig {
	return ExportConfig{
		NodeURL:     url,
		APIEmail:    node.email,
		APIPassword: node.password,
		OutDir:      outDir,
	}
}

func TestExportNodeKeys(t *testing.T) {
	t.Parallel()
	node := happyNode(t)
	srv := node.start()
	outDir := t.TempDir()

	result, err := ExportNodeKeys(context.Background(), logger.Test(t), happyConfig(node, srv.URL, outDir))
	require.NoError(t, err)

	// The identity reported is the key the node held, in the checksummed form an operator compares
	// against a block explorer.
	assert.Equal(t, addressOf(node.ocr2Key), result.SigningAddress)

	// Every key material file is owner-only.
	for _, path := range []string{result.OCR2Path, result.PasswordPath} {
		info, err := os.Stat(path)
		require.NoError(t, err, "%s should exist", path)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "%s must not be world-readable", path)
	}

	// The export decodes under the generated password to the identity the node registered.
	signingID, err := keys.InspectImport(keys.Import{Format: keys.ImportFormatOCR2, Path: result.OCR2Path, PasswordPath: result.PasswordPath})
	require.NoError(t, err)
	assert.Equal(t, result.SigningAddress, ChecksumAddress(signingID))
}

func TestExportNodeKeysRefusesANodeWithSeveralVerifierJobs(t *testing.T) {
	t.Parallel()
	node := happyNode(t)
	node.jobsJSON = strings.Join([]string{
		jobJSON("1", JobTypeVerifier),
		jobJSON("2", JobTypeVerifier),
		jobJSON("3", JobTypeExecutor),
	}, ",")
	srv := node.start()

	_, err := ExportNodeKeys(context.Background(), logger.Test(t), happyConfig(node, srv.URL, t.TempDir()))
	require.ErrorContains(t, err, "consolidated")
}

// A node with an executor job but no verifier job is the wrong node, not a node whose verifier
// jobs need consolidating — the error has to say so, or it sends the operator after a job that
// does not exist.
func TestExportNodeKeysRefusesANodeWithNoVerifierJob(t *testing.T) {
	t.Parallel()
	node := happyNode(t)
	node.jobsJSON = jobJSON("1", JobTypeExecutor)
	srv := node.start()

	_, err := ExportNodeKeys(context.Background(), logger.Test(t), happyConfig(node, srv.URL, t.TempDir()))
	require.ErrorContains(t, err, "runs no "+JobTypeVerifier+" job")
	require.NotContains(t, err.Error(), "consolidated")
}

func TestExportNodeKeysHonorsTheBundleOverride(t *testing.T) {
	t.Parallel()
	node := happyNode(t)
	// An ambiguous listing, resolved by hand: a second EVM bundle the resolution would otherwise
	// refuse to guess between.
	node.ocr2BundlesJSON = strings.Join([]string{
		ocr2BundleJSON("bundle-1", "evm"),
		ocr2BundleJSON("bundle-2", "evm"),
	}, ",")
	srv := node.start()

	cfg := happyConfig(node, srv.URL, t.TempDir())
	cfg.BundleID = "bundle-1"
	result, err := ExportNodeKeys(context.Background(), logger.Test(t), cfg)
	require.NoError(t, err)
	assert.Equal(t, addressOf(node.ocr2Key), result.SigningAddress)
}

// The JD-sourced expected_id is the only check that sees a wrong bundle choice: any exported
// bundle decodes to a self-consistent identity, so the decode self-check alone cannot.
func TestExportNodeKeysExpectedID(t *testing.T) {
	t.Parallel()

	t.Run("matching expected_id passes", func(t *testing.T) {
		t.Parallel()
		node := happyNode(t)
		srv := node.start()
		cfg := happyConfig(node, srv.URL, t.TempDir())
		cfg.ExpectedID = addressOf(node.ocr2Key)

		result, err := ExportNodeKeys(context.Background(), logger.Test(t), cfg)
		require.NoError(t, err)
		assert.Equal(t, addressOf(node.ocr2Key), result.SigningAddress)
	})

	// The rejected pair decodes fine — it is the wrong key, not a broken one — so leaving it in
	// outDir would let a later mount use a key this command refused.
	t.Run("mismatching expected_id fails as a wrong bundle export and removes the files", func(t *testing.T) {
		t.Parallel()
		node := happyNode(t)
		srv := node.start()
		outDir := t.TempDir()
		cfg := happyConfig(node, srv.URL, outDir)
		cfg.ExpectedID = addressOf(newTestKey(t))

		_, err := ExportNodeKeys(context.Background(), logger.Test(t), cfg)
		require.ErrorContains(t, err, "wrong OCR2 bundle")
		assert.NoFileExists(t, filepath.Join(outDir, OCR2ExportFileName))
		assert.NoFileExists(t, filepath.Join(outDir, PasswordFileName))
	})

	t.Run("malformed expected_id fails before anything is exported", func(t *testing.T) {
		t.Parallel()
		node := happyNode(t)
		srv := node.start()
		outDir := t.TempDir()
		cfg := happyConfig(node, srv.URL, outDir)
		cfg.ExpectedID = "not-an-address"

		_, err := ExportNodeKeys(context.Background(), logger.Test(t), cfg)
		require.ErrorContains(t, err, "not a hex address")
		assert.NoFileExists(t, filepath.Join(outDir, OCR2ExportFileName))
		assert.NoFileExists(t, filepath.Join(outDir, PasswordFileName))
	})
}

// The snippet is ready to paste: the [key_import] block with expected_id already filled in, so
// the one value that must not be mistyped never passes through a human.
func TestWriteKeyImportSnippet(t *testing.T) {
	t.Parallel()
	priv := newTestKey(t)
	path := filepath.Join(t.TempDir(), VerifierTOMLFileName)
	require.NoError(t, WriteKeyImportSnippet(path, "verifier", OCR2ExportFileName, addressOf(priv)))

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(content), "[key_import]")
	assert.Contains(t, string(content), `expected_id   = "`+addressOf(priv)+`"`)
	assert.Contains(t, string(content), OCR2ExportFileName)
	assert.Contains(t, string(content), PasswordFileName)
}

func TestGenerateExportPassword(t *testing.T) {
	t.Parallel()
	first, err := generateExportPassword()
	require.NoError(t, err)
	second, err := generateExportPassword()
	require.NoError(t, err)
	assert.Len(t, first, 40)
	assert.NotEqual(t, first, second, "two generated passwords must not collide")
	for _, r := range first {
		assert.Contains(t, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", string(r))
	}
}

func TestExportConfigValidate(t *testing.T) {
	t.Parallel()
	require.ErrorContains(t, ExportConfig{}.validate(), "NodeURL")
	require.ErrorContains(t, ExportConfig{NodeURL: "http://localhost:6688"}.validate(), "APIEmail")
	require.NoError(t, ExportConfig{
		NodeURL: "http://localhost:6688", APIEmail: "admin@example.com", APIPassword: "pw",
		OutDir: "out",
	}.validate())
}
