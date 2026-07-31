package migrate

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

// happyNode returns a fake node running one verifier job and one executor job, with one EVM OCR2
// bundle and one account enabled for chain 1 — the shape the migration procedure applies to.
func happyNode(t *testing.T) *fakeNode {
	t.Helper()
	node := newFakeNode(t)
	node.ocr2Key = newTestKey(t)
	node.ethKey = newTestKey(t)
	node.ocr2BundlesJSON = ocr2BundleJSON("bundle-1", "evm")
	node.ethKeysJSON = ethKeyJSON(addressOf(node.ethKey), "1", false)
	node.jobsJSON = oneVerifierOneExecutorJSON()
	return node
}

func writeCredsFile(t *testing.T, dir, contents string) string {
	t.Helper()
	path := filepath.Join(dir, "api-creds.txt")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

func TestExportNodeKeys(t *testing.T) {
	t.Parallel()
	node := happyNode(t)
	srv := node.start()
	outDir := t.TempDir()
	credsPath := writeCredsFile(t, t.TempDir(), node.email+"\n"+node.password+"\n")

	result, err := ExportNodeKeys(context.Background(), logger.Test(t), ExportConfig{
		NodeURL:   srv.URL,
		CredsPath: credsPath,
		ChainID:   "1",
		OutDir:    outDir,
	})
	require.NoError(t, err)

	// The identities reported are the keys the node held, in the checksummed form an operator
	// compares against a block explorer.
	assert.Equal(t, addressOf(node.ocr2Key), result.SigningAddress)
	assert.Equal(t, addressOf(node.ethKey), result.TransmitterAddress)

	// Every key material file is owner-only; the snippets carry public addresses only.
	for _, path := range []string{result.OCR2Path, result.ETHPath, result.PasswordPath} {
		info, err := os.Stat(path)
		require.NoError(t, err, "%s should exist", path)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "%s must not be world-readable", path)
	}

	// Both exports decode under the generated password to the identities the node registered.
	signingID, err := keys.InspectImport(keys.Import{Format: keys.ImportFormatOCR2, Path: result.OCR2Path, PasswordPath: result.PasswordPath})
	require.NoError(t, err)
	assert.Equal(t, result.SigningAddress, checksumAddress(signingID))
	transmitterID, err := keys.InspectImport(keys.Import{Format: keys.ImportFormatETH, Path: result.ETHPath, PasswordPath: result.PasswordPath})
	require.NoError(t, err)
	assert.Equal(t, result.TransmitterAddress, checksumAddress(transmitterID))

	// The snippets are ready to paste: the [key_import] block with expected_id already filled in,
	// so the one value that must not be mistyped never passes through a human.
	verifierTOML, err := os.ReadFile(result.VerifierTOMLPath)
	require.NoError(t, err)
	assert.Contains(t, string(verifierTOML), "[key_import]")
	assert.Contains(t, string(verifierTOML), `expected_id   = "`+result.SigningAddress+`"`)
	executorTOML, err := os.ReadFile(result.ExecutorTOMLPath)
	require.NoError(t, err)
	assert.Contains(t, string(executorTOML), `expected_id   = "`+result.TransmitterAddress+`"`)
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
	credsPath := writeCredsFile(t, t.TempDir(), node.email+"\n"+node.password)

	_, err := ExportNodeKeys(context.Background(), logger.Test(t), ExportConfig{
		NodeURL:   srv.URL,
		CredsPath: credsPath,
		ChainID:   "1",
		OutDir:    t.TempDir(),
	})
	require.ErrorContains(t, err, "consolidated")
}

func TestExportNodeKeysRefusesAnExportThatDisagreesWithTheListing(t *testing.T) {
	t.Parallel()
	node := happyNode(t)
	// The listing names one account, but the export endpoint returns a different key — the exact
	// situation expected_id exists to catch at boot, caught here while the node is still up.
	node.ethKeysJSON = ethKeyJSON(addressOf(newTestKey(t)), "1", false)
	srv := node.start()
	credsPath := writeCredsFile(t, t.TempDir(), node.email+"\n"+node.password)

	_, err := ExportNodeKeys(context.Background(), logger.Test(t), ExportConfig{
		NodeURL:   srv.URL,
		CredsPath: credsPath,
		ChainID:   "1",
		OutDir:    t.TempDir(),
	})
	require.ErrorContains(t, err, "a different key than the account names")
}

func TestExportNodeKeysHonorsTheOverrides(t *testing.T) {
	t.Parallel()
	node := happyNode(t)
	// Ambiguous listings, resolved by hand: a second EVM bundle and a second account on the chain.
	node.ocr2BundlesJSON = strings.Join([]string{
		ocr2BundleJSON("bundle-1", "evm"),
		ocr2BundleJSON("bundle-2", "evm"),
	}, ",")
	node.ethKeysJSON = strings.Join([]string{
		ethKeyJSON(addressOf(node.ethKey), "1", false),
		ethKeyJSON(addressOf(newTestKey(t)), "1", false),
	}, ",")
	srv := node.start()
	credsPath := writeCredsFile(t, t.TempDir(), node.email+"\n"+node.password)

	result, err := ExportNodeKeys(context.Background(), logger.Test(t), ExportConfig{
		NodeURL:   srv.URL,
		CredsPath: credsPath,
		ChainID:   "1",
		OutDir:    t.TempDir(),
		BundleID:  "bundle-1",
		Account:   addressOf(node.ethKey),
	})
	require.NoError(t, err)
	assert.Equal(t, addressOf(node.ocr2Key), result.SigningAddress)
	assert.Equal(t, addressOf(node.ethKey), result.TransmitterAddress)
}

func TestReadAPICredentials(t *testing.T) {
	t.Parallel()

	t.Run("email and password, CRLF tolerated", func(t *testing.T) {
		t.Parallel()
		path := writeCredsFile(t, t.TempDir(), "admin@example.com\r\nnode-password\r\n")
		email, password, err := readAPICredentials(path)
		require.NoError(t, err)
		assert.Equal(t, "admin@example.com", email)
		assert.Equal(t, "node-password", password)
	})

	t.Run("a password may contain spaces", func(t *testing.T) {
		t.Parallel()
		path := writeCredsFile(t, t.TempDir(), "admin@example.com\npass word\n")
		_, password, err := readAPICredentials(path)
		require.NoError(t, err)
		assert.Equal(t, "pass word", password)
	})

	t.Run("missing password line", func(t *testing.T) {
		t.Parallel()
		path := writeCredsFile(t, t.TempDir(), "admin@example.com\n")
		_, _, err := readAPICredentials(path)
		require.ErrorContains(t, err, "line 2")
	})

	t.Run("empty password", func(t *testing.T) {
		t.Parallel()
		path := writeCredsFile(t, t.TempDir(), "admin@example.com\n\n")
		_, _, err := readAPICredentials(path)
		require.ErrorContains(t, err, "empty password")
	})
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
	require.ErrorContains(t, ExportConfig{}.validate(), "--node-url")
	require.ErrorContains(t, ExportConfig{NodeURL: "http://localhost:6688"}.validate(), "--api-creds")
	require.NoError(t, ExportConfig{
		NodeURL: "http://localhost:6688", CredsPath: "creds.txt", ChainID: "1", OutDir: "out",
	}.validate())
}
