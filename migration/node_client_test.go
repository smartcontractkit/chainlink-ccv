package migration

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewNodeClientRejectsBadURLs(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"", "not-a-url", "ftp://node.example", "http://",
		"http://node.example:6688/v2", "http://node.example:6688/?x=1",
	} {
		_, err := NewNodeClient(raw)
		require.Errorf(t, err, "expected %q to be rejected", raw)
	}
	client, err := NewNodeClient("http://localhost:6688")
	require.NoError(t, err)
	require.NotNil(t, client)
	// A trailing slash is canonicalized away rather than doubling every request path.
	_, err = NewNodeClient("http://localhost:6688/")
	require.NoError(t, err)
}

func TestLoginStoresTheSessionCookie(t *testing.T) {
	t.Parallel()
	node := newFakeNode(t)
	node.ocr2BundlesJSON = ocr2BundleJSON("bundle-1", "evm")
	srv := node.start()

	client, err := NewNodeClient(srv.URL)
	require.NoError(t, err)
	require.NoError(t, client.Login(context.Background(), node.email, node.password))

	// Any later call proves the jar kept the session: the fake rejects cookie-less requests.
	_, err = client.EVMOCR2BundleID(context.Background())
	require.NoError(t, err)
	assert.True(t, node.sawSessionCookie.Load())
}

func TestLoginRejected(t *testing.T) {
	t.Parallel()
	node := newFakeNode(t)
	srv := node.start()

	client, err := NewNodeClient(srv.URL)
	require.NoError(t, err)
	err = client.Login(context.Background(), node.email, "wrong-password")
	require.ErrorContains(t, err, "rejected the API credentials")
}

func TestEVMOCR2BundleID(t *testing.T) {
	t.Parallel()

	t.Run("exactly one EVM bundle", func(t *testing.T) {
		t.Parallel()
		node := newFakeNode(t)
		node.ocr2BundlesJSON = strings.Join([]string{
			ocr2BundleJSON("sol-bundle", "solana"),
			ocr2BundleJSON("bundle-1", "evm"),
		}, ",")
		srv := node.start()
		client := loggedInClient(t, node, srv.URL)

		id, err := client.EVMOCR2BundleID(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "bundle-1", id)
	})

	t.Run("no EVM bundle", func(t *testing.T) {
		t.Parallel()
		node := newFakeNode(t)
		node.ocr2BundlesJSON = ocr2BundleJSON("sol-bundle", "solana")
		srv := node.start()
		client := loggedInClient(t, node, srv.URL)

		_, err := client.EVMOCR2BundleID(context.Background())
		require.ErrorContains(t, err, "no OCR2 key bundle for EVM")
	})

	t.Run("several EVM bundles is an error, not a guess", func(t *testing.T) {
		t.Parallel()
		node := newFakeNode(t)
		node.ocr2BundlesJSON = strings.Join([]string{
			ocr2BundleJSON("bundle-1", "evm"),
			ocr2BundleJSON("bundle-2", "evm"),
		}, ",")
		srv := node.start()
		client := loggedInClient(t, node, srv.URL)

		_, err := client.EVMOCR2BundleID(context.Background())
		require.ErrorContains(t, err, "--bundle-id")
	})
}

func TestAccountForChain(t *testing.T) {
	t.Parallel()

	t.Run("the enabled account for the chain", func(t *testing.T) {
		t.Parallel()
		node := newFakeNode(t)
		node.ethKeysJSON = strings.Join([]string{
			ethKeyJSON("0xAAAA", "1", false),
			ethKeyJSON("0xBBBB", "1", true),   // disabled for the chain: skipped
			ethKeyJSON("0xCCCC", "10", false), // another chain
		}, ",")
		srv := node.start()
		client := loggedInClient(t, node, srv.URL)

		account, err := client.AccountForChain(context.Background(), "1")
		require.NoError(t, err)
		assert.Equal(t, "0xAAAA", account)
	})

	t.Run("no account enabled for the chain", func(t *testing.T) {
		t.Parallel()
		node := newFakeNode(t)
		node.ethKeysJSON = ethKeyJSON("0xBBBB", "1", true)
		srv := node.start()
		client := loggedInClient(t, node, srv.URL)

		_, err := client.AccountForChain(context.Background(), "1")
		require.ErrorContains(t, err, "no account enabled for chain 1")
	})

	t.Run("several accounts on one chain is an error, not a guess", func(t *testing.T) {
		t.Parallel()
		node := newFakeNode(t)
		node.ethKeysJSON = strings.Join([]string{
			ethKeyJSON("0xAAAA", "1", false),
			ethKeyJSON("0xDDDD", "1", false),
		}, ",")
		srv := node.start()
		client := loggedInClient(t, node, srv.URL)

		_, err := client.AccountForChain(context.Background(), "1")
		require.ErrorContains(t, err, "--account")
	})
}

func TestCCVJobCounts(t *testing.T) {
	t.Parallel()
	node := newFakeNode(t)
	node.jobsJSON = strings.Join([]string{
		jobJSON("1", JobTypeVerifier),
		jobJSON("2", JobTypeExecutor),
		jobJSON("3", "fluxmonitor"),
		jobJSON("4", JobTypeVerifier),
	}, ",")
	srv := node.start()
	client := loggedInClient(t, node, srv.URL)

	verifiers, executors, err := client.CCVJobCounts(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, verifiers)
	assert.Equal(t, 1, executors)
}

func TestExportKeySendsThePasswordAndReturnsTheBody(t *testing.T) {
	t.Parallel()
	node := newFakeNode(t)
	node.ethKey = newTestKey(t)
	srv := node.start()
	client := loggedInClient(t, node, srv.URL)

	body, err := client.ExportETHKey(context.Background(), addressOf(node.ethKey), "export-password")
	require.NoError(t, err)
	assert.Equal(t, "export-password", node.getLastNewPassword())
	assert.NotEmpty(t, body)
}

func loggedInClient(t *testing.T, node *fakeNode, url string) *NodeClient {
	t.Helper()
	client, err := NewNodeClient(url)
	require.NoError(t, err)
	require.NoError(t, client.Login(context.Background(), node.email, node.password))
	return client
}
