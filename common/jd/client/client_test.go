package client

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/smartcontractkit/chainlink-protos/orchestrator/feedsmanager"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// mockEd25519Signer wraps an ed25519.PrivateKey to implement crypto.Signer.
// This mimics what the keystore's CSAKeystoreSigner does.
type mockEd25519Signer struct {
	privateKey ed25519.PrivateKey
}

func (s *mockEd25519Signer) Public() crypto.PublicKey {
	return s.privateKey.Public()
}

func (s *mockEd25519Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return ed25519.Sign(s.privateKey, digest), nil
}

func TestNewClient(t *testing.T) {
	t.Parallel()

	lggr, err := logger.New()
	require.NoError(t, err)

	// Generate test keys
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	jdPubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	signer := &mockEd25519Signer{privateKey: privKey}
	client := New(signer, jdPubKey, "ws://localhost:8080", lggr)

	assert.NotNil(t, client)
	assert.Equal(t, signer, client.csaSigner)
	assert.Equal(t, jdPubKey, client.jdPublicKey)
	assert.Equal(t, "ws://localhost:8080", client.jdURL)
	assert.NotNil(t, client.jobProposalCh)

	// Check public key derivation works
	derivedPubKey := signer.Public().(ed25519.PublicKey)
	assert.Equal(t, pubKey, derivedPubKey)
}

func TestClient_JobProposalChannel(t *testing.T) {
	t.Parallel()

	lggr, err := logger.New()
	require.NoError(t, err)

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	jdPubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	signer := &mockEd25519Signer{privateKey: privKey}
	client := New(signer, jdPubKey, "ws://localhost:8080", lggr)

	// Get the channel
	ch := client.JobProposalCh()
	assert.NotNil(t, ch)

	// Channel should be receive-only from outside
	// This compiles correctly because JobProposalCh returns <-chan *JobProposal
}

func TestClient_Close_BeforeConnect(t *testing.T) {
	t.Parallel()

	lggr, err := logger.New()
	require.NoError(t, err)

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	jdPubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	signer := &mockEd25519Signer{privateKey: privKey}
	client := New(signer, jdPubKey, "ws://localhost:8080", lggr)

	// Closing before connecting should not panic
	err = client.Close()
	assert.NoError(t, err)

	// Closing again should also be safe (idempotent)
	err = client.Close()
	assert.NoError(t, err)
}

// JD answers UpdateNode with per-chain errors instead of failing the call; they must not be dropped.
func TestChainConfigErrors(t *testing.T) {
	require.NoError(t, chainConfigErrors(nil))
	err := chainConfigErrors(map[string]*pb.ChainConfigError{
		"421614":   {Message: "invalid OCR2 key bundle"},
		"11155111": {Message: "chain not found"},
	})
	require.EqualError(t, err, "JD rejected 2 chain config(s): 11155111: chain not found; 421614: invalid OCR2 key bundle")
}
