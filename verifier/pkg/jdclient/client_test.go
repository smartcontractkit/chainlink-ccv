package jdclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestNewClient(t *testing.T) {
	t.Parallel()

	lggr, err := logger.New()
	require.NoError(t, err)

	// Generate test keys
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	jdPubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	client := NewClient(privKey, jdPubKey, "ws://localhost:8080", lggr)

	assert.NotNil(t, client)
	assert.Equal(t, privKey, client.csaPrivateKey)
	assert.Equal(t, jdPubKey, client.jdPublicKey)
	assert.Equal(t, "ws://localhost:8080", client.jdURL)
	assert.NotNil(t, client.jobProposalCh)

	// Check public key derivation works
	derivedPubKey := privKey.Public().(ed25519.PublicKey)
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

	client := NewClient(privKey, jdPubKey, "ws://localhost:8080", lggr)

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

	client := NewClient(privKey, jdPubKey, "ws://localhost:8080", lggr)

	// Closing before connecting should not panic
	err = client.Close()
	assert.NoError(t, err)

	// Closing again should also be safe (idempotent)
	err = client.Close()
	assert.NoError(t, err)
}
