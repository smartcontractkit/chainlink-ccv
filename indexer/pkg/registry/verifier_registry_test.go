package registry

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/readers"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// mockVerifierResultsAPI is a simple mock implementation of VerifierResultsAPI for testing.
type mockVerifierResultsAPI struct {
	results map[protocol.Bytes32]protocol.CCVData
	err     error
}

func (m *mockVerifierResultsAPI) GetVerifications(ctx context.Context, messageIDs []protocol.Bytes32) (map[protocol.Bytes32]protocol.CCVData, error) {
	if m.err != nil {
		return m.results, m.err
	}
	return m.results, nil
}

// newMockVerifierReader creates a new VerifierReader instance for testing.
func newMockVerifierReader() *readers.VerifierReader {
	ctx := context.Background()
	addr, _ := protocol.NewUnknownAddressFromHex("0x0000")
	mockVerifier := &mockVerifierResultsAPI{
		results: make(map[protocol.Bytes32]protocol.CCVData),
	}
	config := readers.VerifierReaderConfig{
		BatchSize:         10,
		MaxWaitTime:       100 * time.Millisecond,
		MaxPendingBatches: 5,
	}
	return readers.NewVerifierReader(ctx, addr, mockVerifier, config)
}

func TestNewVerifierRegistry(t *testing.T) {
	reg := NewVerifierRegistry()
	require.NotNil(t, reg)

	// Verify it's ready to use by adding a verifier
	addr, err := protocol.NewUnknownAddressFromHex("0x1234")
	require.NoError(t, err)
	mockVerifier := newMockVerifierReader()
	defer mockVerifier.Close()
	err = reg.AddVerifier(addr, mockVerifier)
	assert.NoError(t, err)
}

func TestAddVerifier_Success(t *testing.T) {
	reg := NewVerifierRegistry()
	addr, err := protocol.NewUnknownAddressFromHex("0x1234")
	require.NoError(t, err)

	mockVerifier := newMockVerifierReader()
	defer mockVerifier.Close()
	err = reg.AddVerifier(addr, mockVerifier)
	assert.NoError(t, err)

	retrieved := reg.GetVerifier(addr)
	assert.Equal(t, mockVerifier, retrieved)
}

func TestAddVerifier_Duplicate(t *testing.T) {
	reg := NewVerifierRegistry()
	addr, err := protocol.NewUnknownAddressFromHex("0x1234")
	require.NoError(t, err)

	mockVerifier := newMockVerifierReader()
	defer mockVerifier.Close()
	err = reg.AddVerifier(addr, mockVerifier)
	require.NoError(t, err)

	err = reg.AddVerifier(addr, mockVerifier)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "verifier already exists")
}

func TestAddVerifier_NilVerifier(t *testing.T) {
	reg := NewVerifierRegistry()
	addr, err := protocol.NewUnknownAddressFromHex("0x1234")
	require.NoError(t, err)

	err = reg.AddVerifier(addr, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "verifier cannot be nil")
}

func TestRemoveVerifier_Success(t *testing.T) {
	reg := NewVerifierRegistry()
	addr, err := protocol.NewUnknownAddressFromHex("0x1234")
	require.NoError(t, err)

	mockVerifier := newMockVerifierReader()
	defer mockVerifier.Close()
	err = reg.AddVerifier(addr, mockVerifier)
	require.NoError(t, err)

	err = reg.RemoveVerifier(addr)
	assert.NoError(t, err)

	retrieved := reg.GetVerifier(addr)
	assert.Nil(t, retrieved)
}

func TestRemoveVerifier_NonExistent(t *testing.T) {
	reg := NewVerifierRegistry()
	addr, err := protocol.NewUnknownAddressFromHex("0x1234")
	require.NoError(t, err)

	err = reg.RemoveVerifier(addr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "verifier does not exist")
}

func TestGetVerifier_NonExistent(t *testing.T) {
	reg := NewVerifierRegistry()
	addr, err := protocol.NewUnknownAddressFromHex("0x1234")
	require.NoError(t, err)

	retrieved := reg.GetVerifier(addr)
	assert.Nil(t, retrieved)
}

func TestGetVerifier_MultipleVerifiers(t *testing.T) {
	reg := NewVerifierRegistry()

	addr1, err := protocol.NewUnknownAddressFromHex("0x1111")
	require.NoError(t, err)
	addr2, err := protocol.NewUnknownAddressFromHex("0x2222")
	require.NoError(t, err)

	mockVerifier1 := newMockVerifierReader()
	defer mockVerifier1.Close()
	mockVerifier2 := newMockVerifierReader()
	defer mockVerifier2.Close()

	err = reg.AddVerifier(addr1, mockVerifier1)
	require.NoError(t, err)
	err = reg.AddVerifier(addr2, mockVerifier2)
	require.NoError(t, err)

	retrieved1 := reg.GetVerifier(addr1)
	retrieved2 := reg.GetVerifier(addr2)

	assert.NotNil(t, retrieved1)
	assert.NotNil(t, retrieved2)
	assert.Equal(t, mockVerifier1, retrieved1)
	assert.Equal(t, mockVerifier2, retrieved2)
	// Verify they are different pointers (different addresses stored for different keys)
	assert.True(t, retrieved1 != retrieved2, "retrieved verifiers should be different instances")
}

func TestConcurrentAccess(t *testing.T) {
	reg := NewVerifierRegistry()
	done := make(chan bool)
	var verifiersMu sync.Mutex
	verifiers := make([]*readers.VerifierReader, 0, 10)

	// Concurrent adds
	go func() {
		for i := range 10 {
			hexAddr := fmt.Sprintf("0x%04x", i)
			addr, _ := protocol.NewUnknownAddressFromHex(hexAddr)
			mockVerifier := newMockVerifierReader()
			verifiersMu.Lock()
			verifiers = append(verifiers, mockVerifier)
			verifiersMu.Unlock()
			_ = reg.AddVerifier(addr, mockVerifier)
		}
		done <- true
	}()

	// Concurrent reads
	go func() {
		for i := range 10 {
			hexAddr := fmt.Sprintf("0x%04x", i)
			addr, _ := protocol.NewUnknownAddressFromHex(hexAddr)
			_ = reg.GetVerifier(addr)
		}
		done <- true
	}()

	<-done
	<-done

	// Clean up all verifiers
	verifiersMu.Lock()
	for _, verifier := range verifiers {
		if verifier != nil {
			_ = verifier.Close()
		}
	}
	verifiersMu.Unlock()
}
