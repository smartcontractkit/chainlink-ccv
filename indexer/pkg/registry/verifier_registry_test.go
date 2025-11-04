package registry

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func TestNewVerifierRegistry(t *testing.T) {
	reg := NewVerifierRegistry()
	require.NotNil(t, reg)

	// Verify it's ready to use by adding a verifier
	addr, err := protocol.NewUnknownAddressFromHex("0x1234")
	require.NoError(t, err)
	mockVerifier := newMockVerifierReader()
	err = reg.AddVerifier(addr, mockVerifier)
	assert.NoError(t, err)
}

func TestAddVerifier_Success(t *testing.T) {
	reg := NewVerifierRegistry()
	addr, err := protocol.NewUnknownAddressFromHex("0x1234")
	require.NoError(t, err)

	mockVerifier := newMockVerifierReader()
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
	mockVerifier2 := newMockVerifierReader()

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

	// Concurrent adds
	go func() {
		for i := range 10 {
			hexAddr := fmt.Sprintf("0x%04x", i)
			addr, _ := protocol.NewUnknownAddressFromHex(hexAddr)
			mockVerifier := newMockVerifierReader()
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
}

// mockVerifierReader is a minimal implementation of VerifierReader for testing.
type mockVerifierReader struct{}

func (m *mockVerifierReader) Start(ctx context.Context) error { return nil }
func (m *mockVerifierReader) Close() error                    { return nil }
func (m *mockVerifierReader) ProcessMessage(messageID protocol.Bytes32) (chan common.Result[protocol.CCVData], error) {
	return nil, nil
}

// newMockVerifierReader creates a pointer to a VerifierReader interface value.
func newMockVerifierReader() *common.VerifierReader {
	var vr common.VerifierReader = &mockVerifierReader{}
	return &vr
}
