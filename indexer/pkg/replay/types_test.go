package replay

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseType(t *testing.T) {
	tests := []struct {
		input   string
		want    Type
		wantErr bool
	}{
		{"discovery", TypeDiscovery, false},
		{"messages", TypeMessages, false},
		{"invalid", "", true},
		{"", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseType(tt.input)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestRequestHash_Deterministic(t *testing.T) {
	req := Request{
		Type:  TypeDiscovery,
		Since: 42,
		Force: true,
	}
	h1 := req.Hash()
	h2 := req.Hash()
	assert.Equal(t, h1, h2, "same request must produce the same hash")
	assert.Len(t, h1, 64, "SHA-256 hex digest should be 64 characters")
}

func TestRequestHash_DiffersByForce(t *testing.T) {
	base := Request{Type: TypeDiscovery, Since: 42, Force: false}
	forced := Request{Type: TypeDiscovery, Since: 42, Force: true}
	assert.NotEqual(t, base.Hash(), forced.Hash())
}

func TestRequestHash_DiffersBySince(t *testing.T) {
	a := Request{Type: TypeDiscovery, Since: 1, Force: false}
	b := Request{Type: TypeDiscovery, Since: 2, Force: false}
	assert.NotEqual(t, a.Hash(), b.Hash())
}

func TestRequestHash_DiffersByType(t *testing.T) {
	a := Request{Type: TypeDiscovery, Since: 1}
	b := Request{Type: TypeMessages, MessageIDs: []string{"0x1"}}
	assert.NotEqual(t, a.Hash(), b.Hash())
}

func TestRequestHash_MessageIDsOrderIndependent(t *testing.T) {
	a := Request{Type: TypeMessages, MessageIDs: []string{"0xabc", "0xdef"}, Force: false}
	b := Request{Type: TypeMessages, MessageIDs: []string{"0xdef", "0xabc"}, Force: false}
	assert.Equal(t, a.Hash(), b.Hash(), "message ID order should not affect hash")
}

func TestRequestHash_DiffersByMessageIDs(t *testing.T) {
	a := Request{Type: TypeMessages, MessageIDs: []string{"0xabc"}, Force: false}
	b := Request{Type: TypeMessages, MessageIDs: []string{"0xdef"}, Force: false}
	assert.NotEqual(t, a.Hash(), b.Hash())
}

func TestParseStatus(t *testing.T) {
	tests := []struct {
		input   string
		want    Status
		wantErr bool
	}{
		{"pending", StatusPending, false},
		{"running", StatusRunning, false},
		{"completed", StatusCompleted, false},
		{"failed", StatusFailed, false},
		{"unknown", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseStatus(tt.input)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
