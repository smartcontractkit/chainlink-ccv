package blockchain

import (
	"testing"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func TestHelper_GetBlockchainByChainSelector_NilMapEntriesTreatedAsNotFound(t *testing.T) {
	validInfo := &Info{ChainID: "123", Type: "evm", Family: "evm", UniqueChainName: "chain-123"}
	selector := protocol.ChainSelector(999)
	tests := []struct {
		name    string
		infos   map[string]*Info
		wantErr bool
	}{
		{
			name:    "returns error when key exists but value is nil",
			infos:   map[string]*Info{"999": nil},
			wantErr: true,
		},
		{
			name:    "returns info when key exists and value is non-nil",
			infos:   map[string]*Info{"999": validInfo},
			wantErr: false,
		},
		{
			name:    "returns error when key does not exist",
			infos:   map[string]*Info{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHelper(tt.infos)
			got, err := h.GetBlockchainByChainSelector(selector)
			if tt.wantErr {
				if err == nil {
					t.Errorf("GetBlockchainByChainSelector() expected error, got nil")
				}
				if got != nil {
					t.Errorf("GetBlockchainByChainSelector() expected nil info when error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Errorf("GetBlockchainByChainSelector() unexpected error: %v", err)
			}
			if got == nil {
				t.Errorf("GetBlockchainByChainSelector() expected non-nil info")
			}
		})
	}
}

/*
func TestHelper_GetRPCEndpoint_ReturnsErrorWhenSelectorMapsToNil(t *testing.T) {
	h := NewHelper(map[string]*Info{"1": nil})
	_, err := h.GetRPCEndpoint(protocol.ChainSelector(1))
	if err == nil {
		t.Error("GetRPCEndpoint() expected error when map value is nil, got nil")
	}
}

*/
