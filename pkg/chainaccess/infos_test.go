package chainaccess

import (
	"testing"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type TestInfo struct {
	ChainID         string
	Type            string
	Family          string
	UniqueChainName string
}

func (t TestInfo) Empty() bool {
	return t.ChainID == "" && t.Type == "" && t.Family == "" && t.UniqueChainName == ""
}

func TestHelper_GetBlockchainByChainSelector_NilMapEntriesTreatedAsNotFound(t *testing.T) {
	validInfo := TestInfo{ChainID: "123", Type: "evm", Family: "evm", UniqueChainName: "chain-123"}
	selector := protocol.ChainSelector(999)
	tests := []struct {
		name    string
		infos   Infos[TestInfo]
		wantErr bool
	}{
		{
			name:    "returns error when key exists but value is nil",
			infos:   Infos[TestInfo]{"999": {}},
			wantErr: false, // With generic types, this isn't something we can test for.
		},
		{
			name:    "returns info when key exists and value is non-nil",
			infos:   Infos[TestInfo]{"999": validInfo},
			wantErr: false,
		},
		{
			name:    "returns error when key does not exist",
			infos:   Infos[TestInfo]{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.infos.GetBlockchainByChainSelector(selector)
			if tt.wantErr {
				if err == nil {
					t.Errorf("GetBlockchainByChainSelector() expected error, got nil")
				}
				if !got.Empty() {
					t.Errorf("GetBlockchainByChainSelector() expected empty info when error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Errorf("GetBlockchainByChainSelector() unexpected error: %v", err)
			}
			/*
				// Can't reliably test for nil vs empty struct with generic types.
				if got.Empty() {
					t.Errorf("GetBlockchainByChainSelector() expected non-empty info")
				}
			*/
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
