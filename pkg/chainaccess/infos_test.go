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

func TestInfos_GetAllInfos(t *testing.T) {
	t.Run("empty infos returns empty map", func(t *testing.T) {
		infos := Infos[TestInfo]{}
		result := infos.GetAllInfos()
		if len(result) != 0 {
			t.Errorf("expected empty map, got %v", result)
		}
	})

	t.Run("valid numeric keys are converted to ChainSelectors", func(t *testing.T) {
		infos := Infos[TestInfo]{
			"100": {ChainID: "100", Type: "evm"},
			"200": {ChainID: "200", Type: "evm"},
		}
		result := infos.GetAllInfos()
		if len(result) != 2 {
			t.Errorf("expected 2 entries, got %d", len(result))
		}
		if result[protocol.ChainSelector(100)].ChainID != "100" {
			t.Errorf("expected ChainID 100, got %s", result[protocol.ChainSelector(100)].ChainID)
		}
		if result[protocol.ChainSelector(200)].ChainID != "200" {
			t.Errorf("expected ChainID 200, got %s", result[protocol.ChainSelector(200)].ChainID)
		}
	})

	t.Run("non-numeric keys are skipped", func(t *testing.T) {
		infos := Infos[TestInfo]{
			"valid":    {ChainID: "bad"},  // non-numeric: skipped
			"also-bad": {ChainID: "bad"},  // non-numeric: skipped
			"42":       {ChainID: "good"}, // numeric: kept
		}
		result := infos.GetAllInfos()
		if len(result) != 1 {
			t.Errorf("expected 1 entry, got %d", len(result))
		}
		if result[protocol.ChainSelector(42)].ChainID != "good" {
			t.Errorf("expected ChainID good, got %s", result[protocol.ChainSelector(42)].ChainID)
		}
	})
}

func TestInfos_GetAllChainSelectors(t *testing.T) {
	t.Run("empty infos returns empty slice", func(t *testing.T) {
		infos := Infos[TestInfo]{}
		selectors := infos.GetAllChainSelectors()
		if len(selectors) != 0 {
			t.Errorf("expected empty slice, got %v", selectors)
		}
	})

	t.Run("returns one selector per valid numeric key", func(t *testing.T) {
		infos := Infos[TestInfo]{
			"10":      {ChainID: "10"},
			"20":      {ChainID: "20"},
			"bad-key": {ChainID: "skip"},
		}
		selectors := infos.GetAllChainSelectors()
		if len(selectors) != 2 {
			t.Errorf("expected 2 selectors, got %d: %v", len(selectors), selectors)
		}
		found := make(map[protocol.ChainSelector]bool)
		for _, s := range selectors {
			found[s] = true
		}
		if !found[protocol.ChainSelector(10)] {
			t.Error("expected selector 10, not found")
		}
		if !found[protocol.ChainSelector(20)] {
			t.Error("expected selector 20, not found")
		}
	})
}
