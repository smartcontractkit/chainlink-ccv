package utils

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func TestParseSelectorTypes(t *testing.T) {
	ethStr := fmt.Sprintf("%d", chain_selectors.ETHEREUM_MAINNET.Selector)
	solStr := fmt.Sprintf("%d", chain_selectors.SOLANA_MAINNET.Selector)
	ethSel := protocol.ChainSelector(chain_selectors.ETHEREUM_MAINNET.Selector)
	solSel := protocol.ChainSelector(chain_selectors.SOLANA_MAINNET.Selector)

	tests := []struct {
		name    string
		arg     string
		want    []protocol.ChainSelector
		wantErr string // error substring; empty means no error expected
	}{
		{
			name:    "valid selectors",
			arg:     fmt.Sprintf("%s,%s", ethStr, solStr),
			want:    []protocol.ChainSelector{ethSel, solSel},
			wantErr: "",
		},
		{
			name:    "invalid selector (too big)",
			arg:     "99999999999999999999999999999999999999999999999999",
			want:    nil,
			wantErr: "invalid chain selector (99999999999999999999999999999999999999999999999999): strconv.ParseUint",
		},
		{
			name:    "empty is not an error",
			arg:     "",
			want:    nil,
			wantErr: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSelectorTypes(tt.arg)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("ParseSelectorTypes() unexpected error = %v", err)
					return
				}
			} else {
				if err == nil {
					t.Errorf("ParseSelectorTypes() expected error containing %q, got nil", tt.wantErr)
					return
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("ParseSelectorTypes() error = %v, expected to contain %q", err, tt.wantErr)
					return
				}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseSelectorTypes() got = %v, want %v", got, tt.want)
			}
		})
	}
}
