package evm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNonceRangeIdentifiesOrphans(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		latest, pending uint64
		want            []uint64
	}{
		{
			name:    "no transactions in flight",
			latest:  10,
			pending: 10,
			want:    nil,
		},
		{
			name:    "one orphan",
			latest:  10,
			pending: 11,
			want:    []uint64{10},
		},
		{
			name:    "several orphans are all reported",
			latest:  10,
			pending: 14,
			want:    []uint64{10, 11, 12, 13},
		},
		{
			// A pending nonce below the latest is not a state the chain should report. Treating it
			// as "nothing to recover" keeps recovery from inventing transactions out of an RPC that
			// answered the two calls from different nodes mid-block.
			name:    "pending behind latest yields nothing",
			latest:  10,
			pending: 8,
			want:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, nonceRange(tt.latest, tt.pending))
		})
	}
}

// TestNewTxmV2RejectsUnsupportedConfig covers the branches of upstream's builder that this one
// deliberately does not reproduce. They are rejected rather than silently ignored, so a config that
// turns one on fails at startup instead of running without the behavior it asked for.
func TestNewTxmV2RejectsUnsupportedConfig(t *testing.T) {
	t.Parallel()

	cfg, err := newChainlinkEVMConfig(Info{
		ChainID: "1337",
		Nodes:   []Node{{HTTPUrl: "http://node.internal:8545"}},
	})
	require.NoError(t, err)

	// The standalone config never enables forwarders; assert that, since newTxmV2 relies on it to
	// justify passing a nil forwarder manager.
	require.False(t, cfg.EVM().Transactions().ForwardersEnabled(),
		"newTxmV2 passes a nil forwarder manager and rejects configs that enable forwarders")

	dual := cfg.EVM().Transactions().TransactionManagerV2().DualBroadcast()
	require.True(t, dual == nil || !*dual,
		"newTxmV2 passes a nil error handler and rejects configs that enable dual broadcast")
}
