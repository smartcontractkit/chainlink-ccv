package protocol

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFinalityConstants_BitLayout(t *testing.T) {
	t.Run("masks cover all 16 bits without overlap", func(t *testing.T) {
		assert.Equal(t, Finality(0xFFFF), FinalityBlockDepthMask|FinalityFlagMask,
			"depth mask and flag mask together must cover all 16 bits")
		assert.Equal(t, Finality(0), FinalityBlockDepthMask&FinalityFlagMask,
			"depth mask and flag mask must not overlap")
	})

	t.Run("FinalityWaitForFinality is zero", func(t *testing.T) {
		assert.Equal(t, Finality(0x0000), FinalityWaitForFinality)
	})

	t.Run("FinalityWaitForSafe is exactly bit 10", func(t *testing.T) {
		assert.Equal(t, Finality(0x0400), FinalityWaitForSafe,
			"safe flag must live at bit 10")
		assert.Equal(t, Finality(0), FinalityWaitForSafe&FinalityBlockDepthMask,
			"safe flag must carry no block-depth bits")
		assert.Equal(t, FinalityWaitForSafe, FinalityWaitForSafe&FinalityFlagMask,
			"safe flag must be fully within the flag region")
	})

	t.Run("FinalityBlockDepthMask allows max depth 1023", func(t *testing.T) {
		assert.Equal(t, Finality(0x03FF), FinalityBlockDepthMask)
		assert.Equal(t, Finality(1023), FinalityBlockDepthMask,
			"maximum encodable block depth is 1023")
	})

	t.Run("block depth and safe flag are mutually exclusive encodings", func(t *testing.T) {
		// A pure block-depth value (1..1023) must not trigger the safe flag.
		for _, depth := range []Finality{1, 100, 512, 1023} {
			assert.Equal(t, Finality(0), depth&FinalityFlagMask,
				"block depth %d must not set any flag bits", depth)
		}
		// The safe flag must not look like a block depth.
		assert.Equal(t, Finality(0), FinalityWaitForSafe&FinalityBlockDepthMask)
	})
}

func TestFinality_IsMessageReady(t *testing.T) {
	bi := func(n int64) *big.Int { return big.NewInt(n) }

	t.Run("nil arguments", func(t *testing.T) {
		tests := []struct {
			name                string
			msg, lat, safe, fin *big.Int
		}{
			{"nil msgBlock", nil, bi(10), nil, bi(5)},
			{"nil latestBlock", bi(3), nil, nil, bi(5)},
			{"nil latestFinalizedBlock", bi(3), bi(10), nil, nil},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				_, err := FinalityWaitForFinality.IsMessageReady(tc.msg, tc.lat, tc.safe, tc.fin)
				require.ErrorIs(t, err, ErrNilBlock)
			})
		}
	})

	t.Run("nil latestSafeBlock is not an error", func(t *testing.T) {
		// Nil safe block is expected on chains that don't expose one.
		_, err := FinalityWaitForSafe.IsMessageReady(bi(3), bi(10), nil, bi(5))
		require.NoError(t, err)
	})

	t.Run("FinalityWaitForFinality", func(t *testing.T) {
		tests := []struct {
			name      string
			msg, fin  int64
			wantReady bool
		}{
			{"msg block below finalized", 4, 5, true},
			{"msg block equal to finalized", 5, 5, true},
			{"msg block above finalized", 6, 5, false},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				// latestSafeBlock is irrelevant for this mode.
				ready, err := FinalityWaitForFinality.IsMessageReady(bi(tc.msg), bi(100), bi(99), bi(tc.fin))
				require.NoError(t, err)
				assert.Equal(t, tc.wantReady, ready)
			})
		}
	})

	t.Run("FinalityWaitForSafe — safe block available", func(t *testing.T) {
		tests := []struct {
			name      string
			msg, safe int64
			wantReady bool
		}{
			{"msg block below safe", 4, 5, true},
			{"msg block equal to safe", 5, 5, true},
			{"msg block above safe", 6, 5, false},
			// Safe block ahead of finalized: messages between the two heads are safe but not finalized.
			{"msg block between finalized and safe", 8, 10, true},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				ready, err := FinalityWaitForSafe.IsMessageReady(bi(tc.msg), bi(100), bi(tc.safe), bi(3))
				require.NoError(t, err)
				assert.Equal(t, tc.wantReady, ready)
			})
		}
	})

	t.Run("FinalityWaitForSafe — safe block unavailable, falls back to full finality", func(t *testing.T) {
		tests := []struct {
			name      string
			msg, fin  int64
			wantReady bool
		}{
			{"msg block below finalized", 4, 5, true},
			{"msg block equal to finalized", 5, 5, true},
			{"msg block above finalized", 6, 5, false},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				ready, err := FinalityWaitForSafe.IsMessageReady(bi(tc.msg), bi(100), nil, bi(tc.fin))
				require.NoError(t, err)
				assert.Equal(t, tc.wantReady, ready)
			})
		}
	})

	t.Run("block-depth mode", func(t *testing.T) {
		tests := []struct {
			name                   string
			depth                  Finality
			msg, latest, finalized int64
			wantReady              bool
		}{
			{
				name: "confirmation count satisfied",
				// msg=10, depth=5 → required=15 ≤ latest=20
				depth: 5, msg: 10, latest: 20, finalized: 3, wantReady: true,
			},
			{
				name: "confirmation count exactly met",
				// msg=10, depth=5 → required=15 == latest=15
				depth: 5, msg: 10, latest: 15, finalized: 3, wantReady: true,
			},
			{
				name: "confirmation count not yet met, not finalized",
				// msg=10, depth=5 → required=15 > latest=14, msg=10 > finalized=3
				depth: 5, msg: 10, latest: 14, finalized: 3, wantReady: false,
			},
			{
				name: "confirmation count not met but message already finalized (cap)",
				// msg=10 ≤ finalized=12 → capped at finality
				depth: 5, msg: 10, latest: 14, finalized: 12, wantReady: true,
			},
			{
				name: "minimum depth of 1",
				// msg=10, depth=1 → required=11 ≤ latest=11
				depth: 1, msg: 10, latest: 11, finalized: 3, wantReady: true,
			},
			{
				name: "maximum depth of 1023",
				// msg=1, depth=1023 → required=1024 ≤ latest=1024
				depth: 1023, msg: 1, latest: 1024, finalized: 0, wantReady: true,
			},
			{
				name: "maximum depth not yet reached",
				// msg=1, depth=1023 → required=1024 > latest=1023
				depth: 1023, msg: 1, latest: 1023, finalized: 0, wantReady: false,
			},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				// latestSafeBlock is irrelevant for this mode.
				ready, err := tc.depth.IsMessageReady(bi(tc.msg), bi(tc.latest), bi(99), bi(tc.finalized))
				require.NoError(t, err)
				assert.Equal(t, tc.wantReady, ready)
			})
		}
	})
}
