package protocol

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFinalityConstants_BitLayout(t *testing.T) {
	t.Run("masks cover all 16 bits without overlap", func(t *testing.T) {
		assert.Equal(t, uint16(0xFFFF), FinalityBlockDepthMask|FinalityFlagMask,
			"depth mask and flag mask together must cover all 16 bits")
		assert.Equal(t, uint16(0), FinalityBlockDepthMask&FinalityFlagMask,
			"depth mask and flag mask must not overlap")
	})

	t.Run("FinalityWaitForFinality is zero", func(t *testing.T) {
		assert.Equal(t, uint16(0x0000), FinalityWaitForFinality)
	})

	t.Run("FinalityWaitForSafe is exactly bit 10", func(t *testing.T) {
		assert.Equal(t, uint16(0x0400), FinalityWaitForSafe,
			"safe flag must live at bit 10")
		assert.Equal(t, uint16(0), FinalityWaitForSafe&FinalityBlockDepthMask,
			"safe flag must carry no block-depth bits")
		assert.Equal(t, FinalityWaitForSafe, FinalityWaitForSafe&FinalityFlagMask,
			"safe flag must be fully within the flag region")
	})

	t.Run("FinalityBlockDepthMask allows max depth 1023", func(t *testing.T) {
		assert.Equal(t, uint16(0x03FF), FinalityBlockDepthMask)
		assert.Equal(t, uint16(1023), FinalityBlockDepthMask,
			"maximum encodable block depth is 1023")
	})

	t.Run("block depth and safe flag are mutually exclusive encodings", func(t *testing.T) {
		// A pure block-depth value (1..1023) must not trigger the safe flag.
		for _, depth := range []uint16{1, 100, 512, 1023} {
			assert.Equal(t, uint16(0), depth&FinalityFlagMask,
				"block depth %d must not set any flag bits", depth)
		}
		// The safe flag must not look like a block depth.
		assert.Equal(t, uint16(0), FinalityWaitForSafe&FinalityBlockDepthMask)
	})
}
