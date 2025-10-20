package protocol

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBlockHeader(t *testing.T) {
	t.Run("creates valid block header", func(t *testing.T) {
		ts := time.Unix(1234567890, 0)
		header := BlockHeader{
			Number:     100,
			Hash:       Bytes32{0x01},
			ParentHash: Bytes32{0x00},
			Timestamp:  ts,
		}

		assert.Equal(t, uint64(100), header.Number)
		assert.Equal(t, Bytes32{0x01}, header.Hash)
		assert.Equal(t, Bytes32{0x00}, header.ParentHash)
		assert.Equal(t, ts, header.Timestamp)
	})
}

func TestNewChainTail(t *testing.T) {
	t.Run("creates valid chain tail with single block", func(t *testing.T) {
		blocks := []BlockHeader{
			{Number: 100, Hash: Bytes32{0x01}, ParentHash: Bytes32{0x00}, Timestamp: time.Unix(1000, 0)},
		}

		tail, err := NewChainTail(blocks)
		require.NoError(t, err)
		require.NotNil(t, tail)
		assert.Equal(t, 1, tail.Len())
	})

	t.Run("creates valid chain tail with contiguous blocks", func(t *testing.T) {
		blocks := []BlockHeader{
			{Number: 100, Hash: Bytes32{0x01}, ParentHash: Bytes32{0x00}, Timestamp: time.Unix(1000, 0)},
			{Number: 101, Hash: Bytes32{0x02}, ParentHash: Bytes32{0x01}, Timestamp: time.Unix(1001, 0)},
			{Number: 102, Hash: Bytes32{0x03}, ParentHash: Bytes32{0x02}, Timestamp: time.Unix(1002, 0)},
		}

		tail, err := NewChainTail(blocks)
		require.NoError(t, err)
		require.NotNil(t, tail)
		assert.Equal(t, 3, tail.Len())
	})

	t.Run("rejects empty blocks", func(t *testing.T) {
		tail, err := NewChainTail([]BlockHeader{})
		assert.Error(t, err)
		assert.Nil(t, tail)
		assert.Contains(t, err.Error(), "cannot be empty")
	})

	t.Run("rejects non-contiguous blocks", func(t *testing.T) {
		blocks := []BlockHeader{
			{Number: 100, Hash: Bytes32{0x01}, ParentHash: Bytes32{0x00}, Timestamp: time.Unix(1000, 0)},
			{Number: 101, Hash: Bytes32{0x02}, ParentHash: Bytes32{0xFF}, Timestamp: time.Unix(1001, 0)}, // Wrong parent hash
		}

		tail, err := NewChainTail(blocks)
		assert.Error(t, err)
		assert.Nil(t, tail)
		assert.Contains(t, err.Error(), "non-contiguous")
	})

	t.Run("rejects duplicate block numbers", func(t *testing.T) {
		blocks := []BlockHeader{
			{Number: 100, Hash: Bytes32{0x01}, ParentHash: Bytes32{0x00}, Timestamp: time.Unix(1000, 0)},
			{Number: 100, Hash: Bytes32{0x02}, ParentHash: Bytes32{0x01}, Timestamp: time.Unix(1001, 0)}, // Duplicate number
		}

		tail, err := NewChainTail(blocks)
		assert.Error(t, err)
		assert.Nil(t, tail)
		assert.Contains(t, err.Error(), "duplicate block number")
	})
}

func TestChainTail_StableTip(t *testing.T) {
	t.Run("returns first block", func(t *testing.T) {
		blocks := []BlockHeader{
			{Number: 100, Hash: Bytes32{0x01}, ParentHash: Bytes32{0x00}, Timestamp: time.Unix(1000, 0)},
			{Number: 101, Hash: Bytes32{0x02}, ParentHash: Bytes32{0x01}, Timestamp: time.Unix(1001, 0)},
			{Number: 102, Hash: Bytes32{0x03}, ParentHash: Bytes32{0x02}, Timestamp: time.Unix(1002, 0)},
		}

		tail, err := NewChainTail(blocks)
		require.NoError(t, err)

		stableTip := tail.StableTip()
		assert.Equal(t, uint64(100), stableTip.Number)
		assert.Equal(t, Bytes32{0x01}, stableTip.Hash)
	})

	t.Run("returns empty block header for empty tail", func(t *testing.T) {
		tail := &ChainTail{blocks: []BlockHeader{}}
		stableTip := tail.StableTip()
		assert.Equal(t, BlockHeader{}, stableTip)
	})
}

func TestChainTail_Tip(t *testing.T) {
	t.Run("returns last block", func(t *testing.T) {
		blocks := []BlockHeader{
			{Number: 100, Hash: Bytes32{0x01}, ParentHash: Bytes32{0x00}, Timestamp: time.Unix(1000, 0)},
			{Number: 101, Hash: Bytes32{0x02}, ParentHash: Bytes32{0x01}, Timestamp: time.Unix(1001, 0)},
			{Number: 102, Hash: Bytes32{0x03}, ParentHash: Bytes32{0x02}, Timestamp: time.Unix(1002, 0)},
		}

		tail, err := NewChainTail(blocks)
		require.NoError(t, err)

		tip := tail.Tip()
		assert.Equal(t, uint64(102), tip.Number)
		assert.Equal(t, Bytes32{0x03}, tip.Hash)
	})

	t.Run("returns empty block header for empty tail", func(t *testing.T) {
		tail := &ChainTail{blocks: []BlockHeader{}}
		tip := tail.Tip()
		assert.Equal(t, BlockHeader{}, tip)
	})
}

func TestChainTail_Contains(t *testing.T) {
	blocks := []BlockHeader{
		{Number: 100, Hash: Bytes32{0x01}, ParentHash: Bytes32{0x00}, Timestamp: time.Unix(1000, 0)},
		{Number: 101, Hash: Bytes32{0x02}, ParentHash: Bytes32{0x01}, Timestamp: time.Unix(1001, 0)},
		{Number: 102, Hash: Bytes32{0x03}, ParentHash: Bytes32{0x02}, Timestamp: time.Unix(1002, 0)},
	}

	tail, err := NewChainTail(blocks)
	require.NoError(t, err)

	t.Run("finds existing block", func(t *testing.T) {
		block := BlockHeader{Number: 101, Hash: Bytes32{0x02}, ParentHash: Bytes32{0x01}, Timestamp: time.Unix(1001, 0)}
		assert.True(t, tail.Contains(block))
	})

	t.Run("does not find block with wrong hash", func(t *testing.T) {
		block := BlockHeader{Number: 101, Hash: Bytes32{0xFF}, ParentHash: Bytes32{0x01}, Timestamp: time.Unix(1001, 0)}
		assert.False(t, tail.Contains(block))
	})

	t.Run("does not find block with wrong number", func(t *testing.T) {
		block := BlockHeader{Number: 999, Hash: Bytes32{0x02}, ParentHash: Bytes32{0x01}, Timestamp: time.Unix(1001, 0)}
		assert.False(t, tail.Contains(block))
	})
}

func TestChainTail_BlockByNumber(t *testing.T) {
	blocks := []BlockHeader{
		{Number: 100, Hash: Bytes32{0x01}, ParentHash: Bytes32{0x00}, Timestamp: time.Unix(1000, 0)},
		{Number: 101, Hash: Bytes32{0x02}, ParentHash: Bytes32{0x01}, Timestamp: time.Unix(1001, 0)},
		{Number: 102, Hash: Bytes32{0x03}, ParentHash: Bytes32{0x02}, Timestamp: time.Unix(1002, 0)},
	}

	tail, err := NewChainTail(blocks)
	require.NoError(t, err)

	t.Run("finds block by number", func(t *testing.T) {
		block := tail.BlockByNumber(101)
		require.NotNil(t, block)
		assert.Equal(t, uint64(101), block.Number)
		assert.Equal(t, Bytes32{0x02}, block.Hash)
	})

	t.Run("returns nil for non-existent block number", func(t *testing.T) {
		block := tail.BlockByNumber(999)
		assert.Nil(t, block)
	})
}

func TestChainStatusTypes(t *testing.T) {
	t.Run("ChainStatusReorg", func(t *testing.T) {
		blocks := []BlockHeader{
			{Number: 100, Hash: Bytes32{0x01}, ParentHash: Bytes32{0x00}, Timestamp: time.Unix(1000, 0)},
		}
		tail, err := NewChainTail(blocks)
		require.NoError(t, err)

		status := ChainStatusReorg{
			NewTail:             *tail,
			CommonAncestorBlock: 99,
		}
		assert.Equal(t, uint64(99), status.CommonAncestorBlock)

		// Verify it implements ChainStatus interface
		var _ ChainStatus = status
	})

	t.Run("ChainStatusFinalityViolated", func(t *testing.T) {
		blocks := []BlockHeader{
			{Number: 100, Hash: Bytes32{0x01}, ParentHash: Bytes32{0x00}, Timestamp: time.Unix(1000, 0)},
		}
		tail, err := NewChainTail(blocks)
		require.NoError(t, err)

		violatedBlock := BlockHeader{Number: 50, Hash: Bytes32{0xFF}, ParentHash: Bytes32{0xFE}, Timestamp: time.Unix(500, 0)}
		status := ChainStatusFinalityViolated{
			ViolatedBlock:    violatedBlock,
			NewTail:          *tail,
			SafeRestartBlock: 49,
		}
		assert.Equal(t, uint64(50), status.ViolatedBlock.Number)
		assert.Equal(t, uint64(49), status.SafeRestartBlock)

		// Verify it implements ChainStatus interface
		var _ ChainStatus = status
	})
}

func TestReorgType_String(t *testing.T) {
	tests := []struct {
		name      string
		reorgType ReorgType
		expected  string
	}{
		{"Regular", ReorgTypeRegular, "Regular"},
		{"FinalityViolation", ReorgTypeFinalityViolation, "FinalityViolation"},
		{"Unknown", ReorgType(999), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.reorgType.String())
		})
	}
}
