package protocol

import (
	"errors"
	"math/big"
)

// Finality is the per-message finality value encoded in the wire format.
// It mirrors the bytes2 finality field from FinalityCodec.sol (MSB on the left):
//
//	Bit:   15 14 13 12 11 10 | 9 8 7 6 5 4 3 2 1 0
//	     [reserved 5 bits] S | block depth (10 bits)
//
//	S (bit 10) = FinalityWaitForSafe — wait for the `safe` tag.
//	Bits 11-15 = reserved for future flags.
//
//	Special values:
//	  0x0000 — FinalityWaitForFinality: wait for full finality (safest, default).
//	  0x0400 — FinalityWaitForSafe: wait for the `safe` head (bit 10 set, no depth).
//	  0x0001..0x03FF — wait for N block confirmations (lower 10 bits).
type Finality uint16

const (
	// FinalityWaitForFinality signals waiting for full on-chain finality (default, safest).
	FinalityWaitForFinality Finality = 0x0000
	// FinalityWaitForSafe signals waiting for the Ethereum `safe` head (bit 10 set).
	FinalityWaitForSafe Finality = 0x0400
	// FinalityBlockDepthMask extracts the lower 10 bits (block-confirmation depth).
	FinalityBlockDepthMask Finality = 0x03FF
	// FinalityFlagMask extracts the upper 6 flag bits.
	FinalityFlagMask Finality = 0xFC00
)

// ErrNilBlock is returned by IsMessageReady when a required block argument is nil.
var ErrNilBlock = errors.New("block must not be nil")

// IsMessageReady reports whether a message included in msgBlock has satisfied its
// finality requirement given the current chain head state.
//
// msgBlock, latestBlock and latestFinalizedBlock are required; passing nil for any
// of them returns ErrNilBlock. latestSafeBlock may be nil — a nil value means the
// chain does not expose a safe head, and FinalityWaitForSafe falls back to full
// finality in that case.
//
// The three modes mirror the FinalityCodec.sol bit layout:
//   - FinalityWaitForFinality (0x0000): ready when msgBlock ≤ latestFinalizedBlock.
//   - FinalityWaitForSafe    (0x0400): ready when msgBlock ≤ latestSafeBlock.
//     Falls back to full-finality semantics when latestSafeBlock is nil.
//   - Block-depth (0x0001-0x03FF): ready when msgBlock + depth ≤ latestBlock,
//     OR capped: msgBlock ≤ latestFinalizedBlock (prevents depth from exceeding finality).
func (f Finality) IsMessageReady(msgBlock, latestBlock, latestSafeBlock, latestFinalizedBlock *big.Int) (bool, error) {
	if msgBlock == nil {
		return false, ErrNilBlock
	}
	if latestBlock == nil {
		return false, ErrNilBlock
	}
	if latestFinalizedBlock == nil {
		return false, ErrNilBlock
	}

	switch {
	case f == FinalityWaitForFinality:
		return msgBlock.Cmp(latestFinalizedBlock) <= 0, nil

	case f == FinalityWaitForSafe:
		if latestSafeBlock == nil {
			// Safe head unavailable on this chain — fall back to full finality.
			return msgBlock.Cmp(latestFinalizedBlock) <= 0, nil
		}
		return msgBlock.Cmp(latestSafeBlock) <= 0, nil

	case f&FinalityFlagMask == 0:
		// Block-depth mode: no flag bits set, lower 10 bits are the confirmation count.
		depth := uint64(f & FinalityBlockDepthMask)
		required := new(big.Int).Add(msgBlock, new(big.Int).SetUint64(depth))
		return required.Cmp(latestBlock) <= 0 || msgBlock.Cmp(latestFinalizedBlock) <= 0, nil

	default:
		// Unknown flag bits set, require full finality as the safest fallback.
		return msgBlock.Cmp(latestFinalizedBlock) <= 0, nil
	}
}
