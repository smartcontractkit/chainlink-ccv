package protocol

import (
	"errors"
	"math/big"
)

// Finality is the per-message finality value encoded in the wire format.
// It mirrors the bytes4 finality field from FinalityCodec.sol (MSB on the left):
//
//	  Bit: 31  30  29  28  27  26  25  24  23  22  21  20  19  18  17  16 | 15  14  13  12  11  10   9   8   7   6   5   4   3   2   1   0
//	      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//	      | R | R | R | R | R | R | R | R | R | R | R | R | R | R | R | S |                          block depth (16 bits)                |
//	      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//	      \_______________________________  _____________________________/ \______________________________  _____________________________/
//	                                      \/                                                              \/
//	                                 flags (16 bits)                                                  depth (16 bits)
//	                                                                                                max = 65535 (0xFFFF)
//
//		S (bit 16) = FinalityWaitForSafe — wait for the `safe` tag.
//		Bits 17-31 = reserved for future flags.
//
//		Special values:
//		  0x00000000 — FinalityWaitForFinality: wait for full finality (safest, default).
//		  0x00010000 — FinalityWaitForSafe: wait for the `safe` head (bit 16 set, no depth).
//		  0x00000001..0x0000FFFF — wait for N block confirmations (lower 16 bits).
type Finality uint32

const (
	// FinalityWaitForFinality signals waiting for full on-chain finality (default, safest).
	FinalityWaitForFinality Finality = 0x00000000
	// FinalityWaitForSafe signals waiting for the Ethereum `safe` head (bit 16 set).
	FinalityWaitForSafe Finality = 0x00010000
	// FinalityBlockDepthMask extracts the lower 16 bits (block-confirmation depth).
	FinalityBlockDepthMask Finality = 0x0000FFFF
	// FinalityFlagMask extracts the upper 16 flag bits.
	FinalityFlagMask Finality = 0xFFFF0000
)

// New returns the zero Finality value (FinalityWaitForFinality).
// Use it as the single entry point for all builder chains.
func New() Finality { return FinalityWaitForFinality }

// WithSafe sets the safe-head flag (bit 16).
func (f Finality) WithSafe() Finality { return f | FinalityWaitForSafe }

// WithBlockDepth sets the block-confirmation depth (lower 16 bits), clearing any prior depth.
func (f Finality) WithBlockDepth(n uint16) Finality {
	return (f &^ FinalityBlockDepthMask) | Finality(n)
}

// ToBytes returns the wire-format [4]byte representation (big-endian, mirrors bytes4 in Solidity).
func (f Finality) ToBytes() [4]byte {
	return [4]byte{byte(f >> 24), byte(f >> 16), byte(f >> 8), byte(f)}
}

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
//   - FinalityWaitForFinality (0x00000000): ready when msgBlock ≤ latestFinalizedBlock.
//   - FinalityWaitForSafe    (0x00010000): ready when msgBlock ≤ latestSafeBlock.
//     Falls back to full-finality semantics when latestSafeBlock is nil.
//   - Block-depth (0x00000001-0x0000FFFF): ready when msgBlock + depth ≤ latestBlock,
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
		// Block-depth mode: no flag bits set, lower 16 bits are the confirmation count.
		depth := uint64(f & FinalityBlockDepthMask)
		required := new(big.Int).Add(msgBlock, new(big.Int).SetUint64(depth))
		return required.Cmp(latestBlock) <= 0 || msgBlock.Cmp(latestFinalizedBlock) <= 0, nil

	default:
		// Unknown flag bits set, require full finality as the safest fallback.
		return msgBlock.Cmp(latestFinalizedBlock) <= 0, nil
	}
}
