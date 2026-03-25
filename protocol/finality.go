package protocol

// Finality bit-layout constants — mirror FinalityCodec.sol.
//
// Bit layout of the uint16 finality field (MSB on the left):
//
//	Bit: 15 14 13 12 11 10 | 9 8 7 6 5 4 3 2 1 0
//	      [reserved 5 bits] S |   block depth (10 bits)
//
//	S (bit 10) = FinalityWaitForSafe — wait for the `safe` tag.
//	Bits 11-15 = reserved for future flags.
//
//	Special values:
//	  0x0000 — FinalityWaitForFinality: wait for full finality (safest, default).
//	  0x0400 — FinalityWaitForSafe: wait for the `safe` head (bit 10 set, no depth).
//	  0x0001..0x03FF — wait for N block confirmations (lower 10 bits).
const (
	// FinalityWaitForFinality signals waiting for full on-chain finality (default, safest).
	FinalityWaitForFinality uint16 = 0x0000
	// FinalityWaitForSafe signals waiting for the Ethereum `safe` head (bit 10 set).
	FinalityWaitForSafe uint16 = 0x0400
	// FinalityBlockDepthMask extracts the lower 10 bits (block-confirmation depth).
	FinalityBlockDepthMask uint16 = 0x03FF
	// FinalityFlagMask extracts the upper 6 flag bits.
	FinalityFlagMask uint16 = 0xFC00
)
