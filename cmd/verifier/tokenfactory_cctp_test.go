package verifier

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token/cctp"
)

type testCCTPCodec struct{}

func (testCCTPCodec) Domain(protocol.ChainSelector) (uint32, bool) { return 0, true }
func (testCCTPCodec) EncodeTxHash(protocol.ByteSlice) string       { return "" }
func (testCCTPCodec) DecodeAddress(string) (protocol.UnknownAddress, error) {
	return nil, nil
}

func TestCCTPCodecsFor(t *testing.T) {
	// The verifier reads Sepolia messages that can go to Solana.
	// It needs both resolver addresses, but only the Sepolia source needs a CCTP codec.
	resolvers := map[protocol.ChainSelector]protocol.UnknownAddress{
		sepoliaSelector:      {0x01},
		solanaDevnetSelector: {0x02},
	}

	t.Run("does not need a codec for the Solana destination", func(t *testing.T) {
		accessor := mocks.NewMockAccessor(t)
		accessor.EXPECT().CCTPCodec().Return(testCCTPCodec{}, nil)

		codecs, err := cctpCodecsFor(
			map[protocol.ChainSelector]chainaccess.Accessor{sepoliaSelector: accessor},
			&cctp.CCTPConfig{
				ParsedVerifiers:         map[protocol.ChainSelector]protocol.UnknownAddress{sepoliaSelector: {0x0a}},
				ParsedVerifierResolvers: resolvers,
			},
		)
		require.NoError(t, err)
		require.Len(t, codecs, 1)
		require.Contains(t, codecs, sepoliaSelector)
		require.NotContains(t, codecs, solanaDevnetSelector)
	})

	t.Run("fails when the Sepolia source has no codec", func(t *testing.T) {
		accessor := mocks.NewMockAccessor(t)
		accessor.EXPECT().CCTPCodec().Return(nil, nil)

		_, err := cctpCodecsFor(
			map[protocol.ChainSelector]chainaccess.Accessor{sepoliaSelector: accessor},
			&cctp.CCTPConfig{ParsedVerifiers: map[protocol.ChainSelector]protocol.UnknownAddress{sepoliaSelector: {0x0a}}},
		)
		require.ErrorContains(t, err, "no CCTP chain codec for source chain selector")
	})

	t.Run("fails when the Sepolia source has no accessor", func(t *testing.T) {
		_, err := cctpCodecsFor(
			map[protocol.ChainSelector]chainaccess.Accessor{},
			&cctp.CCTPConfig{
				ParsedVerifiers:         map[protocol.ChainSelector]protocol.UnknownAddress{sepoliaSelector: {0x0a}},
				ParsedVerifierResolvers: resolvers,
			},
		)
		require.ErrorContains(t, err, "no accessor resolved for CCTP source chain selector")
	})
}
