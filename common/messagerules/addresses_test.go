package messagerules

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func TestAddressBytesEqual(t *testing.T) {
	t.Parallel()

	token20 := mustHexBytes(t, "7A9Ec1d04904907De0ED7b6839CcdD59c3716AC9")
	token20Padded := leftZeroPad(token20, 32)
	token20PaddedNonZeroPrefix := append([]byte(nil), token20Padded...)
	token20PaddedNonZeroPrefix[0] = 0x01
	tokenB := mustHexBytes(t, "0000000000000000000000000000000000000001")
	pubkey32 := protocol.ByteSlice{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

	tests := []struct {
		name string
		a    []byte
		b    []byte
		want bool
	}{
		{name: "exact_equal_length", a: []byte{0x01, 0x02}, b: []byte{0x01, 0x02}, want: true},
		{name: "left_padded_message", a: token20, b: token20Padded, want: true},
		{name: "left_padded_rule", a: token20Padded, b: token20, want: true},
		{name: "equal_32_byte_non_evm", a: pubkey32, b: pubkey32, want: true},
		{name: "padded_mismatch_non_zero_prefix", a: token20, b: token20PaddedNonZeroPrefix, want: false},
		{name: "different_identity", a: token20, b: tokenB, want: false},
		{name: "empty_shorter", a: []byte{}, b: token20, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, addressBytesEqual(tt.a, tt.b))
		})
	}
}

func TestTokenAddressBytesEqual(t *testing.T) {
	t.Parallel()

	token20Padded := leftZeroPad(mustHexBytes(t, "7A9Ec1d04904907De0ED7b6839CcdD59c3716AC9"), 32)

	require.True(t, tokenAddressBytesEqual("0x7A9Ec1d04904907De0ED7b6839CcdD59c3716AC9", token20Padded))
	require.False(t, tokenAddressBytesEqual("0x7A9Ec1d04904907De0ED7b6839CcdD59c3716AC9", protocol.ByteSlice{}))
	require.False(t, tokenAddressBytesEqual("not-hex", token20Padded))
}

func TestCompiledRules_TokenRule_MatchesLeftZeroPaddedSourceTokenAddress(t *testing.T) {
	t.Parallel()

	const sourceSelector = protocol.ChainSelector(3379446385462418246)
	const destSelector = protocol.ChainSelector(4793464827907405086)

	token20 := mustHexBytes(t, "7A9Ec1d04904907De0ED7b6839CcdD59c3716AC9")
	token20Padded := leftZeroPad(token20, 32)
	token20PaddedNonZeroPrefix := append([]byte(nil), token20Padded...)
	token20PaddedNonZeroPrefix[0] = 0x01
	tokenB := mustHexBytes(t, "0000000000000000000000000000000000000001")
	pubkey32 := protocol.ByteSlice{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

	tokenRuleData, err := NewTokenRuleData(uint64(sourceSelector), "0x7A9Ec1d04904907De0ED7b6839CcdD59c3716AC9")
	require.NoError(t, err)
	tokenRule, err := NewRule("token", tokenRuleData, time.Time{}, time.Time{})
	require.NoError(t, err)

	compiled, err := CompileRules([]Rule{tokenRule})
	require.NoError(t, err)

	tests := []struct {
		name     string
		report   testMessageReport
		disabled bool
	}{
		{
			name: "exact_equal_length_dest_token",
			report: testMessageReport{
				source: 1,
				dest:   sourceSelector,
				tt:     &protocol.TokenTransfer{DestTokenAddress: protocol.ByteSlice{0x01, 0x02}},
			},
			disabled: false,
		},
		{
			name: "left_padded_source_token_matches_minimal_rule",
			report: testMessageReport{
				source: sourceSelector,
				dest:   destSelector,
				tt:     &protocol.TokenTransfer{SourceTokenAddress: token20Padded},
			},
			disabled: true,
		},
		{
			name: "left_padded_rule_matches_minimal_message_token",
			report: testMessageReport{
				source: sourceSelector,
				dest:   destSelector,
				tt:     &protocol.TokenTransfer{SourceTokenAddress: token20},
			},
			disabled: true,
		},
		{
			name: "equal_32_byte_non_evm_token",
			report: testMessageReport{
				source: sourceSelector,
				dest:   destSelector,
				tt: &protocol.TokenTransfer{
					SourceTokenAddress: pubkey32,
				},
			},
			disabled: false,
		},
		{
			name: "padded_mismatch_non_zero_prefix_does_not_disable",
			report: testMessageReport{
				source: sourceSelector,
				dest:   destSelector,
				tt:     &protocol.TokenTransfer{SourceTokenAddress: token20PaddedNonZeroPrefix},
			},
			disabled: false,
		},
		{
			name: "different_token_identity_does_not_disable",
			report: testMessageReport{
				source: sourceSelector,
				dest:   destSelector,
				tt:     &protocol.TokenTransfer{SourceTokenAddress: tokenB},
			},
			disabled: false,
		},
		{
			name:     "non_token_message_not_disabled",
			report:   testMessageReport{source: sourceSelector, dest: destSelector},
			disabled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.disabled, compiled.IsDisabled(tt.report))
		})
	}
}

func mustHexBytes(t *testing.T, hex string) []byte {
	t.Helper()
	b, err := protocol.NewByteSliceFromHex("0x" + hex)
	require.NoError(t, err)
	return b
}

func leftZeroPad(b []byte, size int) []byte {
	if len(b) >= size {
		return append([]byte(nil), b...)
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
